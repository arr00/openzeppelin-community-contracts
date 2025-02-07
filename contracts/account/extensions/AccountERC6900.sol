// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IModularAccount, IModularAccountView, ValidationDataView, ExecutionDataView, IValidationHookModule, PackedUserOperation, IValidationModule, Call, ValidationFlags, ModuleEntity, ValidationConfig, ExecutionManifest, HookConfig, ManifestExecutionFunction, ManifestExecutionHook, IModule} from "contracts/interfaces/draft-IERC6900.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {IAccountExecute} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {AccountCore} from "../AccountCore.sol";
import {ERC6900Utils} from "../utils/ERC6900Utils.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";

abstract contract AccountERC6900 is AccountCore, IAccountExecute, IModularAccountView, IModularAccount {
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using ERC6900Utils for *;
    using Address for address;

    struct ExecutionStorage {
        // The module that implements this execution function.
        // If this is a native function, the address must remain address(0).
        address module;
        // Whether or not the function needs runtime validation, or can be called by anyone. The function can still be
        // state changing if this flag is set to true.
        // Note that even if this is set to true, user op validation will still be required, otherwise anyone could
        // drain the account of native tokens by wasting gas.
        bool skipRuntimeValidation;
        // Whether or not a global validation function may be used to validate this function.
        bool allowGlobalValidation;
        // The execution hooks for this function selector.
        EnumerableSet.Bytes32Set executionHooks;
    }

    struct ValidationStorage {
        // ValidationFlags layout:
        // 0b00000___ // unused
        // 0b_____A__ // isGlobal
        // 0b______B_ // isSignatureValidation
        // 0b_______C // isUserOpValidation
        ValidationFlags validationFlags;
        // The validation hooks for this validation function.
        EnumerableSet.Bytes32Set validationHooks;
        // Execution hooks to run with this validation function.
        EnumerableSet.Bytes32Set executionHooks;
        // The set of selectors that may be validated by this validation function.
        EnumerableSet.Bytes32Set selectors;
    }

    mapping(bytes4 => ExecutionStorage) private _executionStorage;
    mapping(bytes4 => uint256) private _supportedInterfaceIds;
    mapping(ModuleEntity => ValidationStorage) private _validationStorage;

    modifier validatedAndHooked() {
        ERC6900Utils.PostHooksExecutionInfo[] memory postValidationExecutionHooks = _runDirectValidation(msg.sig);
        ERC6900Utils.PostHooksExecutionInfo[] memory postSelectorExecutionHooks = _runExecutionHooks(msg.sig);

        _;

        postSelectorExecutionHooks.executePostHooks();
        postValidationExecutionHooks.executePostHooks();
    }

    fallback() external payable {
        _fallback();
    }

    function installExecution(
        address module,
        ExecutionManifest calldata manifest,
        bytes calldata installData
    ) public override validatedAndHooked {
        if (module == address(0)) revert("Module is 0");

        uint256 executionFunctionLength = manifest.executionFunctions.length;
        for (uint256 i = 0; i < executionFunctionLength; ++i) {
            _addExecutionFunction(module, manifest.executionFunctions[i]);
        }

        uint256 executionHookLength = manifest.executionHooks.length;
        for (uint256 i = 0; i < executionHookLength; ++i) {
            _addExecutionHook(module, manifest.executionHooks[i]);
        }

        uint256 interfaceIdsLength = manifest.interfaceIds.length;
        for (uint256 i = 0; i < interfaceIdsLength; ++i) {
            _addInterfaceId(manifest.interfaceIds[i]);
        }

        if (installData.length > 0) {
            IModule(module).onInstall(installData);
        }

        emit ExecutionInstalled(module, manifest);
    }

    function uninstallExecution(
        address module,
        ExecutionManifest calldata manifest,
        bytes calldata uninstallData
    ) public override validatedAndHooked {
        if (module == address(0)) revert("Module is 0");

        uint256 interfaceIdsLength = manifest.interfaceIds.length;
        for (uint256 i = 0; i < interfaceIdsLength; i++) {
            _removeInterfaceId(manifest.interfaceIds[i]);
        }

        uint256 executionHooksLength = manifest.executionHooks.length;
        for (uint256 i = 0; i < executionHooksLength; i++) {
            _removeExecutionHook(module, manifest.executionHooks[i]);
        }

        uint256 executionFunctionLength = manifest.executionFunctions.length;
        for (uint256 i = 0; i < executionFunctionLength; i++) {
            _removeExecutionFunction(module, manifest.executionFunctions[i]);
        }

        bool uninstallSuccessful = true;
        if (uninstallData.length > 0) {
            try IModule(module).onUninstall(uninstallData) {} catch {
                uninstallSuccessful = false;
            }
        }

        emit ExecutionUninstalled(module, uninstallSuccessful, manifest);
    }

    function installValidation(
        ValidationConfig validationConfig,
        bytes4[] calldata selectors,
        bytes calldata installData,
        bytes[] calldata hooks
    ) public override validatedAndHooked {
        // What if there is an existing validation function with the same module and entity? Not addressed by the ERC.
        // Do we need to ensure there are no

        ModuleEntity moduleEntity = validationConfig.moduleEntity();

        _validationStorage[moduleEntity].validationFlags = validationConfig.flags();

        {
            uint256 selectorsLength = selectors.length;
            for (uint256 i = 0; i < selectorsLength; ++i) {
                _addValidationSelector(moduleEntity, selectors[i]);
            }
        }

        {
            uint256 hooksLength = hooks.length;
            for (uint256 i = 0; i < hooksLength; ++i) {
                HookConfig hookConfig = HookConfig.wrap(bytes25(hooks[i][:25]));
                bytes calldata hookOnInstallData = hooks[i][25:];

                if (hookConfig.isValidationHook()) {
                    _addValidationHook(moduleEntity, hookConfig, hookOnInstallData);
                } else {
                    _addValidationExecutionHook(moduleEntity, hookConfig, hookOnInstallData);
                }
            }
        }

        _callOnInstall(validationConfig.module(), installData);

        emit ValidationInstalled(validationConfig.module(), validationConfig.entity());
    }

    function uninstallValidation(
        ModuleEntity validationFunction,
        bytes calldata uninstallData,
        bytes[] calldata hookUninstallData
    ) public override validatedAndHooked {
        _validationStorage[validationFunction].validationFlags = ValidationFlags.wrap(0);
        _validationStorage[validationFunction].selectors.clear();

        bool uninstallSuccessful = true;

        if (hookUninstallData.length != 0) {
            uint256 hooksLength = _validationStorage[validationFunction].validationHooks.length() +
                _validationStorage[validationFunction].executionHooks.length();
            if (hooksLength != hookUninstallData.length) {
                revert("Account: hookUninstallData length does not match hooks length");
            }

            // Assume uninstallation data is validation hooks, then execution hooks. Following the reference impl
            // https://github.com/erc6900/reference-implementation/blob/c9b256cfd963a655179fa3cd9ea3f92c73cbfcdd/src/account/ModuleManagerInternals.sol#L289
            uint256 validationHooksLength = _validationStorage[validationFunction].validationHooks.length();
            for (uint256 i = 0; i < hooksLength; ++i) {
                HookConfig hookConfig;
                if (i < validationHooksLength) {
                    hookConfig = HookConfig.wrap(bytes25(_validationStorage[validationFunction].validationHooks.at(i)));
                } else {
                    hookConfig = HookConfig.wrap(
                        bytes25(_validationStorage[validationFunction].executionHooks.at(i - validationHooksLength))
                    );
                }

                try IModule(hookConfig.module()).onUninstall(hookUninstallData[i]) {} catch {
                    uninstallSuccessful = false;
                }
            }
        }

        _validationStorage[validationFunction].validationHooks.clear();
        _validationStorage[validationFunction].executionHooks.clear();

        if (uninstallData.length > 0) {
            try IModule(validationFunction.module()).onUninstall(uninstallData) {} catch {
                uninstallSuccessful = false;
            }
        }

        emit ValidationUninstalled(validationFunction.module(), validationFunction.entity(), uninstallSuccessful);
    }

    function execute(
        address target,
        uint256 value,
        bytes calldata data
    ) public payable virtual override validatedAndHooked returns (bytes memory) {
        if (target == address(this)) {
            revert("Self call");
        }
        return target.functionCallWithValue(data, value);
    }

    function executeBatch(
        Call[] calldata calls
    ) public payable virtual override validatedAndHooked returns (bytes[] memory) {
        uint256 length = calls.length;
        bytes[] memory res = new bytes[](length);
        for (uint256 i = 0; i < length; ++i) {
            if (calls[i].target == address(this)) {
                revert("Self call");
            }
            res[i] = calls[i].target.functionCallWithValue(calls[i].data, calls[i].value);
        }

        return res;
    }

    function executeWithRuntimeValidation(
        bytes calldata data,
        bytes calldata authorization
    ) public payable returns (bytes memory) {
        ModuleEntity moduleEntity = ModuleEntity.wrap(bytes24(authorization[:24]));
        ValidationStorage storage validationStorage = _validationStorage[moduleEntity];

        if (validationStorage.validationFlags.isGlobal()) {
            if (!_executionStorage[bytes4(data[:4])].allowGlobalValidation) {
                revert("Global validation not allowed");
            }
        } else {
            if (!validationStorage.selectors.contains(bytes4(data[:4]))) {
                revert("Validation not allowed");
            }
        }

        validationStorage.validationHooks.executePreValidationHooks(authorization);

        IValidationModule(moduleEntity.module()).validateRuntime(
            address(this),
            moduleEntity.entity(),
            msg.sender,
            msg.value,
            data,
            authorization
        );

        ERC6900Utils.PostHooksExecutionInfo[] memory preValidationExecutionHooksResults = validationStorage
            .executionHooks
            .executeExecutionPreHooks();

        bytes memory res = address(this).functionCall(data);

        preValidationExecutionHooksResults.executePostHooks();

        return res;
    }

    function executeUserOp(PackedUserOperation calldata userOp, bytes32) public virtual override {
        if (msg.sender != address(entryPoint())) {
            revert("Not Entrypoint");
        }

        ModuleEntity userOpValidationFunction = ModuleEntity.wrap(bytes24(userOp.signature[:24]));
        ERC6900Utils.PostHooksExecutionInfo[] memory preValidationExecutionHooksResults = _validationStorage[
            userOpValidationFunction
        ].executionHooks.executeExecutionPreHooks();

        // Should we be running the user op validation function?

        // Remove `executeUserOp` selector from callData
        address(this).functionCall(userOp.callData[4:]);

        preValidationExecutionHooksResults.executePostHooks();
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) public view returns (bytes4) {
        bytes calldata authorization = signature[24:];

        ModuleEntity moduleEntity = ModuleEntity.wrap(bytes24(signature));
        ValidationStorage storage validationStorage = _validationStorage[moduleEntity];

        if (!validationStorage.validationFlags.isSignatureValidation()) {
            revert("Validation not applicable to signature");
        }

        bytes[] memory authorizationSegments = abi.decode(authorization, (bytes[]));
        uint256 validationHooksLength = validationStorage.validationHooks.length();
        if (authorizationSegments.length != validationHooksLength + 1) {
            revert("Authorization segments length does not match hooks length");
        }

        for (uint256 i = 0; i < validationHooksLength; ++i) {
            HookConfig hookConfig = HookConfig.wrap(bytes25(validationStorage.validationHooks.at(i)));
            IValidationHookModule(hookConfig.module()).preSignatureValidationHook(
                hookConfig.entity(),
                msg.sender,
                hash,
                authorizationSegments[i]
            );
        }
        return
            IValidationModule(moduleEntity.module()).validateSignature(
                address(this),
                moduleEntity.entity(),
                msg.sender,
                hash,
                authorizationSegments[validationHooksLength]
            );
    }

    function getExecutionData(bytes4 selector) public view virtual override returns (ExecutionDataView memory) {
        uint256 hooksLength = _executionStorage[selector].executionHooks.length();
        HookConfig[] memory hooks = new HookConfig[](hooksLength);
        for (uint256 i = 0; i < hooksLength; ++i) {
            hooks[i] = HookConfig.wrap(bytes25(_executionStorage[selector].executionHooks.at(i)));
        }

        return
            ExecutionDataView({
                module: _executionStorage[selector].module,
                skipRuntimeValidation: _executionStorage[selector].skipRuntimeValidation,
                allowGlobalValidation: _executionStorage[selector].allowGlobalValidation,
                executionHooks: hooks
            });
    }

    function getValidationData(
        ModuleEntity validationFunction
    ) public view virtual override returns (ValidationDataView memory) {
        uint256 validationHooksLength = _validationStorage[validationFunction].validationHooks.length();
        HookConfig[] memory validationHooks = new HookConfig[](validationHooksLength);
        for (uint256 i = 0; i < validationHooksLength; ++i) {
            validationHooks[i] = HookConfig.wrap(bytes25(_validationStorage[validationFunction].validationHooks.at(i)));
        }

        uint256 executionHooksLength = _validationStorage[validationFunction].executionHooks.length();
        HookConfig[] memory executionHooks = new HookConfig[](executionHooksLength);
        for (uint256 i = 0; i < executionHooksLength; ++i) {
            executionHooks[i] = HookConfig.wrap(bytes25(_validationStorage[validationFunction].executionHooks.at(i)));
        }

        uint256 selectorsLength = _validationStorage[validationFunction].selectors.length();
        bytes4[] memory selectors = new bytes4[](selectorsLength);
        for (uint256 i = 0; i < selectorsLength; ++i) {
            selectors[i] = bytes4(_validationStorage[validationFunction].selectors.at(i));
        }

        return
            ValidationDataView({
                validationFlags: _validationStorage[validationFunction].validationFlags,
                validationHooks: validationHooks,
                executionHooks: executionHooks,
                selectors: selectors
            });
    }

    /// @inheritdoc IModularAccount
    function accountId() public view virtual returns (string memory) {
        // vendorname.accountname.semver
        return "@openzeppelin/community-contracts.AccountERC6900.v0.0.0";
    }

    function _fallback() internal validatedAndHooked {
        ExecutionStorage storage executionStorage = _executionStorage[msg.sig];
        if (executionStorage.module == address(0)) {
            revert("Account: function not found");
        }
        executionStorage.module.functionCall(msg.data);
    }

    function _runExecutionHooks(bytes4 selector) internal returns (ERC6900Utils.PostHooksExecutionInfo[] memory) {
        return _executionStorage[selector].executionHooks.executeExecutionPreHooks();
    }

    function _runDirectValidation(bytes4 selector) internal returns (ERC6900Utils.PostHooksExecutionInfo[] memory) {
        ERC6900Utils.PostHooksExecutionInfo[] memory postHooksExecutionInfo;

        if (
            msg.sender == address(this) ||
            msg.sender == address(entryPoint()) ||
            _executionStorage[selector].skipRuntimeValidation
        ) return postHooksExecutionInfo;

        ModuleEntity moduleEntity = ModuleEntity.wrap(
            bytes24(bytes20(msg.sender)) | bytes24(uint192(type(uint32).max))
        );

        ValidationStorage storage validationStorage = _validationStorage[moduleEntity];
        if (
            !(validationStorage.validationFlags.isGlobal() && _executionStorage[msg.sig].allowGlobalValidation) &&
            !validationStorage.selectors.contains(selector)
        ) {
            revert("Unauthorized");
        }

        validationStorage.validationHooks.executePreValidationHooks("");
        postHooksExecutionInfo = validationStorage.executionHooks.executeExecutionPreHooks();

        return postHooksExecutionInfo;
    }

    function _addExecutionFunction(
        address module,
        ManifestExecutionFunction calldata manifestExecutionFunction
    ) internal {
        if (_executionStorage[manifestExecutionFunction.executionSelector].module != address(0)) {
            revert("Account: execution function already installed");
        }

        _executionStorage[manifestExecutionFunction.executionSelector].module = module;
        _executionStorage[manifestExecutionFunction.executionSelector].skipRuntimeValidation = manifestExecutionFunction
            .skipRuntimeValidation;
        _executionStorage[manifestExecutionFunction.executionSelector].allowGlobalValidation = manifestExecutionFunction
            .allowGlobalValidation;
    }

    function _removeExecutionFunction(
        address module,
        ManifestExecutionFunction calldata manifestExecutionFunction
    ) internal {
        if (_executionStorage[manifestExecutionFunction.executionSelector].module != module) {
            revert("Account: module not installed for function to uninstall");
        }

        delete _executionStorage[manifestExecutionFunction.executionSelector].module;
        delete _executionStorage[manifestExecutionFunction.executionSelector].skipRuntimeValidation;
        delete _executionStorage[manifestExecutionFunction.executionSelector].allowGlobalValidation;
    }

    function _addExecutionHook(address module, ManifestExecutionHook calldata manifestExecutionHook) internal {
        if (!manifestExecutionHook.isPreHook && !manifestExecutionHook.isPostHook) {
            revert("Account: execution hook must be pre or post");
        }
        if (
            !_executionStorage[manifestExecutionHook.executionSelector].executionHooks.add(
                _packExecutionHook(module, manifestExecutionHook)
            )
        ) revert("Hook already exists");
    }

    function _removeExecutionHook(address module, ManifestExecutionHook calldata manifestExecutionHook) internal {
        if (
            !_executionStorage[manifestExecutionHook.executionSelector].executionHooks.remove(
                _packExecutionHook(module, manifestExecutionHook)
            )
        ) revert("Hook does not exist");
    }

    function _addInterfaceId(bytes4 interfaceId) internal {
        _supportedInterfaceIds[interfaceId] += 1;
    }

    function _removeInterfaceId(bytes4 interfaceId) internal {
        _supportedInterfaceIds[interfaceId] -= 1;
    }

    function _removeValidationSelector(ModuleEntity moduleEntity, bytes4 selector) internal {
        if (!_validationStorage[moduleEntity].selectors.remove(selector)) {
            revert("Validation selector does not exist");
        }
    }

    function _addValidationHook(
        ModuleEntity moduleEntity,
        HookConfig hookConfig,
        bytes calldata onInstallData
    ) internal {
        if (!hookConfig.isValidationHook()) {
            revert("Account: hook is not a validation hook");
        }
        if (!_validationStorage[moduleEntity].validationHooks.add(HookConfig.unwrap(hookConfig))) {
            revert("Validation hook already exists");
        }

        _callOnInstall(moduleEntity.module(), onInstallData);
    }

    function _removeValidationHook(ModuleEntity moduleEntity, HookConfig hookConfig) internal {
        if (!_validationStorage[moduleEntity].validationHooks.remove(HookConfig.unwrap(hookConfig))) {
            revert("Validation hook does not exist");
        }
    }

    function _addValidationExecutionHook(
        ModuleEntity moduleEntity,
        HookConfig hookConfig,
        bytes calldata onInstallData
    ) internal {
        if (hookConfig.isValidationHook()) {
            revert("Account: hook is not an execution hook");
        }
        if (!hookConfig.hasPre() && !hookConfig.hasPost()) {
            revert("Account: execution hook must be pre or post");
        }
        if (!_validationStorage[moduleEntity].executionHooks.add(HookConfig.unwrap(hookConfig))) {
            revert("Validation execution hook already exists");
        }

        _callOnInstall(moduleEntity.module(), onInstallData);
    }

    function _removeValidationExecutionHook(ModuleEntity moduleEntity, HookConfig hookConfig) internal {
        if (!_validationStorage[moduleEntity].executionHooks.remove(HookConfig.unwrap(hookConfig))) {
            revert("Validation execution hook does not exist");
        }
    }

    function _callOnInstall(address module, bytes calldata onInstallData) internal {
        if (onInstallData.length > 0) {
            try IModule(module).onInstall(onInstallData) {} catch {
                revert("onInstall failed");
            }
        }
    }

    function _packExecutionHook(
        address module,
        ManifestExecutionHook calldata manifestExecutionHook
    ) internal pure returns (bytes25) {
        bytes1 flags = bytes1(
            ((manifestExecutionHook.isPreHook ? 1 : 0) << 2) | ((manifestExecutionHook.isPostHook ? 1 : 0) << 1) | 1
        );
        return bytes25(bytes20(module)) | bytes5(bytes4(manifestExecutionHook.entityId)) | flags;
    }

    function _unpackValidationConfig(
        ValidationConfig validationConfig
    )
        internal
        pure
        returns (
            ModuleEntity moduleEntity,
            bool isGlobalFlag,
            bool isSignatureValidationFlag,
            bool isUserOpValidationFlag
        )
    {
        bytes25 config = ValidationConfig.unwrap(validationConfig);
        moduleEntity = ModuleEntity.wrap(bytes24(config >> 8));

        bytes1 globalFlagBit = bytes1(uint8(1 << 2));
        bytes1 signatureValidationFlagBit = bytes1(uint8(1 << 1));
        bytes1 userOpValidationFlagBit = bytes1(uint8(1));

        isGlobalFlag = (config & globalFlagBit) != 0;
        isSignatureValidationFlag = (config & signatureValidationFlagBit) != 0;
        isUserOpValidationFlag = (config & userOpValidationFlagBit) != 0;
    }

    function _addValidationSelector(ModuleEntity moduleEntity, bytes4 selector) internal {
        if (!_validationStorage[moduleEntity].selectors.add(selector)) {
            revert("Validation selector already exists");
        }
    }
}
