// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IAccountExecute} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {ERC165, IERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {IModularAccount, IModularAccountView, IModule, IExecutionHookModule, IValidationModule, IValidationHookModule, ValidationDataView, ExecutionDataView, PackedUserOperation, Call, ValidationFlags, ModuleEntity, ValidationConfig, HookConfig, ExecutionManifest, ManifestExecutionFunction, ManifestExecutionHook} from "../../interfaces/draft-IERC6900.sol";
import {AccountCore} from "../AccountCore.sol";
import {ERC6900Utils} from "../utils/ERC6900Utils.sol";

abstract contract AccountERC6900 is
    AccountCore,
    ERC165,
    IModularAccountView,
    IModularAccount,
    IAccountExecute,
    IERC1271
{
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using ERC6900Utils for *;
    using Address for address;

    /**
     * Enum representing the 3 different types of validation done by the account.
     *
     * - Direct: Direct validation is done when a caller directly calls a function on the modular account or calls {executeWithRuntimeValidation}.
     * - UserOp: UserOp validation is done on {validateUserOp} calls.
     * - Signature: Signature validation is done on 1271 {isValidSignature} calls.
     */
    enum ValidationType {
        Direct,
        UserOp,
        Signature
    }

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
        ValidationFlags validationFlags;
        // The validation hooks for this validation function.
        EnumerableSet.Bytes32Set validationHooks;
        // Execution hooks to run with this validation function.
        EnumerableSet.Bytes32Set executionHooks;
        // The set of selectors that may be validated by this validation function.
        EnumerableSet.Bytes32Set selectors;
    }

    struct PostExecutionHooksInfo {
        HookConfig hookConfig;
        bytes data;
    }

    mapping(bytes4 => ExecutionStorage) private _executionStorage;
    mapping(bytes4 => uint256) private _supportedInterfaceIds;
    mapping(ModuleEntity => ValidationStorage) private _validationStorage;

    error ERC6900AccountInvalidModule();
    error ERC6900AccountInvalidUninstallData();
    error ERC6900AccountValidationDoesNotApply();
    error ERC6900AccountSelfCall();
    error ERC6900AccountFunctionNotFound();
    error ERC6900AccountInvalidHookConfig();
    error ERC6900AccountModuleOnInstallFailed();

    modifier validatedAndHooked() {
        PostExecutionHooksInfo[] memory postValidationExecutionHooks = _runDirectValidation();
        PostExecutionHooksInfo[] memory postSelectorExecutionHooks = _runPreExecutionHooks(
            _executionStorage[msg.sig].executionHooks
        );

        _;

        _runPostExecutionHooks(postSelectorExecutionHooks);
        _runPostExecutionHooks(postValidationExecutionHooks);
    }

    fallback(bytes calldata) external payable virtual returns (bytes memory) {
        return _fallback();
    }

    /// @inheritdoc IModularAccount
    function installExecution(
        address module,
        ExecutionManifest calldata manifest,
        bytes calldata installData
    ) public virtual override validatedAndHooked {
        if (module == address(0)) revert ERC6900AccountInvalidModule();

        uint256 executionFunctionLength = manifest.executionFunctions.length;
        for (uint256 i = 0; i < executionFunctionLength; ++i) {
            _addExecutionFunction(module, manifest.executionFunctions[i]);
        }

        uint256 executionHookLength = manifest.executionHooks.length;
        for (uint256 i = 0; i < executionHookLength; ++i) {
            _addSelectorExecutionHook(module, manifest.executionHooks[i]);
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

    /// @inheritdoc IModularAccount
    function uninstallExecution(
        address module,
        ExecutionManifest calldata manifest,
        bytes calldata uninstallData
    ) public virtual override validatedAndHooked {
        if (module == address(0)) revert ERC6900AccountInvalidModule();

        uint256 interfaceIdsLength = manifest.interfaceIds.length;
        for (uint256 i = 0; i < interfaceIdsLength; ++i) {
            _removeInterfaceId(manifest.interfaceIds[i]);
        }

        uint256 executionHooksLength = manifest.executionHooks.length;
        for (uint256 i = 0; i < executionHooksLength; ++i) {
            _removeSelectorExecutionHook(module, manifest.executionHooks[i]);
        }

        uint256 executionFunctionLength = manifest.executionFunctions.length;
        for (uint256 i = 0; i < executionFunctionLength; ++i) {
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

    /// @inheritdoc IModularAccount
    function installValidation(
        ValidationConfig validationConfig,
        bytes4[] calldata selectors,
        bytes calldata installData,
        bytes[] calldata hooks
    ) public virtual override validatedAndHooked {
        // What if there is an existing validation function with the same module and entity? Not addressed by the ERC.

        ModuleEntity moduleEntity = validationConfig.moduleEntity();
        address module = moduleEntity.module();

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
                    // OW execution hook
                    _addValidationExecutionHook(moduleEntity, hookConfig, hookOnInstallData);
                }
            }
        }

        _callOnInstall(module, installData);

        emit ValidationInstalled(module, validationConfig.entity());
    }

    /// @inheritdoc IModularAccount
    function uninstallValidation(
        ModuleEntity validationFunction,
        bytes calldata uninstallData,
        bytes[] calldata hookUninstallData
    ) public virtual override validatedAndHooked {
        bool uninstallSuccessful = true;

        if (hookUninstallData.length != 0) {
            uint256 validationHooksLength = _validationStorage[validationFunction].validationHooks.length();
            uint256 hooksLength = validationHooksLength +
                _validationStorage[validationFunction].executionHooks.length();
            if (hooksLength != hookUninstallData.length) {
                revert ERC6900AccountInvalidUninstallData();
            }

            // Assume uninstallation data is validation hooks, then execution hooks. Following the reference impl
            // https://github.com/erc6900/reference-implementation/blob/c9b256cfd963a655179fa3cd9ea3f92c73cbfcdd/src/account/ModuleManagerInternals.sol#L289

            bool validationHooksSuccessfullyUninstalled = _removeHooks(
                _validationStorage[validationFunction].validationHooks,
                hookUninstallData,
                0
            );
            bool executionHooksSuccessfullyUninstalled = _removeHooks(
                _validationStorage[validationFunction].executionHooks,
                hookUninstallData,
                validationHooksLength
            );
            uninstallSuccessful = validationHooksSuccessfullyUninstalled && executionHooksSuccessfullyUninstalled;
        }

        _validationStorage[validationFunction].validationFlags = ValidationFlags.wrap(0);
        _validationStorage[validationFunction].selectors.clear();

        if (uninstallData.length > 0) {
            try IModule(validationFunction.module()).onUninstall(uninstallData) {} catch {
                uninstallSuccessful = false;
            }
        }

        emit ValidationUninstalled(validationFunction.module(), validationFunction.entity(), uninstallSuccessful);
    }

    /// @inheritdoc IModularAccount
    function execute(
        address target,
        uint256 value,
        bytes calldata data
    ) public payable virtual override validatedAndHooked returns (bytes memory) {
        if (target == address(this)) {
            revert ERC6900AccountSelfCall();
        }
        (bool success, bytes memory res) = target.call{value: value}(data);
        return Address.verifyCallResult(success, res);
    }

    /// @inheritdoc IModularAccount
    function executeBatch(
        Call[] calldata calls
    ) public payable virtual override validatedAndHooked returns (bytes[] memory) {
        uint256 length = calls.length;
        bytes[] memory res = new bytes[](length);
        for (uint256 i = 0; i < length; ++i) {
            // This is on the stricter side and we may want to relax the restriction (more logic)
            if (calls[i].target == address(this)) {
                revert ERC6900AccountSelfCall();
            }

            (bool success, bytes memory res_) = calls[i].target.call{value: calls[i].value}(calls[i].data);
            res[i] = Address.verifyCallResult(success, res_);
        }

        return res;
    }

    /// @inheritdoc IModularAccount
    function executeWithRuntimeValidation(
        bytes calldata data,
        bytes calldata authorization
    ) public payable virtual returns (bytes memory) {
        if (authorization.length < 24) {
            revert("Authorization data too short");
        }
        ModuleEntity moduleEntity = ModuleEntity.wrap(bytes24(authorization[:24]));
        ValidationStorage storage validationStorage = _validationStorage[moduleEntity];

        _validationApplies(validationStorage, ValidationType.Direct, bytes4(data[:4]));

        _runRuntimeValidationHooks(validationStorage.validationHooks, authorization);

        IValidationModule(moduleEntity.module()).validateRuntime(
            address(this),
            moduleEntity.entity(),
            msg.sender,
            msg.value,
            data,
            authorization
        );

        PostExecutionHooksInfo[] memory postValidationExecutionHooksInfo = _runPreExecutionHooks(
            validationStorage.executionHooks
        );

        bytes memory res = address(this).functionCallWithValue(data, msg.value);

        _runPostExecutionHooks(postValidationExecutionHooksInfo);

        return res;
    }

    /// @inheritdoc IAccountExecute
    function executeUserOp(PackedUserOperation calldata userOp, bytes32) public virtual override onlyEntryPoint {
        ModuleEntity userOpValidationFunction = ModuleEntity.wrap(bytes24(userOp.signature[:24]));
        PostExecutionHooksInfo[] memory postExecutionHooksInfo = _runPreExecutionHooks(
            _validationStorage[userOpValidationFunction].executionHooks
        );

        // Remove `executeUserOp` selector from callData
        address(this).functionCall(userOp.callData[4:]);

        _runPostExecutionHooks(postExecutionHooksInfo);
    }

    /// @inheritdoc IERC1271
    function isValidSignature(bytes32 hash, bytes calldata signature) public view virtual returns (bytes4) {
        if (signature.length < 24) {
            revert("Signature too short");
        }
        bytes calldata authorization = signature[24:];

        ModuleEntity moduleEntity = ModuleEntity.wrap(bytes24(signature));
        ValidationStorage storage validationStorage = _validationStorage[moduleEntity];

        _validationApplies(validationStorage, ValidationType.Signature, bytes4(0));

        bytes[] memory authorizationSegments = abi.decode(authorization, (bytes[]));
        uint256 validationHooksLength = validationStorage.validationHooks.length();
        if (authorizationSegments.length != validationHooksLength + 1) {
            revert("Authorization segments length does not match hooks length");
        }

        for (uint256 i = 0; i < validationHooksLength; ++i) {
            HookConfig hookConfig = validationStorage.validationHooks.at(i).toHookConfig();
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

    /// @inheritdoc IModularAccountView
    function getExecutionData(bytes4 selector) public view virtual override returns (ExecutionDataView memory) {
        uint256 hooksLength = _executionStorage[selector].executionHooks.length();
        HookConfig[] memory hooks = new HookConfig[](hooksLength);
        for (uint256 i = 0; i < hooksLength; ++i) {
            hooks[i] = _executionStorage[selector].executionHooks.at(i).toHookConfig();
        }

        return
            ExecutionDataView({
                module: _executionStorage[selector].module,
                skipRuntimeValidation: _executionStorage[selector].skipRuntimeValidation,
                allowGlobalValidation: _executionStorage[selector].allowGlobalValidation,
                executionHooks: hooks
            });
    }

    /// @inheritdoc IModularAccountView
    function getValidationData(
        ModuleEntity validationFunction
    ) public view virtual override returns (ValidationDataView memory) {
        uint256 validationHooksLength = _validationStorage[validationFunction].validationHooks.length();
        HookConfig[] memory validationHooks = new HookConfig[](validationHooksLength);
        for (uint256 i = 0; i < validationHooksLength; ++i) {
            validationHooks[i] = _validationStorage[validationFunction].validationHooks.at(i).toHookConfig();
        }

        uint256 executionHooksLength = _validationStorage[validationFunction].executionHooks.length();
        HookConfig[] memory executionHooks = new HookConfig[](executionHooksLength);
        for (uint256 i = 0; i < executionHooksLength; ++i) {
            executionHooks[i] = _validationStorage[validationFunction].executionHooks.at(i).toHookConfig();
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

    /// @inheritdoc IERC165
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return
            _supportedInterfaceIds[interfaceId] > 0 ||
            type(IERC1271).interfaceId == interfaceId ||
            super.supportsInterface(interfaceId);
    }

    function _fallback() internal virtual validatedAndHooked returns (bytes memory) {
        ExecutionStorage storage executionStorage = _executionStorage[msg.sig];
        if (executionStorage.module == address(0)) {
            revert ERC6900AccountFunctionNotFound();
        }
        return executionStorage.module.functionCall(msg.data);
    }

    /// MARK: Hook execution

    /**
     * @dev Run pre-execution hooks.
     *
     * NOTE: This function does not assert that a hook is an execution hook as it is enforced when installed.
     */
    function _runPreExecutionHooks(
        EnumerableSet.Bytes32Set storage executionHooks
    ) internal virtual returns (PostExecutionHooksInfo[] memory) {
        uint256 hooksLength = executionHooks.length();
        PostExecutionHooksInfo[] memory postExecutionHooksInfo = new PostExecutionHooksInfo[](hooksLength);

        for (uint256 i = 0; i < hooksLength; ++i) {
            HookConfig hookConfig = executionHooks.at(i).toHookConfig();
            bool hasPost = hookConfig.hasPost();
            if (hookConfig.hasPre()) {
                if (hasPost) {
                    // Save return data
                    postExecutionHooksInfo[i] = PostExecutionHooksInfo(hookConfig, _runPreExecutionHook(hookConfig));
                } else {
                    // No post. Not necessary to save.
                    _runPreExecutionHook(hookConfig);
                }
            } else if (hasPost) {
                // Must cache for running post
                postExecutionHooksInfo[i] = PostExecutionHooksInfo(hookConfig, "");
            }
        }

        return postExecutionHooksInfo;
    }

    function _runPreExecutionHook(HookConfig hookConfig) internal virtual returns (bytes memory) {
        return
            IExecutionHookModule(hookConfig.module()).preExecutionHook(
                hookConfig.entity(),
                msg.sender,
                msg.value,
                msg.data
            );
    }

    function _runPostExecutionHooks(PostExecutionHooksInfo[] memory postExecutionHooksInfo) internal virtual {
        uint256 hooksLength = postExecutionHooksInfo.length;

        for (uint256 i = hooksLength; i > 0; --i) {
            HookConfig hookConfig = postExecutionHooksInfo[i - 1].hookConfig;
            if (hookConfig.hasPost()) {
                IExecutionHookModule(hookConfig.module()).postExecutionHook(
                    hookConfig.entity(),
                    postExecutionHooksInfo[i - 1].data
                );
            }
        }
    }

    function _runRuntimeValidationHooks(
        EnumerableSet.Bytes32Set storage hooks,
        bytes memory authorization
    ) internal virtual {
        uint256 hooksLength = hooks.length();

        bytes[] memory authorizations = new bytes[](hooksLength + 1);
        if (authorization.length > 0) {
            authorizations = abi.decode(authorization, (bytes[]));
        }

        for (uint256 i = 0; i < hooksLength; ++i) {
            HookConfig hookConfig = HookConfig.wrap(bytes25(hooks.at(i)));
            IValidationHookModule(hookConfig.module()).preRuntimeValidationHook(
                hookConfig.entity(),
                msg.sender,
                msg.value,
                msg.data,
                authorization
            );
        }
    }

    function _runDirectValidation() internal virtual returns (PostExecutionHooksInfo[] memory) {
        PostExecutionHooksInfo[] memory postExecutionHooksInfo;

        // No further validation required
        if (
            msg.sender == address(this) ||
            msg.sender == address(entryPoint()) ||
            _executionStorage[msg.sig].skipRuntimeValidation
        ) return postExecutionHooksInfo;

        ModuleEntity moduleEntity = ModuleEntity.wrap(
            bytes24(bytes20(msg.sender)) | bytes24(uint192(type(uint32).max))
        );

        ValidationStorage storage validationStorage = _validationStorage[moduleEntity];
        _validationApplies(validationStorage, ValidationType.Direct, msg.sig);

        // No authorization since it is a direct call
        _runRuntimeValidationHooks(validationStorage.validationHooks, "");
        postExecutionHooksInfo = _runPreExecutionHooks(validationStorage.executionHooks);

        // Do NOT run validation function on the module.

        return postExecutionHooksInfo;
    }

    /// MARK: Start module management functions
    function _addExecutionFunction(
        address module,
        ManifestExecutionFunction calldata manifestExecutionFunction
    ) internal virtual {
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
    ) internal virtual {
        if (_executionStorage[manifestExecutionFunction.executionSelector].module != module) {
            revert("Account: module not installed for function to uninstall");
        }

        delete _executionStorage[manifestExecutionFunction.executionSelector].module;
        delete _executionStorage[manifestExecutionFunction.executionSelector].skipRuntimeValidation;
        delete _executionStorage[manifestExecutionFunction.executionSelector].allowGlobalValidation;
    }

    function _addSelectorExecutionHook(
        address module,
        ManifestExecutionHook calldata manifestExecutionHook
    ) internal virtual {
        if (!manifestExecutionHook.isPreHook && !manifestExecutionHook.isPostHook) {
            revert ERC6900AccountInvalidHookConfig();
        }
        if (
            !_executionStorage[manifestExecutionHook.executionSelector].executionHooks.add(
                _packExecutionHook(module, manifestExecutionHook)
            )
        ) revert("Hook already exists");
    }

    function _removeSelectorExecutionHook(
        address module,
        ManifestExecutionHook calldata manifestExecutionHook
    ) internal virtual {
        if (
            !_executionStorage[manifestExecutionHook.executionSelector].executionHooks.remove(
                _packExecutionHook(module, manifestExecutionHook)
            )
        ) revert("Hook does not exist");
    }

    function _removeHooks(
        EnumerableSet.Bytes32Set storage hooks,
        bytes[] memory hookUninstallData,
        uint256 uninstallOffset
    ) internal virtual returns (bool) {
        bool success = true;

        uint256 hooksLength = hooks.length();
        for (uint256 i = 0; i < hooksLength; ++i) {
            HookConfig hookConfig = hooks.at(i).toHookConfig();
            try IModule(hookConfig.module()).onUninstall(hookUninstallData[i + uninstallOffset]) {} catch {
                success = false;
            }
        }
        hooks.clear();

        return success;
    }

    function _addInterfaceId(bytes4 interfaceId) internal virtual {
        _supportedInterfaceIds[interfaceId] += 1;
    }

    function _removeInterfaceId(bytes4 interfaceId) internal virtual {
        _supportedInterfaceIds[interfaceId] -= 1;
    }

    function _addValidationSelector(ModuleEntity moduleEntity, bytes4 selector) internal virtual {
        if (!_validationStorage[moduleEntity].selectors.add(selector)) {
            revert("Validation selector already exists");
        }
    }

    function _addValidationHook(
        ModuleEntity moduleEntity,
        HookConfig hookConfig,
        bytes calldata onInstallData
    ) internal virtual {
        if (!hookConfig.isValidationHook()) {
            revert ERC6900AccountInvalidHookConfig();
        }
        if (!_validationStorage[moduleEntity].validationHooks.add(hookConfig.toBytes32())) {
            revert("Validation hook already exists");
        }

        _callOnInstall(moduleEntity.module(), onInstallData);
    }

    function _addValidationExecutionHook(
        ModuleEntity moduleEntity,
        HookConfig hookConfig,
        bytes calldata onInstallData
    ) internal virtual {
        if (hookConfig.isValidationHook()) {
            revert ERC6900AccountInvalidHookConfig();
        }
        if (!hookConfig.hasPre() && !hookConfig.hasPost()) {
            revert ERC6900AccountInvalidHookConfig();
        }
        if (!_validationStorage[moduleEntity].executionHooks.add(hookConfig.toBytes32())) {
            revert("Validation execution hook already exists");
        }

        _callOnInstall(moduleEntity.module(), onInstallData);
    }

    function _callOnInstall(address module, bytes calldata onInstallData) internal virtual {
        if (onInstallData.length > 0) {
            try IModule(module).onInstall(onInstallData) {} catch {
                revert ERC6900AccountModuleOnInstallFailed();
            }
        }
    }

    function _validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal virtual override returns (uint256) {
        ModuleEntity validationFunc = ModuleEntity.wrap(bytes24(userOp.signature[:24]));
        ValidationStorage storage validationStorage = _validationStorage[validationFunc];

        {
            bytes4 selector = bytes4(userOp.callData[:4]);

            if (validationStorage.executionHooks.length() > 0 && selector != IAccountExecute.executeUserOp.selector) {
                revert("Account: user op execution hooks will only execute during executeUserOp");
            }

            // Update selector to be the inner selector for further validation
            if (selector == IAccountExecute.executeUserOp.selector) {
                selector = bytes4(userOp.callData[4:8]);
            }
            _validationApplies(validationStorage, ValidationType.UserOp, selector);
        }

        uint256 validationHooksLength = validationStorage.validationHooks.length();
        bytes[] memory signatureSegments = abi.decode(userOp.signature[24:], (bytes[]));

        if (signatureSegments.length != validationHooksLength + 1) {
            revert("Account: signature segments length does not match hooks length");
        }

        PackedUserOperation memory userOpCopy = userOp;
        uint256 currentValidationData;

        for (uint256 i = 0; i < validationHooksLength; ++i) {
            HookConfig hookConfig = validationStorage.validationHooks.at(i).toHookConfig();
            userOpCopy.signature = signatureSegments[i];
            currentValidationData = currentValidationData.mergeUserOpValidation(
                IValidationHookModule(hookConfig.module()).preUserOpValidationHook(
                    hookConfig.entity(),
                    userOpCopy,
                    userOpHash
                )
            );
        }

        userOpCopy.signature = signatureSegments[validationHooksLength];
        currentValidationData = currentValidationData.mergeUserOpValidation(
            IValidationModule(validationFunc.module()).validateUserOp(validationFunc.entity(), userOp, userOpHash)
        );

        return currentValidationData;
    }

    /// @dev Internal function which reverts if the given validation function does not apply to the given context.
    function _validationApplies(
        ValidationStorage storage validationStorage,
        ValidationType validationType,
        bytes4 functionSelector
    ) internal view virtual {
        if (validationType == ValidationType.Signature) {
            if (!validationStorage.validationFlags.isSignatureValidation()) {
                revert ERC6900AccountValidationDoesNotApply();
            }
            return;
        }
        if (validationType == ValidationType.UserOp) {
            if (!validationStorage.validationFlags.isUserOpValidation()) {
                revert ERC6900AccountValidationDoesNotApply();
            }
        }
        if (
            !(validationStorage.validationFlags.isGlobal() &&
                _executionStorage[functionSelector].allowGlobalValidation) &&
            !validationStorage.selectors.contains(functionSelector)
        ) {
            revert ERC6900AccountValidationDoesNotApply();
        }
    }

    function _packExecutionHook(
        address module,
        ManifestExecutionHook calldata manifestExecutionHook
    ) private pure returns (bytes25) {
        bytes1 flags = bytes1(
            ((manifestExecutionHook.isPreHook ? 1 : 0) << 2) | ((manifestExecutionHook.isPostHook ? 1 : 0) << 1)
        );
        return
            bytes25(bytes20(module)) |
            bytes25(uint200(manifestExecutionHook.entityId) << 8) |
            bytes25(uint200(uint8(flags)));
    }
}
