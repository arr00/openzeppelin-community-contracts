// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {Packing} from "@openzeppelin/contracts/utils/Packing.sol";
import {IModularAccount, IExecutionHookModule, ModuleEntity, ValidationConfig, ValidationFlags, IValidationHookModule, ExecutionManifest, HookConfig, ManifestExecutionFunction, ManifestExecutionHook, IModule} from "contracts/interfaces/draft-IERC6900.sol";

library ERC6900Utils {
    using EnumerableSet for EnumerableSet.Bytes32Set;
    struct PostHooksExecutionInfo {
        HookConfig hookConfig;
        bytes data;
    }

    function module(ValidationConfig validationConfig) internal pure returns (address) {
        return address(bytes20(ValidationConfig.unwrap(validationConfig)));
    }

    function entity(ValidationConfig validationConfig) internal pure returns (uint32) {
        return uint32(bytes4(ValidationConfig.unwrap(validationConfig) << 160));
    }

    function flags(ValidationConfig validationConfig) internal pure returns (ValidationFlags) {
        return ValidationFlags.wrap(uint8(uint200(ValidationConfig.unwrap(validationConfig))));
    }

    function isGlobal(ValidationFlags validationFlags) internal pure returns (bool) {
        return uint8(ValidationFlags.unwrap(validationFlags)) & (1 << 2) != 0;
    }

    function isSignatureValidation(ValidationFlags validationFlags) internal pure returns (bool) {
        return uint8(ValidationFlags.unwrap(validationFlags)) & (1 << 1) != 0;
    }

    function hasPre(HookConfig config) internal pure returns (bool) {
        return uint200(HookConfig.unwrap(config)) & (1 << 2) != 0;
    }

    function hasPost(HookConfig config) internal pure returns (bool) {
        return uint200(HookConfig.unwrap(config)) & (1 << 1) != 0;
    }

    function module(HookConfig config) internal pure returns (address) {
        return address(bytes20(HookConfig.unwrap(config)));
    }

    function entity(HookConfig config) internal pure returns (uint32) {
        return uint32(uint200(HookConfig.unwrap(config)) >> 8);
    }

    function moduleEntity(ValidationConfig validationConfig) internal pure returns (ModuleEntity) {
        return ModuleEntity.wrap(bytes24(ValidationConfig.unwrap(validationConfig)));
    }

    function isValidationHook(HookConfig hookConfig) internal pure returns (bool) {
        return (uint8(uint200(HookConfig.unwrap(hookConfig))) & 1) == 1;
    }

    function module(ModuleEntity moduleEntity_) internal pure returns (address) {
        return address(bytes20(ModuleEntity.unwrap(moduleEntity_)));
    }

    function entity(ModuleEntity moduleEntity_) internal pure returns (uint32) {
        return uint32(uint192(ModuleEntity.unwrap(moduleEntity_)));
    }

    function clear(EnumerableSet.Bytes32Set storage set) internal {
        for (uint256 i = set.length(); i > 0; --i) {
            set.remove(set.at(i - 1));
        }
    }

    function executeExecutionPreHooks(
        EnumerableSet.Bytes32Set storage hooks
    ) internal returns (PostHooksExecutionInfo[] memory res) {
        uint256 hooksLength = hooks.length();

        for (uint256 i = 0; i < hooksLength; ++i) {
            HookConfig hookConfig = HookConfig.wrap(bytes25(hooks.at(i)));
            if (hasPre(hookConfig)) {
                if (hasPost(hookConfig)) {
                    // Save return data
                    res[i] = PostHooksExecutionInfo(hookConfig, _executePreExecutionHook(hookConfig));
                } else {
                    // No post. Not necessary to save.
                    _executePreExecutionHook(hookConfig);
                }
            } else if (hasPost(hookConfig)) {
                // Must cache for running post
                res[i] = PostHooksExecutionInfo(hookConfig, "");
            }
        }
    }

    function _executePreExecutionHook(HookConfig hookConfig) private returns (bytes memory) {
        return
            IExecutionHookModule(module(hookConfig)).preExecutionHook(
                entity(hookConfig),
                msg.sender,
                msg.value,
                msg.data
            );
    }

    function executePreValidationHooks(EnumerableSet.Bytes32Set storage hooks, bytes memory authorization) internal {
        uint256 hooksLength = hooks.length();

        bytes[] memory authorizations = new bytes[](hooksLength + 1);
        if (authorization.length > 0) {
            authorizations = abi.decode(authorization, (bytes[]));
        }

        for (uint256 i = 0; i < hooksLength; ++i) {
            HookConfig hookConfig = HookConfig.wrap(bytes25(hooks.at(i)));
            _executeValidationHook(hookConfig, authorizations[i]);
        }
    }

    function _executeValidationHook(HookConfig hookConfig, bytes memory authorization) private {
        IValidationHookModule(module(hookConfig)).preRuntimeValidationHook(
            entity(hookConfig),
            msg.sender,
            msg.value,
            msg.data,
            authorization
        );
    }

    function executePostHooks(PostHooksExecutionInfo[] memory preHookResults) internal {
        uint256 hooksLength = preHookResults.length;

        for (uint256 i = hooksLength; i > 0; --i) {
            if (hasPost(preHookResults[i].hookConfig)) {
                IExecutionHookModule(module(preHookResults[i].hookConfig)).postExecutionHook(
                    entity(preHookResults[i].hookConfig),
                    preHookResults[i].data
                );
            }
        }
    }
}
