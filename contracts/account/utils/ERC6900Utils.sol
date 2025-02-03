// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IModularAccount, IExecutionHookModule, ModuleEntity, ValidationConfig, ValidationFlags, IValidationHookModule, ExecutionManifest, HookConfig, ManifestExecutionFunction, ManifestExecutionHook, IModule} from "contracts/interfaces/draft-IERC6900.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

library ERC6900Utils {
    struct PreHookResult {
        HookConfig hookConfig;
        bytes data;
    }

    using EnumerableSet for EnumerableSet.Bytes32Set;
    using ERC6900Utils for *;

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
    ) internal returns (PreHookResult[] memory res) {
        uint256 hooksLength = hooks.length();

        for (uint256 i = 0; i < hooksLength; ++i) {
            HookConfig hookConfig = HookConfig.wrap(bytes25(hooks.at(i)));
            if (hookConfig.hasPre()) {
                if (hookConfig.hasPost()) {
                    // Save return data
                    res[i] = PreHookResult(hookConfig, _executePreExecutionHook(hookConfig));
                } else {
                    // No post. Not necessary to save.
                    _executePreExecutionHook(hookConfig);
                }
            } else if (hookConfig.hasPost()) {
                // Must cache for running post
                res[i] = PreHookResult(hookConfig, "");
            }
        }
    }

    function _executePreExecutionHook(HookConfig hookConfig) private returns (bytes memory) {
        return
            IExecutionHookModule(hookConfig.module()).preExecutionHook(
                hookConfig.entity(),
                msg.sender,
                msg.value,
                msg.data
            );
    }

    function executePreValidationHooks(EnumerableSet.Bytes32Set storage hooks) internal {
        uint256 hooksLength = hooks.length();

        for (uint256 i = 0; i < hooksLength; ++i) {
            HookConfig hookConfig = HookConfig.wrap(bytes25(hooks.at(i)));
            _executeValidationHook(hookConfig, "");
        }
    }

    function _executeValidationHook(HookConfig hookConfig, bytes memory authorization) private {
        IValidationHookModule(hookConfig.module()).preRuntimeValidationHook(
            hookConfig.entity(),
            msg.sender,
            msg.value,
            msg.data,
            authorization
        );
    }

    function executePostHooks(PreHookResult[] memory preHookResults) internal {
        uint256 hooksLength = preHookResults.length;

        for (uint256 i = hooksLength; i > 0; --i) {
            if (preHookResults[i].hookConfig.hasPost()) {
                IExecutionHookModule(preHookResults[i].hookConfig.module()).postExecutionHook(
                    preHookResults[i].hookConfig.entity(),
                    preHookResults[i].data
                );
            }
        }
    }
}
