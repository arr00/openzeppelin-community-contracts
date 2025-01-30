// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IModularAccount, ModuleEntity, ValidationConfig, ValidationFlags, ExecutionManifest, HookConfig, ManifestExecutionFunction, ManifestExecutionHook, IModule} from "contracts/interfaces/draft-IERC6900.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

library ERC6900Utils {
    using EnumerableSet for EnumerableSet.Bytes32Set;

    function module(ValidationConfig validationConfig) internal pure returns (address) {
        return address(bytes20(ValidationConfig.unwrap(validationConfig)));
    }

    function entity(ValidationConfig validationConfig) internal pure returns (uint32) {
        return uint32(bytes4(ValidationConfig.unwrap(validationConfig) << 160));
    }

    function flags(ValidationConfig validationConfig) internal pure returns (ValidationFlags) {
        return ValidationFlags.wrap(uint8(uint200(ValidationConfig.unwrap(validationConfig))));
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
}
