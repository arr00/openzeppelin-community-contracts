// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {HookConfig, ModuleEntity, ValidationConfig, ValidationFlags} from "contracts/interfaces/draft-IERC6900.sol";

library ERC6900Utils {
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

    function isGlobal(ValidationFlags validationFlags) internal pure returns (bool) {
        return uint8(ValidationFlags.unwrap(validationFlags)) & (1 << 2) != 0;
    }

    function isSignatureValidation(ValidationFlags validationFlags) internal pure returns (bool) {
        return uint8(ValidationFlags.unwrap(validationFlags)) & (1 << 1) != 0;
    }

    function isUserOpValidation(ValidationFlags validationFlags) internal pure returns (bool) {
        return uint8(ValidationFlags.unwrap(validationFlags)) & 1 != 0;
    }

    function hasPre(HookConfig config) internal pure returns (bool) {
        return uint200(HookConfig.unwrap(config)) & (1 << 2) != 0;
    }

    function hasPost(HookConfig config) internal pure returns (bool) {
        return uint200(HookConfig.unwrap(config)) & (1 << 1) != 0;
    }

    function isValidationHook(HookConfig hookConfig) internal pure returns (bool) {
        return (uint8(uint200(HookConfig.unwrap(hookConfig))) & 1) == 1;
    }

    function module(HookConfig config) internal pure returns (address) {
        return address(bytes20(HookConfig.unwrap(config)));
    }

    function entity(HookConfig config) internal pure returns (uint32) {
        return uint32(uint200(HookConfig.unwrap(config)) >> 8);
    }

    function toBytes32(HookConfig self) internal pure returns (bytes32) {
        return bytes32(HookConfig.unwrap(self));
    }

    function toHookConfig(bytes32 self) internal pure returns (HookConfig) {
        return HookConfig.wrap(bytes25(self));
    }

    function module(ModuleEntity moduleEntity_) internal pure returns (address) {
        return address(bytes20(ModuleEntity.unwrap(moduleEntity_)));
    }

    function entity(ModuleEntity moduleEntity_) internal pure returns (uint32) {
        return uint32(uint192(ModuleEntity.unwrap(moduleEntity_)));
    }
}
