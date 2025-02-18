// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IValidationHookModule, PackedUserOperation} from "contracts/interfaces/draft-IERC6900.sol";
import {ERC6900ModuleMock} from "./ERC6900ModuleMock.sol";

contract ERC6900ValidationHookModuleMock is ERC6900ModuleMock, IValidationHookModule {
    function preUserOpValidationHook(
        uint32,
        PackedUserOperation calldata,
        bytes32
    ) public virtual override returns (uint256) {
        return 0;
    }

    function preRuntimeValidationHook(
        uint32 entityId,
        address sender,
        uint256 value,
        bytes calldata data,
        bytes calldata authorization
    ) public virtual override {}

    function preSignatureValidationHook(
        uint32 entityId,
        address sender,
        bytes32 hash,
        bytes calldata signature
    ) public view virtual override {}
}
