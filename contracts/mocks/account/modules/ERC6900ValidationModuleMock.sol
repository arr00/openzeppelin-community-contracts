// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IValidationModule, PackedUserOperation} from "contracts/interfaces/draft-IERC6900.sol";
import {ERC6900ModuleMock} from "./ERC6900ModuleMock.sol";

contract ERC6900ExecutionHookModuleMock is ERC6900ModuleMock, IValidationModule {
    function validateUserOp(uint32, PackedUserOperation calldata, bytes32) public virtual override returns (uint256) {
        return 0;
    }

    function validateRuntime(
        address account,
        uint32 entityId,
        address sender,
        uint256 value,
        bytes calldata data,
        bytes calldata authorization
    ) public virtual override {}

    function validateSignature(
        address,
        uint32,
        address,
        bytes32,
        bytes calldata
    ) public view virtual override returns (bytes4) {
        return this.validateSignature.selector;
    }
}
