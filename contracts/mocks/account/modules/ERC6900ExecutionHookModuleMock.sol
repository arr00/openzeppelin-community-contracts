// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IExecutionHookModule} from "contracts/interfaces/draft-IERC6900.sol";
import {ERC6900ModuleMock} from "./ERC6900ModuleMock.sol";

contract ERC6900ExecutionHookModuleMock is ERC6900ModuleMock, IExecutionHookModule {
    event OnPreExecutionHook(uint32 entityId, address sender, uint256 value, bytes data);
    event OnPostExecutionHook(uint32 entityId, bytes preExecHookData);

    function preExecutionHook(
        uint32 entityId,
        address sender,
        uint256 value,
        bytes calldata data
    ) public virtual override returns (bytes memory) {
        emit OnPreExecutionHook(entityId, sender, value, data);
        return "";
    }

    function postExecutionHook(uint32 entityId, bytes calldata preExecHookData) public virtual override {
        emit OnPostExecutionHook(entityId, preExecHookData);
    }
}
