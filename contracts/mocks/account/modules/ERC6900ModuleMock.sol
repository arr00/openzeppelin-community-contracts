// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IModule} from "contracts/interfaces/draft-IERC6900.sol";
import {ERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";

contract ERC6900ModuleMock is ERC165, IModule {
    event OnInstall(bytes data);
    event OnUninstall(bytes data);

    function onInstall(bytes calldata data) public virtual override {
        emit OnInstall(data);
    }

    function onUninstall(bytes calldata data) public virtual override {
        emit OnUninstall(data);
    }

    function moduleId() public pure virtual override returns (string memory) {
        return "ERC6900ModuleMock";
    }
}
