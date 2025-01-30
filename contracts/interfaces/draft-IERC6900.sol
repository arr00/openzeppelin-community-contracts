// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/// @dev A packed representation of a module function.
/// Consists of the following, left-aligned:
/// Module address: 20 bytes
/// Entity ID:      4 bytes
type ModuleEntity is bytes24;

/// @dev A packed representation of a validation function and its associated flags.
/// Consists of the following, left-aligned:
/// Module address:     20 bytes
/// Entity ID:          4 bytes
/// ValidationFlags:    1 byte
type ValidationConfig is bytes25;

// ValidationFlags layout:
// 0b00000___ // unused
// 0b_____A__ // isGlobal
// 0b______B_ // isSignatureValidation
// 0b_______C // isUserOpValidation
type ValidationFlags is uint8;

/// @dev A packed representation of a hook function and its associated flags.
/// Consists of the following, left-aligned:
/// Module address: 20 bytes
/// Entity ID:      4 bytes
/// Flags:          1 byte
///
/// Hook flags layout:
/// 0b00000___ // unused
/// 0b_____A__ // hasPre (exec only)
/// 0b______B_ // hasPost (exec only)
/// 0b_______C // hook type (0 for exec, 1 for validation)
type HookConfig is bytes25;

struct Call {
    // The target address for the account to call.
    address target;
    // The value to send with the call.
    uint256 value;
    // The calldata for the call.
    bytes data;
}

struct ManifestExecutionFunction {
    // The selector to install.
    bytes4 executionSelector;
    // If true, the function won't need runtime validation, and can be called by anyone.
    bool skipRuntimeValidation;
    // If true, the function can be validated by a global validation function.
    bool allowGlobalValidation;
}

struct ManifestExecutionHook {
    bytes4 executionSelector;
    uint32 entityId;
    bool isPreHook;
    bool isPostHook;
}

struct ExecutionManifest {
    // Execution functions defined in this module to be installed on the MSCA.
    ManifestExecutionFunction[] executionFunctions;
    ManifestExecutionHook[] executionHooks;
    // List of ERC-165 interface IDs to add to account to support introspection checks. This MUST NOT include
    // IModule's interface ID.
    bytes4[] interfaceIds;
}

interface IModularAccount {
    event ExecutionInstalled(address indexed module, ExecutionManifest manifest);
    event ExecutionUninstalled(address indexed module, bool onUninstallSucceeded, ExecutionManifest manifest);
    event ValidationInstalled(address indexed module, uint32 indexed entityId);
    event ValidationUninstalled(address indexed module, uint32 indexed entityId, bool onUninstallSucceeded);

    /// @notice Standard execute method.
    /// @param target The target address for the account to call.
    /// @param value The value to send with the call.
    /// @param data The calldata for the call.
    /// @return The return data from the call.
    function execute(address target, uint256 value, bytes calldata data) external payable returns (bytes memory);

    /// @notice Standard executeBatch method.
    /// @dev If the target is a module, the call SHOULD revert. If any of the calls revert, the entire batch MUST
    /// revert.
    /// @param calls The array of calls.
    /// @return An array containing the return data from the calls.
    function executeBatch(Call[] calldata calls) external payable returns (bytes[] memory);

    /// @notice Execute a call using the specified runtime validation.
    /// @param data The calldata to send to the account.
    /// @param authorization The authorization data to use for the call. The first 24 bytes is a ModuleEntity which
    /// specifies which runtime validation to use, and the rest is sent as a parameter to runtime validation.
    function executeWithRuntimeValidation(
        bytes calldata data,
        bytes calldata authorization
    ) external payable returns (bytes memory);

    /// @notice Install a module to the modular account.
    /// @param module The module to install.
    /// @param manifest the manifest describing functions to install.
    /// @param installData Optional data to be used by the account to handle the initial execution setup. Data encoding
    /// is implementation-specific.
    function installExecution(address module, ExecutionManifest calldata manifest, bytes calldata installData) external;

    /// @notice Uninstall a module from the modular account.
    /// @param module The module to uninstall.
    /// @param manifest The manifest describing functions to uninstall.
    /// @param uninstallData Optional data to be used by the account to handle the execution uninstallation. Data
    /// encoding is implementation-specific.
    function uninstallExecution(
        address module,
        ExecutionManifest calldata manifest,
        bytes calldata uninstallData
    ) external;

    /// @notice Installs a validation function across a set of execution selectors, and optionally mark it as a
    /// global validation function.
    /// @param validationConfig The validation function to install, along with configuration flags.
    /// @param selectors The selectors to install the validation function for.
    /// @param installData Optional data to be used by the account to handle the initial validation setup. Data
    /// encoding is implementation-specific.
    /// @param hooks Optional hooks to install and associate with the validation function. Data encoding is
    /// implementation-specific.
    function installValidation(
        ValidationConfig validationConfig,
        bytes4[] calldata selectors,
        bytes calldata installData,
        bytes[] calldata hooks
    ) external;

    /// @notice Uninstall a validation function from a set of execution selectors.
    /// @param validationFunction The validation function to uninstall.
    /// @param uninstallData Optional data to be used by the account to handle the validation uninstallation. Data
    /// encoding is implementation-specific.
    /// @param hookUninstallData Optional data to be used by the account to handle hook uninstallation. Data encoding
    /// is implementation-specific.
    function uninstallValidation(
        ModuleEntity validationFunction,
        bytes calldata uninstallData,
        bytes[] calldata hookUninstallData
    ) external;

    /// @notice Return a unique identifier for the account implementation.
    /// @dev This function MUST return a string in the format "vendor.account.semver". The vendor and account
    /// names MUST NOT contain a period character.
    /// @return The account ID.
    function accountId() external view returns (string memory);
}

interface IModule is IERC165 {
    /// @notice Initialize module data for the modular account.
    /// @dev Called by the modular account during `installExecution`.
    /// @param data Optional bytes array to be decoded and used by the module to setup initial module data for the
    /// modular account.
    function onInstall(bytes calldata data) external;

    /// @notice Clear module data for the modular account.
    /// @dev Called by the modular account during `uninstallExecution`.
    /// @param data Optional bytes array to be decoded and used by the module to clear module data for the modular
    /// account.
    function onUninstall(bytes calldata data) external;

    /// @notice Return a unique identifier for the module.
    /// @dev This function MUST return a string in the format "vendor.module.semver". The vendor and module
    /// names MUST NOT contain a period character.
    /// @return The module ID.
    function moduleId() external view returns (string memory);
}
