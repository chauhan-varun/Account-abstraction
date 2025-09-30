// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IAccount} from "lib/account-abstraction/contracts/interfaces/IAccount.sol";
import {PackedUserOperation} from "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "lib/account-abstraction/contracts/core/Helpers.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";

/**
 * @title MinimalAccount
 * @author Varun Chauhan
 * @notice A minimal implementation of an ERC-4337 compatible smart contract
 * account
 * @dev This contract implements the IAccount interface for ERC-4337 account
 * abstraction. It provides basic functionality for signature validation and gas
 * payment handling. The account is owned by a single EOA (Externally Owned
 * Account) which can authorize user operations through ECDSA signatures.
 *
 * Key Features:
 * - ERC-4337 compatible account abstraction
 * - Single owner signature validation
 * - Automatic gas prefunding to EntryPoint
 * - Minimal overhead design for gas efficiency
 *
 * Security Considerations:
 * - Only the owner can authorize user operations
 * - Signature validation uses Ethereum signed message hash format
 * - Prefund failures are silently ignored to prevent DoS attacks
 */
contract MinimalAccount is IAccount, Ownable {
    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Error thrown when a function is called by an unauthorized caller
    error MinimalAccount__CallerNotEntryPoint();
    /// @notice Error thrown when a function is called by neither the EntryPoint nor the owner
    error MinimalAccount__CallerNotEntryPointOrOwner();
    /// @notice Error thrown when a low-level call to an external contract fails
    error MinimalAccount__CallFailed(bytes result);

    /*//////////////////////////////////////////////////////////////
                             STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice The EntryPoint contract that manages user operations
    IEntryPoint private immutable i_entryPoint;

    /*//////////////////////////////////////////////////////////////
                               MODIFIERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Modifier to restrict function access to only the EntryPoint
     * contract
     * @dev This modifier checks if the caller is the EntryPoint contract.
     *      If not, it reverts with an appropriate error.
     */
    modifier requireFromEntryPoint() {
        if (msg.sender != address(i_entryPoint)) {
            revert MinimalAccount__CallerNotEntryPoint();
        }
        _;
    }

    /**
     * @notice Modifier to restrict function access to either the EntryPoint
     * contract or the account owner
     * @dev This modifier checks if the caller is either the EntryPoint
     * contract or the owner of the account.
     *      If not, it reverts with an appropriate error.
     */
    modifier requireFromEntryPointOrOwner() {
        if (msg.sender != address(i_entryPoint) && msg.sender != owner()) {
            revert MinimalAccount__CallerNotEntryPointOrOwner();
        }
        _;
    }

    /*//////////////////////////////////////////////////////////////
                               CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Initializes the MinimalAccount contract
     * @dev Sets the deployer as the initial owner of the account.
     *      This constructor calls the Ownable constructor with msg.sender,
     *      establishing ownership immediately upon deployment.
     */
    constructor() Ownable(msg.sender) {}

    /*//////////////////////////////////////////////////////////////
                             EXTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Validates a user operation according to ERC-4337 specification
     * @dev This function is called by the EntryPoint contract to validate a user
     * operation. It performs signature validation and handles gas prefunding if
     * needed.
     *
     *      The function follows the ERC-4337 validation flow:
     *      1. Validate the signature against the user operation hash
     *      2. Pay any missing funds to the EntryPoint for gas coverage
     *
     * @param userOp The user operation to validate, containing all transaction
     * details
     * @param userOpHash The hash of the user operation, used for signature
     * verification
     * @param missingAccountFunds The amount of funds this account needs to pay to
     * the EntryPoint
     * @return validationData Encoded validation result:
     *         - SIG_VALIDATION_SUCCESS (0) if signature is valid
     *         - SIG_VALIDATION_FAILED (1) if signature is invalid
     *         - Can also encode time bounds for signature validity (not used in
     * this implementation)
     *
     * @custom:security Only callable by EntryPoint contract during user operation
     * validation
     */
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external requireFromEntryPoint returns (uint256 validationData) {
        // Validate the signature first
        validationData = _validateSignature(userOp, userOpHash);

        // Pay the required prefund to EntryPoint for gas coverage
        _payPrefund(missingAccountFunds);
    }

    /**
     * @notice Executes a transaction from this account
     * @dev This function allows the account owner to execute arbitrary
     * transactions. It can be called by either the EntryPoint contract or the
     * owner.
     *      The function performs a low-level call to the target address with the
     * specified value and data.
     *      If the call fails, it reverts with the returned error data.
     * @param target The address of the contract or account to call
     * @param value The amount of wei to send with the call
     * @param data The calldata to send in the call
     * @custom:security Only callable by EntryPoint or the account owner
     */
    function execute(
        address target,
        uint256 value,
        bytes calldata data
    ) external onlyOwner {
        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) {
            revert MinimalAccount__CallFailed(result);
        }
    }

    /*//////////////////////////////////////////////////////////////
                             INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Validates the signature of a user operation
     * @dev This internal function performs ECDSA signature validation using the
     * Ethereum signed message hash format. The process includes:
     *
     *      1. Convert the userOpHash to an Ethereum signed message hash (adds
     * "\x19Ethereum Signed Message:\n32" prefix)
     *      2. Recover the signer's address from the signature
     *      3. Compare the recovered address with the account owner
     *
     *      This follows the standard Ethereum message signing convention where
     * users sign a prefixed hash to prevent signature reuse across different
     * contexts.
     *
     * @param userOp The user operation containing the signature to validate
     * @param userOpHash The hash of the user operation that was signed
     * @return uint256 Validation result:
     *         - SIG_VALIDATION_SUCCESS (0) if the signature is valid and from the
     * owner
     *         - SIG_VALIDATION_FAILED (1) if the signature is invalid or from wrong
     * signer
     *
     * @custom:security Critical function - ensures only the owner can authorize
     * operations
     */

    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal view returns (uint256) {
        // Convert to Ethereum signed message hash format
        // This adds the "\x19Ethereum Signed Message:\n32" prefix
        bytes32 ethSignedMessageHash = MessageHashUtils.toEthSignedMessageHash(
            userOpHash
        );

        // Recover the signer address from the signature
        address signer = ECDSA.recover(ethSignedMessageHash, userOp.signature);

        // Check if the recovered signer matches the account owner
        if (signer != owner()) {
            return SIG_VALIDATION_FAILED;
        }

        return SIG_VALIDATION_SUCCESS;
    }

    /**
     * @notice Pays the required prefund to the EntryPoint contract
     * @dev This internal function handles the gas prefunding mechanism required by
     * ERC-4337. The EntryPoint contract calculates how much ETH this account needs
     * to provide to cover the gas costs of the user operation execution.
     *
     *      Key behaviors:
     *      - Only sends funds if missingAccountFunds > 0
     *      - Sends ETH directly to msg.sender (which should be the EntryPoint)
     *      - Intentionally ignores transfer failures to prevent DoS attacks
     *      - Uses low-level call for maximum gas efficiency
     *
     * @param missingAccountFunds The amount of wei to send to the EntryPoint for
     * gas coverage
     *
     * @custom:security Failures are silently ignored to prevent malicious
     * EntryPoints from causing DoS attacks by reverting on fund transfers
     */
    function _payPrefund(uint256 missingAccountFunds) internal {
        // Only attempt payment if funds are actually needed
        if (missingAccountFunds != 0) {
            // Send ETH to the EntryPoint (msg.sender) using low-level call
            // This is more gas efficient than using transfer() or send()
            (bool success, ) = address(msg.sender).call{
                value: missingAccountFunds
            }("");

            // Intentionally ignore the success result
            // This prevents DoS attacks where a malicious EntryPoint could revert
            // the fund transfer and cause the entire user operation to fail
            success; // suppress unused variable warning
        }
    }
}
