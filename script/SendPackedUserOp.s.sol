// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {PackedUserOperation} from "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {HelperConfig} from "./HelperConfig.s.sol";

contract SendPackedUserOp is Script {
    using MessageHashUtils for bytes32;

    function run() public {}

    function generateSignedUserOperation(
        bytes memory callData,
        HelperConfig.NetworkConfig memory config
    ) public view returns (PackedUserOperation memory) {
        uint256 nounce = vm.getNonce(config.account);
        PackedUserOperation memory userOp = _generateUnsignedUserOperation(
            callData,
            config.account,
            nounce
        );

        bytes32 userOpHash = IEntryPoint(config.entryPoint).getUserOpHash(
            userOp
        );
        bytes32 ethSignedMessageHash = userOpHash.toEthSignedMessageHash();
        uint8 v;
        bytes32 r;
        bytes32 s;

        uint256 ANVIL_PRIVATE_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
        if (block.chainid == 31337)
            (v, r, s) = vm.sign(ANVIL_PRIVATE_KEY, ethSignedMessageHash);
        else (v, r, s) = vm.sign(config.account, ethSignedMessageHash);
        userOp.signature = abi.encodePacked(r, s, v);
        return userOp;
    }

    function _generateUnsignedUserOperation(
        bytes memory callData,
        address sender,
        uint256 nonce
    ) internal pure returns (PackedUserOperation memory) {
        uint128 verificationGasLimit = 16777216;
        uint128 callGasLimit = 16777216;
        uint128 maxPriorityFeePerGas = 256;
        uint128 maxFeePerGas = maxPriorityFeePerGas;
        return
            //         struct PackedUserOperation {
            //     address sender;
            //     uint256 nonce;
            //     bytes initCode;
            //     bytes callData;
            //     bytes32 accountGasLimits;
            //     uint256 preVerificationGas;
            //     bytes32 gasFees;
            //     bytes paymasterAndData;
            //     bytes signature;
            // }

            PackedUserOperation({
                sender: sender,
                nonce: nonce,
                initCode: hex"",
                callData: callData,
                // accountGasLimits is packed as
                // abi.encodePacked(uint128(verificationGasLimit),
                // uint128(callGasLimit))
                accountGasLimits: bytes32(
                    abi.encodePacked(
                        uint128(verificationGasLimit),
                        uint128(callGasLimit)
                    )
                ),
                // preVerificationGas is a separate field (batch overhead); reuse
                // verificationGasLimit here if desired
                preVerificationGas: verificationGasLimit,
                gasFees: bytes32(
                    (uint256(maxPriorityFeePerGas) << 128) |
                        uint256(maxFeePerGas)
                ),
                paymasterAndData: hex"",
                signature: hex""
            });
    }
}
