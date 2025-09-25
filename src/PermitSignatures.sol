// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {StdConstants} from "forge-std/StdConstants.sol";
import {IAllowanceTransfer} from "permit2/interfaces/IAllowanceTransfer.sol";
import {ISignatureTransfer} from "permit2/interfaces/ISignatureTransfer.sol";
import {EIP2612Permit} from "./EIP2612Permit.sol";
import {TypeHashes} from "./TypeHashes.sol";

/// @title PermitSignatures
library PermitSignatures {
    using TypeHashes for *;

    error InvalidSignature();

    bytes32 internal constant DAI_DOMAIN_SEPARATOR = 0xdbb8cf42e1ecb028be3f3dbc922e1d878b963f411dc388ced501601c60f7c6f7;

    function sign(
        uint256 privateKey,
        bytes32 domainSeparator,
        EIP2612Permit memory permit
    ) internal pure returns (bytes memory signature) {
        bytes32 structHash = permit.hash(domainSeparator != DAI_DOMAIN_SEPARATOR);
        return _sign(privateKey, domainSeparator.hashTypedData(structHash));
    }

    function sign(
        uint256 privateKey,
        bytes32 domainSeparator,
        IAllowanceTransfer.PermitSingle memory permit
    ) internal pure returns (bytes memory signature) {
        bytes32 structHash = permit.hash();
        return _sign(privateKey, domainSeparator.hashTypedData(structHash));
    }

    function signCompact(
        uint256 privateKey,
        bytes32 domainSeparator,
        IAllowanceTransfer.PermitSingle memory permit
    ) internal pure returns (bytes memory signature) {
        bytes32 structHash = permit.hash();
        return _signCompact(privateKey, domainSeparator.hashTypedData(structHash));
    }

    function sign(
        uint256 privateKey,
        bytes32 domainSeparator,
        IAllowanceTransfer.PermitBatch memory permit
    ) internal pure returns (bytes memory signature) {
        bytes32 structHash = permit.hash();
        return _sign(privateKey, domainSeparator.hashTypedData(structHash));
    }

    function signCompact(
        uint256 privateKey,
        bytes32 domainSeparator,
        IAllowanceTransfer.PermitBatch memory permit
    ) internal pure returns (bytes memory signature) {
        bytes32 structHash = permit.hash();
        return _signCompact(privateKey, domainSeparator.hashTypedData(structHash));
    }

    function sign(
        uint256 privateKey,
        bytes32 domainSeparator,
        ISignatureTransfer.PermitTransferFrom memory permit,
        address spender
    ) internal pure returns (bytes memory signature) {
        bytes32 structHash = permit.hash(spender);
        return _sign(privateKey, domainSeparator.hashTypedData(structHash));
    }

    function signCompact(
        uint256 privateKey,
        bytes32 domainSeparator,
        ISignatureTransfer.PermitTransferFrom memory permit,
        address spender
    ) internal pure returns (bytes memory signature) {
        bytes32 structHash = permit.hash(spender);
        return _signCompact(privateKey, domainSeparator.hashTypedData(structHash));
    }

    function sign(
        uint256 privateKey,
        bytes32 domainSeparator,
        ISignatureTransfer.PermitBatchTransferFrom memory permit,
        address spender
    ) internal pure returns (bytes memory signature) {
        bytes32 structHash = permit.hash(spender);
        return _sign(privateKey, domainSeparator.hashTypedData(structHash));
    }

    function signCompact(
        uint256 privateKey,
        bytes32 domainSeparator,
        ISignatureTransfer.PermitBatchTransferFrom memory permit,
        address spender
    ) internal pure returns (bytes memory signature) {
        bytes32 structHash = permit.hash(spender);
        return _signCompact(privateKey, domainSeparator.hashTypedData(structHash));
    }

    function sign(
        uint256 privateKey,
        bytes32 domainSeparator,
        ISignatureTransfer.PermitTransferFrom memory permit,
        address spender,
        string memory witnessTypeString,
        bytes32 witness
    ) internal pure returns (bytes memory signature) {
        bytes32 structHash = permit.hash(spender, witnessTypeString, witness);
        return _sign(privateKey, domainSeparator.hashTypedData(structHash));
    }

    function signCompact(
        uint256 privateKey,
        bytes32 domainSeparator,
        ISignatureTransfer.PermitTransferFrom memory permit,
        address spender,
        string memory witnessTypeString,
        bytes32 witness
    ) internal pure returns (bytes memory signature) {
        bytes32 structHash = permit.hash(spender, witnessTypeString, witness);
        return _signCompact(privateKey, domainSeparator.hashTypedData(structHash));
    }

    function sign(
        uint256 privateKey,
        bytes32 domainSeparator,
        ISignatureTransfer.PermitBatchTransferFrom memory permit,
        address spender,
        string memory witnessTypeString,
        bytes32 witness
    ) internal pure returns (bytes memory signature) {
        bytes32 structHash = permit.hash(spender, witnessTypeString, witness);
        return _sign(privateKey, domainSeparator.hashTypedData(structHash));
    }

    function signCompact(
        uint256 privateKey,
        bytes32 domainSeparator,
        ISignatureTransfer.PermitBatchTransferFrom memory permit,
        address spender,
        string memory witnessTypeString,
        bytes32 witness
    ) internal pure returns (bytes memory signature) {
        bytes32 structHash = permit.hash(spender, witnessTypeString, witness);
        return _signCompact(privateKey, domainSeparator.hashTypedData(structHash));
    }

    function parse(
        bytes memory signature
    ) internal pure returns (uint8 v, bytes32 r, bytes32 s) {
        assembly ("memory-safe") {
            switch mload(signature)
            case 65 {
                r := mload(add(signature, 0x20))
                s := mload(add(signature, 0x40))
                v := byte(0, mload(add(signature, 0x60)))
            }
            case 64 {
                let vs := mload(add(signature, 0x40))
                r := mload(add(signature, 0x20))
                s := and(vs, shr(1, not(0)))
                v := add(shr(255, vs), 27)
            }
            default {
                mstore(0x00, 0x8baa579f) // InvalidSignature()
                revert(0x1c, 0x04)
            }
        }
    }

    function parseCompact(
        bytes memory signature
    ) internal pure returns (bytes32 r, bytes32 vs) {
        assembly ("memory-safe") {
            switch mload(signature)
            case 65 {
                r := mload(add(signature, 0x20))
                let s := mload(add(signature, 0x40))
                let v := byte(0, mload(add(signature, 0x60)))
                vs := or(shl(255, sub(v, 27)), s)
            }
            case 64 {
                r := mload(add(signature, 0x20))
                vs := mload(add(signature, 0x40))
            }
            default {
                mstore(0x00, 0x8baa579f) // InvalidSignature()
                revert(0x1c, 0x04)
            }
        }
    }

    function compact(uint8 v, bytes32 s) internal pure returns (bytes32 vs) {
        assembly ("memory-safe") {
            vs := or(shl(255, sub(v, 27)), s)
        }
    }

    function _sign(uint256 privateKey, bytes32 digest) private pure returns (bytes memory signature) {
        (uint8 v, bytes32 r, bytes32 s) = StdConstants.VM.sign(privateKey, digest);
        return bytes.concat(r, s, bytes1(v));
    }

    function _signCompact(uint256 privateKey, bytes32 digest) private pure returns (bytes memory signature) {
        (bytes32 r, bytes32 vs) = StdConstants.VM.signCompact(privateKey, digest);
        return bytes.concat(r, vs);
    }
}
