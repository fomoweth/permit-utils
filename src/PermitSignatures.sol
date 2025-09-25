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

    bytes32 internal constant DAI_DOMAIN_SEPARATOR = 0xdbb8cf42e1ecb028be3f3dbc922e1d878b963f411dc388ced501601c60f7c6f7;

    function sign(uint256 privateKey, bytes32 domainSeparator, EIP2612Permit memory permit)
        internal
        pure
        returns (bytes memory signature)
    {
        bytes32 structHash = permit.hash(domainSeparator != DAI_DOMAIN_SEPARATOR);
        return _sign(privateKey, domainSeparator.hashTypedData(structHash));
    }

    function sign(uint256 privateKey, bytes32 domainSeparator, IAllowanceTransfer.PermitSingle memory permit)
        internal
        pure
        returns (bytes memory signature)
    {
        bytes32 structHash = permit.hash();
        return _sign(privateKey, domainSeparator.hashTypedData(structHash));
    }

    function signCompact(uint256 privateKey, bytes32 domainSeparator, IAllowanceTransfer.PermitSingle memory permit)
        internal
        pure
        returns (bytes memory signature)
    {
        bytes32 structHash = permit.hash();
        return _signCompact(privateKey, domainSeparator.hashTypedData(structHash));
    }

    function sign(uint256 privateKey, bytes32 domainSeparator, IAllowanceTransfer.PermitBatch memory permit)
        internal
        pure
        returns (bytes memory signature)
    {
        bytes32 structHash = permit.hash();
        return _sign(privateKey, domainSeparator.hashTypedData(structHash));
    }

    function signCompact(uint256 privateKey, bytes32 domainSeparator, IAllowanceTransfer.PermitBatch memory permit)
        internal
        pure
        returns (bytes memory signature)
    {
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

    function _sign(uint256 privateKey, bytes32 digest) private pure returns (bytes memory signature) {
        (uint8 v, bytes32 r, bytes32 s) = StdConstants.VM.sign(privateKey, digest);
        return bytes.concat(r, s, bytes1(v));
    }

    function _signCompact(uint256 privateKey, bytes32 digest) private pure returns (bytes memory signature) {
        (bytes32 r, bytes32 vs) = StdConstants.VM.signCompact(privateKey, digest);
        return bytes.concat(r, vs);
    }
}
