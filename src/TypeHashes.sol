// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IAllowanceTransfer} from "permit2/interfaces/IAllowanceTransfer.sol";
import {ISignatureTransfer} from "permit2/interfaces/ISignatureTransfer.sol";
import {EIP2612Permit} from "./EIP2612Permit.sol";

/// @title TypeHashes
library TypeHashes {
    /// @dev `keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)")`
    bytes32 internal constant EIP2612_PERMIT_TYPEHASH =
        0x6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9;

    /// @dev `keccak256("Permit(address holder,address spender,uint256 nonce,uint256 expiry,bool allowed)")`
    bytes32 internal constant DAI_PERMIT_TYPEHASH = 0xea2aa0a1be11a07ed86d755c93467f4f82362b452371d1ba94d1715123511acb;

    /// @dev `keccak256("PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)")`
    bytes32 internal constant PERMIT_DETAILS_TYPEHASH =
        0x65626cad6cb96493bf6f5ebea28756c966f023ab9e8a83a7101849d5573b3678;

    /// @dev `keccak256("PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)")`
    bytes32 internal constant PERMIT_SINGLE_TYPEHASH =
        0xf3841cd1ff0085026a6327b620b67997ce40f282c88a8e905a7a5626e310f3d0;

    /// @dev `keccak256("PermitBatch(PermitDetails[] details,address spender,uint256 sigDeadline)PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)")`
    bytes32 internal constant PERMIT_BATCH_TYPEHASH = 0xaf1b0d30d2cab0380e68f0689007e3254993c596f2fdd0aaa7f4d04f79440863;

    /// @dev `keccak256("TokenPermissions(address token,uint256 amount)")`
    bytes32 internal constant TOKEN_PERMISSIONS_TYPEHASH =
        0x618358ac3db8dc274f0cd8829da7e234bd48cd73c4a740aede1adec9846d06a1;

    /// @dev `keccak256("PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)")`
    bytes32 internal constant PERMIT_TRANSFER_FROM_TYPEHASH =
        0x939c21a48a8dbe3a9a2404a1d46691e4d39f6583d6ec6b35714604c986d80106;

    /// @dev `keccak256("PermitBatchTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)")`
    bytes32 internal constant PERMIT_BATCH_TRANSFER_FROM_TYPEHASH =
        0xfcf35f5ac6a2c28868dc44c302166470266239195f02b0ee408334829333b766;

    string internal constant TOKEN_PERMISSIONS_TYPE = "TokenPermissions(address token,uint256 amount)";

    string internal constant PERMIT_WITNESS_TRANSFER_FROM_TYPE =
        "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,";

    string internal constant PERMIT_BATCH_WITNESS_TRANSFER_FROM_TYPE =
        "PermitBatchWitnessTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline,";

    function PERMIT_WITNESS_TRANSFER_FROM_TYPEHASH(string memory typeString) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(PERMIT_WITNESS_TRANSFER_FROM_TYPE, typeString, TOKEN_PERMISSIONS_TYPE));
    }

    function PERMIT_BATCH_WITNESS_TRANSFER_FROM_TYPEHASH(string memory typeString) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(PERMIT_BATCH_WITNESS_TRANSFER_FROM_TYPE, typeString, TOKEN_PERMISSIONS_TYPE));
    }

    function hash(EIP2612Permit memory permit) internal pure returns (bytes32) {
        return hash(permit, true);
    }

    function hash(EIP2612Permit memory permit, bool isEIP2612) internal pure returns (bytes32) {
        return keccak256(
            isEIP2612
                ? abi.encode(
                    EIP2612_PERMIT_TYPEHASH, permit.owner, permit.spender, permit.value, permit.nonce, permit.deadline
                )
                : abi.encode(
                    DAI_PERMIT_TYPEHASH, permit.owner, permit.spender, permit.nonce, permit.deadline, permit.value != 0
                )
        );
    }

    function hash(IAllowanceTransfer.PermitSingle memory permit) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(PERMIT_SINGLE_TYPEHASH, _hashPermitDetails(permit.details), permit.spender, permit.sigDeadline)
        );
    }

    function hash(IAllowanceTransfer.PermitBatch memory permit) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(PERMIT_BATCH_TYPEHASH, _hashPermitDetails(permit.details), permit.spender, permit.sigDeadline)
        );
    }

    function hash(ISignatureTransfer.PermitTransferFrom memory permit, address spender)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                PERMIT_TRANSFER_FROM_TYPEHASH,
                _hashTokenPermissions(permit.permitted),
                spender,
                permit.nonce,
                permit.deadline
            )
        );
    }

    function hash(ISignatureTransfer.PermitBatchTransferFrom memory permit, address spender)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                PERMIT_BATCH_TRANSFER_FROM_TYPEHASH,
                _hashTokenPermissions(permit.permitted),
                spender,
                permit.nonce,
                permit.deadline
            )
        );
    }

    function hash(
        ISignatureTransfer.PermitTransferFrom memory permit,
        address spender,
        string memory witnessTypeString,
        bytes32 witness
    ) internal pure returns (bytes32) {
        return hash(permit, spender, PERMIT_WITNESS_TRANSFER_FROM_TYPEHASH(witnessTypeString), witness);
    }

    function hash(
        ISignatureTransfer.PermitBatchTransferFrom memory permit,
        address spender,
        string memory witnessTypeString,
        bytes32 witness
    ) internal pure returns (bytes32) {
        return hash(permit, spender, PERMIT_BATCH_WITNESS_TRANSFER_FROM_TYPEHASH(witnessTypeString), witness);
    }

    function hash(
        ISignatureTransfer.PermitTransferFrom memory permit,
        address spender,
        bytes32 witnessTypehash,
        bytes32 witness
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                witnessTypehash,
                _hashTokenPermissions(permit.permitted),
                spender,
                permit.nonce,
                permit.deadline,
                witness
            )
        );
    }

    function hash(
        ISignatureTransfer.PermitBatchTransferFrom memory permit,
        address spender,
        bytes32 witnessTypehash,
        bytes32 witness
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                witnessTypehash,
                _hashTokenPermissions(permit.permitted),
                spender,
                permit.nonce,
                permit.deadline,
                witness
            )
        );
    }

    function hashTypedData(bytes32 domainSeparator, bytes32 structHash) internal pure returns (bytes32 digest) {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, hex"1901")
            mstore(add(ptr, 0x02), domainSeparator)
            mstore(add(ptr, 0x22), structHash)
            digest := keccak256(ptr, 0x42)
        }
    }

    function _hashPermitDetails(IAllowanceTransfer.PermitDetails memory details) private pure returns (bytes32) {
        return keccak256(abi.encode(PERMIT_DETAILS_TYPEHASH, details));
    }

    function _hashPermitDetails(IAllowanceTransfer.PermitDetails[] memory details) private pure returns (bytes32) {
        bytes memory hashes;
        for (uint256 i; i < details.length; ++i) {
            hashes = bytes.concat(hashes, _hashPermitDetails(details[i]));
        }
        return keccak256(hashes);
    }

    function _hashTokenPermissions(ISignatureTransfer.TokenPermissions memory permitted)
        private
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(TOKEN_PERMISSIONS_TYPEHASH, permitted));
    }

    function _hashTokenPermissions(ISignatureTransfer.TokenPermissions[] memory permitted)
        private
        pure
        returns (bytes32)
    {
        bytes memory hashes;
        for (uint256 i; i < permitted.length; ++i) {
            hashes = bytes.concat(hashes, _hashTokenPermissions(permitted[i]));
        }
        return keccak256(hashes);
    }
}
