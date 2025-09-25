// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IAllowanceTransfer} from "permit2/interfaces/IAllowanceTransfer.sol";
import {ISignatureTransfer} from "permit2/interfaces/ISignatureTransfer.sol";
import {EIP2612Permit} from "./EIP2612Permit.sol";

/// @title TypeHashes
library TypeHashes {
    string internal constant EIP2612_PERMIT_TYPESTRING =
        "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)";
    bytes32 internal constant EIP2612_PERMIT_TYPEHASH = keccak256(bytes(EIP2612_PERMIT_TYPESTRING));

    string internal constant DAI_PERMIT_TYPESTRING =
        "Permit(address holder,address spender,uint256 nonce,uint256 expiry,bool allowed)";
    bytes32 internal constant DAI_PERMIT_TYPEHASH = keccak256(bytes(DAI_PERMIT_TYPESTRING));

    string internal constant PERMIT_DETAILS_TYPESTRING =
        "PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)";
    bytes32 internal constant PERMIT_DETAILS_TYPEHASH = keccak256(bytes(PERMIT_DETAILS_TYPESTRING));

    string internal constant PERMIT_SINGLE_TYPESTRING =
        "PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)";
    bytes32 internal constant PERMIT_SINGLE_TYPEHASH = keccak256(bytes(PERMIT_SINGLE_TYPESTRING));

    string internal constant PERMIT_BATCH_TYPESTRING =
        "PermitBatch(PermitDetails[] details,address spender,uint256 sigDeadline)PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)";
    bytes32 internal constant PERMIT_BATCH_TYPEHASH = keccak256(bytes(PERMIT_BATCH_TYPESTRING));

    string internal constant TOKEN_PERMISSIONS_TYPESTRING = "TokenPermissions(address token,uint256 amount)";
    bytes32 internal constant TOKEN_PERMISSIONS_TYPEHASH = keccak256(bytes(TOKEN_PERMISSIONS_TYPESTRING));

    string internal constant PERMIT_TRANSFER_FROM_TYPESTRING =
        "PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)";
    bytes32 internal constant PERMIT_TRANSFER_FROM_TYPEHASH = keccak256(bytes(PERMIT_TRANSFER_FROM_TYPESTRING));

    string internal constant PERMIT_BATCH_TRANSFER_FROM_TYPESTRING =
        "PermitBatchTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)";
    bytes32 internal constant PERMIT_BATCH_TRANSFER_FROM_TYPEHASH =
        keccak256(bytes(PERMIT_BATCH_TRANSFER_FROM_TYPESTRING));

    string internal constant PERMIT_WITNESS_TRANSFER_FROM_TYPESTRING =
        "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,";

    string internal constant PERMIT_BATCH_WITNESS_TRANSFER_FROM_TYPESTRING =
        "PermitBatchWitnessTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline,";

    function PERMIT_WITNESS_TRANSFER_FROM_TYPEHASH(
        string memory desc
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(PERMIT_WITNESS_TRANSFER_FROM_TYPESTRING, WITNESS_TYPESTRING(desc)));
    }

    function PERMIT_BATCH_WITNESS_TRANSFER_FROM_TYPEHASH(
        string memory desc
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(PERMIT_BATCH_WITNESS_TRANSFER_FROM_TYPESTRING, WITNESS_TYPESTRING(desc)));
    }

    function WITNESS_TYPESTRING(
        string memory desc
    ) internal pure returns (string memory) {
        return string.concat(_slice(desc, 0, _indexOf(desc, "(")), " witness)", desc, TOKEN_PERMISSIONS_TYPESTRING);
    }

    function hash(
        EIP2612Permit memory permit
    ) internal pure returns (bytes32) {
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

    function hash(
        IAllowanceTransfer.PermitSingle memory permit
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(PERMIT_SINGLE_TYPEHASH, _hashPermitDetails(permit.details), permit.spender, permit.sigDeadline)
        );
    }

    function hash(
        IAllowanceTransfer.PermitBatch memory permit
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(PERMIT_BATCH_TYPEHASH, _hashPermitDetails(permit.details), permit.spender, permit.sigDeadline)
        );
    }

    function hash(
        ISignatureTransfer.PermitTransferFrom memory permit,
        address spender
    ) internal pure returns (bytes32) {
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

    function hash(
        ISignatureTransfer.PermitBatchTransferFrom memory permit,
        address spender
    ) internal pure returns (bytes32) {
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
        bytes32 witnessTypeHash,
        bytes32 witness
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                witnessTypeHash,
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
        bytes32 witnessTypeHash,
        bytes32 witness
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                witnessTypeHash,
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

    function _hashPermitDetails(
        IAllowanceTransfer.PermitDetails memory details
    ) private pure returns (bytes32) {
        return keccak256(abi.encode(PERMIT_DETAILS_TYPEHASH, details));
    }

    function _hashPermitDetails(
        IAllowanceTransfer.PermitDetails[] memory details
    ) private pure returns (bytes32) {
        bytes memory hashes;
        for (uint256 i; i < details.length; ++i) {
            hashes = bytes.concat(hashes, _hashPermitDetails(details[i]));
        }
        return keccak256(hashes);
    }

    function _hashTokenPermissions(
        ISignatureTransfer.TokenPermissions memory permitted
    ) private pure returns (bytes32) {
        return keccak256(abi.encode(TOKEN_PERMISSIONS_TYPEHASH, permitted));
    }

    function _hashTokenPermissions(
        ISignatureTransfer.TokenPermissions[] memory permitted
    ) private pure returns (bytes32) {
        bytes memory hashes;
        for (uint256 i; i < permitted.length; ++i) {
            hashes = bytes.concat(hashes, _hashTokenPermissions(permitted[i]));
        }
        return keccak256(hashes);
    }

    function _indexOf(string memory subject, bytes1 needle) private pure returns (uint256 result) {
        assembly ("memory-safe") {
            result := not(0x00)
            if mload(subject) {
                let o := add(subject, 0x20)
                let e := add(o, mload(subject))
                let m := div(not(0x00), 0xff)
                let h := mul(byte(0x00, needle), m)
                m := not(shl(0x07, m))
                for { let i := o } 0x01 {} {
                    let c := xor(mload(i), h)
                    c := not(or(or(add(and(c, m), m), c), m))
                    if c {
                        c := and(not(shr(shl(0x03, sub(e, i)), not(0x00))), c)
                        if c {
                            let r := shl(0x07, lt(0x8421084210842108cc6318c6db6d54be, c))
                            r := or(shl(0x06, lt(0xffffffffffffffff, shr(r, c))), r)
                            // forgefmt: disable-next-item
                            result := add(sub(i, o), shr(0x03, xor(byte(and(0x1f, shr(byte(0x18,
                                mul(0x02040810204081, shr(r, c))), 0x8421084210842108cc6318c6db6d54be)),
                                0xc0c8c8d0c8e8d0d8c8e8e0e8d0d8e0f0c8d0e8d0e0e0d8f0d0d0e0d8f8f8f8f8), r)))
                            break
                        }
                    }
                    i := add(i, 0x20)
                    if iszero(lt(i, e)) { break }
                }
            }
        }
    }

    function _slice(string memory subject, uint256 start, uint256 end) private pure returns (string memory result) {
        assembly ("memory-safe") {
            let l := mload(subject)
            if iszero(gt(l, end)) { end := l }
            if iszero(gt(l, start)) { start := l }
            if lt(start, end) {
                result := mload(0x40)
                let n := sub(end, start)
                let i := add(subject, start)
                let w := not(0x1f)
                for { let j := and(add(n, 0x1f), w) } 0x01 {} {
                    mstore(add(result, j), mload(add(i, j)))
                    j := add(j, w)
                    if iszero(j) { break }
                }
                let o := add(add(result, 0x20), n)
                mstore(o, 0x00)
                mstore(0x40, add(o, 0x20))
                mstore(result, n)
            }
        }
    }
}
