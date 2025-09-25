// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IAllowanceTransfer} from "permit2/interfaces/IAllowanceTransfer.sol";
import {ISignatureTransfer} from "permit2/interfaces/ISignatureTransfer.sol";

library ArrayHelpers {
    function destructure(
        IAllowanceTransfer.PermitDetails[] memory array
    )
        internal
        pure
        returns (address[] memory tokens, uint160[] memory amounts, uint48[] memory expirations, uint48[] memory nonces)
    {
        uint256 length = array.length;
        tokens = new address[](length);
        amounts = new uint160[](length);
        expirations = new uint48[](length);
        nonces = new uint48[](length);

        for (uint256 i; i < length; ++i) {
            tokens[i] = array[i].token;
            amounts[i] = array[i].amount;
            expirations[i] = array[i].expiration;
            nonces[i] = array[i].nonce;
        }
    }

    function destructure(
        ISignatureTransfer.TokenPermissions[] memory array
    ) internal pure returns (address[] memory tokens, uint256[] memory amounts) {
        uint256 length = array.length;
        tokens = new address[](length);
        amounts = new uint256[](length);

        for (uint256 i; i < length; ++i) {
            tokens[i] = array[i].token;
            amounts[i] = array[i].amount;
        }
    }

    function populate(uint256 target, uint256 length) internal pure returns (uint256[] memory array) {
        array = new uint256[](length);
        for (uint256 i; i < length; ++i) {
            array[i] = target;
        }
    }

    function append(uint256[] memory array, uint256 target) internal pure returns (uint256[] memory) {
        assembly ("memory-safe") {
            mstore(array, add(mload(array), 1))
        }
        array[array.length - 1] = target;
        return array;
    }

    function populate(address target, uint256 length) internal pure returns (address[] memory array) {
        array = new address[](length);
        for (uint256 i; i < length; ++i) {
            array[i] = target;
        }
    }

    function append(address[] memory array, address target) internal pure returns (address[] memory) {
        assembly ("memory-safe") {
            mstore(array, add(mload(array), 1))
        }
        array[array.length - 1] = target;
        return array;
    }
}
