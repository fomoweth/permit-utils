// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {TypeHashes} from "src/TypeHashes.sol";

contract TypeHashesTest is Test {
    struct MockWitness {
        uint256 value;
        address person;
        bool test;
    }

    string internal constant MOCK_WITNESS_TYPE = "MockWitness(uint256 value,address person,bool test)";

    string internal constant MOCK_WITNESS_TYPESTRING =
        "MockWitness witness)MockWitness(uint256 value,address person,bool test)TokenPermissions(address token,uint256 amount)";

    bytes32 internal constant MOCK_WITNESS_TYPEHASH = keccak256(
        "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,MockWitness witness)MockWitness(uint256 value,address person,bool test)TokenPermissions(address token,uint256 amount)"
    );

    bytes32 internal constant MOCK_WITNESS_BATCH_TYPEHASH = keccak256(
        "PermitBatchWitnessTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline,MockWitness witness)MockWitness(uint256 value,address person,bool test)TokenPermissions(address token,uint256 amount)"
    );

    function test_WITNESS_TYPESTRING() public pure {
        assertEq(TypeHashes.WITNESS_TYPESTRING(MOCK_WITNESS_TYPE), MOCK_WITNESS_TYPESTRING);
    }

    function test_PERMIT_WITNESS_TRANSFER_FROM_TYPEHASH() public pure {
        assertEq(TypeHashes.PERMIT_WITNESS_TRANSFER_FROM_TYPEHASH(MOCK_WITNESS_TYPE), MOCK_WITNESS_TYPEHASH);
    }

    function test_PERMIT_BATCH_WITNESS_TRANSFER_FROM_TYPEHASH() public pure {
        assertEq(TypeHashes.PERMIT_BATCH_WITNESS_TRANSFER_FROM_TYPEHASH(MOCK_WITNESS_TYPE), MOCK_WITNESS_BATCH_TYPEHASH);
    }
}
