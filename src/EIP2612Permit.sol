// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

struct EIP2612Permit {
	address owner;
	address spender;
	uint256 nonce;
	uint256 deadline;
	uint256 value;
}

function toEIP2612Permit(
	address owner,
	address spender,
	uint256 nonce,
	uint256 deadline,
	uint256 value
) pure returns (EIP2612Permit memory permit) {
	return EIP2612Permit({owner: owner, spender: spender, nonce: nonce, deadline: deadline, value: value});
}
