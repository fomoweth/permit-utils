// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IAllowanceTransfer} from "permit2/interfaces/IAllowanceTransfer.sol";
import {ISignatureTransfer} from "permit2/interfaces/ISignatureTransfer.sol";
import {EIP2612Permit, toEIP2612Permit} from "./EIP2612Permit.sol";
import {PermitSignatures} from "./PermitSignatures.sol";
import {StructBuilder} from "./StructBuilder.sol";
import {TypeHashes} from "./TypeHashes.sol";
