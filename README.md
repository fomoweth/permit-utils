# Permit Utils

Utility libraries and helpers for working with **EIP-2612** and **Permit2** signatures in Solidity and Foundry tests.

This repository provides building blocks for constructing permit structs, computing their EIP-712 hashes, and generating signatures for testing and integration with protocols that use ERC20 permits.

---

## Overview

```text
permit-utils
├── src
│   ├── EIP2612Permit.sol
│   ├── PermitSignatures.sol
│   ├── PermitUtils.sol
│   ├── StructBuilder.sol
│   └── TypeHashes.sol
└── test
    └── ...
```

### **EIP2612Permit**

Defines the `EIP2612Permit` struct to represent EIP-2612 compliant permit parameters:

- `owner`
- `spender`
- `value`
- `nonce`
- `deadline`

---

### **PermitSignatures**

Helper library for **signing permits** using Foundry’s `vm.sign` cheatcode:

- Supports **EIP-2612 permits** and **Permit2 structs**.
- Standard `(r, s, v)` and compact `(r, vs)` signatures.
- Produces ready-to-use bytes for contract calls.

---

### **StructBuilder**

Utility for **constructing Permit2 structs** in memory:

- Build `PermitSingle`, `PermitBatch`, `PermitTransferFrom`, and `PermitBatchTransferFrom` variants.
- Simplifies test setup with builder-style APIs.

---

### **TypeHashes**

Library for computing **EIP-712 type hashes** and struct hashes:

- Precomputed constants for ERC20 and Permit2.
- Hash helpers that mirror on-chain implementations.

---

## Quick Reference Table

| **Struct**                                 | **TypeHash**                                          | **Hash Helper**                                                                              |
| ------------------------------------------ | ----------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| `EIP2612Permit` (ERC20 Permit)             | `ERC20_PERMIT_TYPEHASH` / `ERC20_PERMIT_DAI_TYPEHASH` | `TypeHashes.hash(EIP2612Permit, isEIP2612)`                                                  |
| `PermitSingle` (Permit2)                   | `PERMIT_SINGLE_TYPEHASH`                              | `TypeHashes.hash(IAllowanceTransfer.PermitSingle)`                                           |
| `PermitBatch` (Permit2)                    | `PERMIT_BATCH_TYPEHASH`                               | `TypeHashes.hash(IAllowanceTransfer.PermitBatch)`                                            |
| `PermitTransferFrom` (Permit2)             | `PERMIT_TRANSFER_FROM_TYPEHASH`                       | `TypeHashes.hash(ISignatureTransfer.PermitTransferFrom, spender)`                            |
| `PermitBatchTransferFrom` (Permit2)        | `PERMIT_BATCH_TRANSFER_FROM_TYPEHASH`                 | `TypeHashes.hash(ISignatureTransfer.PermitBatchTransferFrom, spender)`                       |
| `PermitWitnessTransferFrom` (Permit2)      | `PERMIT_WITNESS_TRANSFER_FROM_TYPEHASH`               | `TypeHashes.hash(ISignatureTransfer.PermitTransferFrom, spender, witnessType, witness)`      |
| `PermitBatchWitnessTransferFrom` (Permit2) | `PERMIT_BATCH_WITNESS_TRANSFER_FROM_TYPEHASH`         | `TypeHashes.hash(ISignatureTransfer.PermitBatchTransferFrom, spender, witnessType, witness)` |

---

## Permit2 Struct Hierarchy

```text
Permit2 Ecosystem
├── AllowanceTransfer
│   ├── PermitSingle
│   │   ├── PermitDetails details
│   │   ├── address spender
│   │   └── uint256 sigDeadline
│   │
│   └── PermitBatch
│       ├── PermitDetails[] details
│       ├── address spender
│       └── uint256 sigDeadline
│
├── SignatureTransfer
│   ├── PermitTransferFrom
│   │   ├── TokenPermissions permitted
│   │   ├── uint256 nonce
│   │   └── uint256 deadline
│   │
│   ├── PermitBatchTransferFrom
│   │   ├── TokenPermissions[] permitted
│   │   ├── uint256 nonce
│   │   └── uint256 deadline
│   │
│   ├── PermitWitnessTransferFrom
│   │   ├── PermitTransferFrom (base)
│   │   ├── bytes witness
│   │   └── string witnessTypeString
│   │
│   └── PermitBatchWitnessTransferFrom
│       ├── PermitBatchTransferFrom (base)
│       ├── bytes witness
│       └── string witnessTypeString
│
└── Core Components
    ├── PermitDetails
    │   ├── address token
    │   ├── uint160 amount
    │   ├── uint48 expiration
    │   └── uint48 nonce
    │
    ├── TokenPermissions
    │   ├── address token
    │   └── uint256 amount
    │
    └── SignatureTransferDetails
        ├── address to
        └── uint256 requestedAmount
```

- **AllowanceTransfer**: approval-style, focuses on allowances (`PermitSingle`, `PermitBatch`).
- **SignatureTransfer**: transfer-style, focuses on moving tokens in a signed flow.
- **Witness variants**: extend the base permits with arbitrary offchain “witness” data.

---

## Installation

```bash
forge install fomoweth/permit-utils
```

## Usage Examples

```solidity
import {IERC20Permit} from "lib/openzeppelin-contracts/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {SignatureChecker} from "lib/openzeppelin-contracts/contracts/utils/cryptography/SignatureChecker.sol";
import {IPermit2, IAllowanceTransfer, ISignatureTransfer} from "lib/permit2/src/interfaces/IPermit2.sol";
import {EIP2612Permit, PermitSignatures, StructBuilder, TypeHashes} from "lib/permit-utils/PermitUtils.sol";

contract PermitTest is Test {
    using PermitSignatures for bytes;
    using StructBuilder for *;
    using TypeHashes for *;

    IPermit2 internal constant PERMIT2 = IPermit2(0x000000000022D473030F116dDEE9F6B43aC78BA3);

    address internal constant DAI = 0x6B175474E89094C44Da98b954EedeAC495271d0F;

    uint256 internal privateKey;
    address internal signer;

    function setUp() public {
        privateKey = ...;
        signer = vm.addr(privateKey);
    }

    function test_signEip2612Permit() public {
        EIP2612Permit memory permit = EIP2612Permit({
            owner: signer,
            spender: ...,
            value: 1 ether,
            nonce: 0,
            deadline: block.timestamp + 5 minutes
        });

        address token = ...;

        bytes32 domainSeparator = IERC20Permit(token).DOMAIN_SEPARATOR();

        (uint8 v, bytes32 r, bytes32 s) = PermitSignatures.sign(privateKey, domainSeparator, permit).parse();

        IERC20Permit(token).permit(permit.owner, permit.spender, permit.value, permit.deadline, v, r, s);
    }

    function test_signDaiPermit() public {
        EIP2612Permit memory permit = EIP2612Permit({
            owner: signer,
            spender: ...,
            value: 1 ether,
            nonce: 0,
            deadline: block.timestamp + 5 minutes
        });

        bytes32 domainSeparator = IERC20Permit(DAI).DOMAIN_SEPARATOR();

        bytes memory signature = PermitSignatures.sign(privateKey, domainSeparator, permit);

        bytes32 structHash = permit.hash(false); // `false` for DAI

        bytes32 messageHash = domainSeparator.hashTypedData(structHash);

        assertTrue(SignatureChecker.isValidSignatureNow(signer, messageHash, signature));
    }

    function test_signPermitSingle() public {
        address spender = ...;
        uint256 sigDeadline = ...;

        address token = ...;
        uint160 amount = ...;
        uint48 expiration = type(uint48).max;
        uint48 nonce = ...;

        IAllowanceTransfer.PermitDetails memory details =
            StructBuilder.asPermitDetails(token, amount, expiration, nonce);

        IAllowanceTransfer.PermitSingle memory permit = StructBuilder
            .init(spender, sigDeadline)
            .set(details)
            .validate();

        bytes32 domainSeparator = PERMIT2.DOMAIN_SEPARATOR();

        bytes memory signature = PermitSignatures.signCompact(privateKey, domainSeparator, permit);

        PERMIT2.permit(signer, permit, signature);
    }

    function test_signPermitBatch() public {
        address spender = ...;
        uint256 sigDeadline = ...;

        address[] memory tokens = ...;
        uint256[] memory amounts = ...;
        uint256[] memory expirations = ...;
        uint256[] memory nonces = ...;

        IAllowanceTransfer.PermitBatch memory permit = StructBuilder
            .init(spender, sigDeadline, tokens.length)
            .set(tokens, amounts, expirations, nonces)
            .validate();

        bytes32 domainSeparator = PERMIT2.DOMAIN_SEPARATOR();

        bytes memory signature = PermitSignatures.signCompact(privateKey, domainSeparator, permit);

        PERMIT2.permit(signer, permit, signature);
    }

    function test_signPermitTransfer() public {
        uint256 nonce = ...;
        uint256 deadline = ...;

        address token = ...;
        uint256 amount = ...;
        address recipient = ...;

        ISignatureTransfer.SignatureTransferDetails memory transferDetails =
            StructBuilder.asSignatureTransferDetails(recipient, amount);

        ISignatureTransfer.PermitTransferFrom memory permit = StructBuilder
            .init(nonce, deadline)
            .set(token, amount)
            .validate();

        bytes32 domainSeparator = PERMIT2.DOMAIN_SEPARATOR();

        bytes memory signature = PermitSignatures.signCompact(privateKey, domainSeparator, permit);

        PERMIT2.permitTransferFrom(permit, transferDetails, signer, signature);
    }

    function test_signPermitBatchTransfer() public {
        uint256 nonce = ...;
        uint256 deadline = ...;

        address[] memory tokens = ...;
        uint256[] memory amounts = ...;
        address[] memory recipients = ...;

        ISignatureTransfer.SignatureTransferDetails[] memory transferDetails =
            StructBuilder.asSignatureTransferDetails(recipients, amounts);

        ISignatureTransfer.TokenPermissions[] memory permitted =
            StructBuilder.asTokenPermissions(tokens, amounts);

        ISignatureTransfer.PermitBatchTransferFrom memory permit = StructBuilder
            .init(nonce, deadline, permitted.length)
            .set(permitted)
            .validate();

        bytes32 domainSeparator = PERMIT2.DOMAIN_SEPARATOR();

        bytes memory signature = PermitSignatures.signCompact(privateKey, domainSeparator, permit);

        PERMIT2.permitTransferFrom(permit, transferDetails, signer, signature);
    }

    struct MockWitness {
        uint256 value;
        address person;
        bool test;
    }

    string internal constant MOCK_WITNESS_TYPE = "MockWitness(uint256 value,address person,bool test)";
    bytes32 internal constant MOCK_WITNESS_TYPEHASH = keccak256(bytes(MOCK_WITNESS_TYPE));

    string internal constant MOCK_WITNESS_TYPESTRING =
        "MockWitness witness)MockWitness(uint256 value,address person,bool test)TokenPermissions(address token,uint256 amount)";

    function test_signPermitWitnessTransfer() public {
        MockWitness memory witnessData = ...;
        string memory witnessTypeString = TypeHashes.WITNESS_TYPESTRING(MOCK_WITNESS_TYPE);
        bytes32 witness = keccak256(abi.encode(MOCK_WITNESS_TYPEHASH, witnessData));
        assertEq(witnessTypeString, MOCK_WITNESS_TYPESTRING);

        uint256 nonce = ...;
        uint256 deadline = ...;

        address token = ...;
        uint256 amount = ...;
        address recipient = ...;

        ISignatureTransfer.SignatureTransferDetails memory transferDetails =
            StructBuilder.asSignatureTransferDetails(recipient, amount);

        ISignatureTransfer.PermitTransferFrom memory permit = StructBuilder
            .init(nonce, deadline)
            .set(token, amount)
            .validate();

        bytes32 domainSeparator = PERMIT2.DOMAIN_SEPARATOR();

        bytes memory signature = PermitSignatures.signCompact(privateKey, domainSeparator, permit);

        PERMIT2.permitWitnessTransferFrom(permit, transferDetails, signer, witness, witnessTypeString, signature);
    }

    function test_signPermitWitnessBatchTransfer() public {
        MockWitness memory witnessData = ...;
        string memory witnessTypeString = TypeHashes.WITNESS_TYPESTRING(MOCK_WITNESS_TYPE);
        bytes32 witness = keccak256(abi.encode(MOCK_WITNESS_TYPEHASH, witnessData));
        assertEq(witnessTypeString, MOCK_WITNESS_TYPESTRING);

        uint256 nonce = ...;
        uint256 deadline = ...;

        address[] memory tokens = ...;
        uint256[] memory amounts = ...;
        address[] memory recipients = ...;

        ISignatureTransfer.SignatureTransferDetails[] memory transferDetails =
            StructBuilder.asSignatureTransferDetails(recipients, amounts);

        ISignatureTransfer.PermitBatchTransferFrom memory permit = StructBuilder
            .init(nonce, deadline, permitted.length)
            .set(tokens, amounts)
            .validate();

        bytes32 domainSeparator = PERMIT2.DOMAIN_SEPARATOR();

        bytes memory signature = PermitSignatures.signCompact(privateKey, domainSeparator, permit);

        PERMIT2.permitWitnessTransferFrom(permit, transferDetails, signer, witness, witnessTypeString, signature);
    }
}
```

---

## Motivation

Permit-based approvals (EIP-2612 and Permit2) are widely adopted in DeFi, but their signatures and struct encoding can be tricky to test.
This repository provides a focused toolkit for:
• Struct construction
• Type hashing
• EIP-712 digest computation
• Signature generation

So developers can write robust unit and integration tests quickly.

## References

- [EIP-2612: Permit Extension for EIP-20 Signed Approvals](https://eips.ethereum.org/EIPS/eip-2612)
- [EIP-712: Typed structured data hashing and signing](https://eips.ethereum.org/EIPS/eip-712)
- [Permit2 by Uniswap](https://github.com/Uniswap/permit2)
