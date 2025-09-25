// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IAllowanceTransfer} from "permit2/interfaces/IAllowanceTransfer.sol";
import {ISignatureTransfer} from "permit2/interfaces/ISignatureTransfer.sol";

/// @title StructBuilder
library StructBuilder {
    error EmptyArray();

    error IndexOutOfBounds();

    error InvalidParameter(string);

    error LengthMismatch();

    error MissingRequiredField(string);

    // PermitSingle

    function init(
        address spender,
        uint256 sigDeadline
    ) internal pure returns (IAllowanceTransfer.PermitSingle memory permit) {
        permit.spender = spender;
        permit.sigDeadline = sigDeadline;
    }

    function set(
        IAllowanceTransfer.PermitSingle memory permit,
        IAllowanceTransfer.PermitDetails memory params
    ) internal pure returns (IAllowanceTransfer.PermitSingle memory) {
        permit.details = params;
        return permit;
    }

    function set(
        IAllowanceTransfer.PermitSingle memory permit,
        address token,
        uint256 amount,
        uint256 expiration,
        uint256 nonce
    ) internal pure returns (IAllowanceTransfer.PermitSingle memory) {
        return set(permit, asPermitDetails(token, amount, expiration, nonce));
    }

    function validate(
        IAllowanceTransfer.PermitSingle memory permit
    ) internal pure returns (IAllowanceTransfer.PermitSingle memory) {
        if (permit.spender == address(0)) revert MissingRequiredField("spender");
        if (permit.sigDeadline == 0) revert MissingRequiredField("sigDeadline");
        if (permit.details.token == address(0)) revert MissingRequiredField("details");
        return permit;
    }

    // PermitBatch

    function init(
        address spender,
        uint256 sigDeadline,
        uint256 capacity
    ) internal pure returns (IAllowanceTransfer.PermitBatch memory permit) {
        permit.details = new IAllowanceTransfer.PermitDetails[](capacity);
        permit.spender = spender;
        permit.sigDeadline = sigDeadline;
    }

    function set(
        IAllowanceTransfer.PermitBatch memory permit,
        IAllowanceTransfer.PermitDetails[] memory params
    ) internal pure returns (IAllowanceTransfer.PermitBatch memory) {
        if (params.length == 0) revert EmptyArray();
        permit.details = params;
        return permit;
    }

    function set(
        IAllowanceTransfer.PermitBatch memory permit,
        address[] memory tokens,
        uint256[] memory amounts,
        uint256[] memory expirations,
        uint256[] memory nonces
    ) internal pure returns (IAllowanceTransfer.PermitBatch memory) {
        return set(permit, asPermitDetails(tokens, amounts, expirations, nonces));
    }

    function set(
        IAllowanceTransfer.PermitBatch memory permit,
        uint256 index,
        IAllowanceTransfer.PermitDetails memory params
    ) internal pure returns (IAllowanceTransfer.PermitBatch memory) {
        if (index >= permit.details.length) revert IndexOutOfBounds();
        permit.details[index] = params;
        return permit;
    }

    function set(
        IAllowanceTransfer.PermitBatch memory permit,
        uint256 index,
        address token,
        uint256 amount,
        uint256 expiration,
        uint256 nonce
    ) internal pure returns (IAllowanceTransfer.PermitBatch memory) {
        return set(permit, index, asPermitDetails(token, amount, expiration, nonce));
    }

    function add(
        IAllowanceTransfer.PermitBatch memory permit,
        IAllowanceTransfer.PermitDetails memory params
    ) internal pure returns (IAllowanceTransfer.PermitBatch memory) {
        IAllowanceTransfer.PermitDetails[] memory details = permit.details;
        assembly ("memory-safe") {
            mstore(details, add(mload(details), 1))
        }

        details[details.length - 1] = params;
        permit.details = details;

        return permit;
    }

    function add(
        IAllowanceTransfer.PermitBatch memory permit,
        address token,
        uint256 amount,
        uint256 expiration,
        uint256 nonce
    ) internal pure returns (IAllowanceTransfer.PermitBatch memory) {
        return add(permit, asPermitDetails(token, amount, expiration, nonce));
    }

    function validate(
        IAllowanceTransfer.PermitBatch memory permit
    ) internal pure returns (IAllowanceTransfer.PermitBatch memory) {
        if (permit.spender == address(0)) revert MissingRequiredField("spender");
        if (permit.sigDeadline == 0) revert MissingRequiredField("sigDeadline");
        if (permit.details.length == 0) revert MissingRequiredField("details");
        for (uint256 i; i < permit.details.length; ++i) {
            if (permit.details[i].token == address(0)) revert MissingRequiredField("details");
        }
        return permit;
    }

    // PermitTransferFrom

    function init(
        uint256 nonce,
        uint256 deadline
    ) internal pure returns (ISignatureTransfer.PermitTransferFrom memory permit) {
        permit.nonce = nonce;
        permit.deadline = deadline;
    }

    function set(
        ISignatureTransfer.PermitTransferFrom memory permit,
        ISignatureTransfer.TokenPermissions memory params
    ) internal pure returns (ISignatureTransfer.PermitTransferFrom memory) {
        permit.permitted = params;
        return permit;
    }

    function set(
        ISignatureTransfer.PermitTransferFrom memory permit,
        address token,
        uint256 amount
    ) internal pure returns (ISignatureTransfer.PermitTransferFrom memory) {
        return set(permit, asTokenPermissions(token, amount));
    }

    function validate(
        ISignatureTransfer.PermitTransferFrom memory permit
    ) internal pure returns (ISignatureTransfer.PermitTransferFrom memory) {
        if (permit.deadline == 0) revert MissingRequiredField("deadline");
        if (permit.permitted.token == address(0)) revert MissingRequiredField("permitted");
        return permit;
    }

    // PermitBatchTransferFrom

    function init(
        uint256 nonce,
        uint256 deadline,
        uint256 capacity
    ) internal pure returns (ISignatureTransfer.PermitBatchTransferFrom memory permit) {
        permit.nonce = nonce;
        permit.deadline = deadline;
        permit.permitted = new ISignatureTransfer.TokenPermissions[](capacity);
    }

    function set(
        ISignatureTransfer.PermitBatchTransferFrom memory permit,
        ISignatureTransfer.TokenPermissions[] memory params
    ) internal pure returns (ISignatureTransfer.PermitBatchTransferFrom memory) {
        if (params.length == 0) revert EmptyArray();
        permit.permitted = params;
        return permit;
    }

    function set(
        ISignatureTransfer.PermitBatchTransferFrom memory permit,
        address[] memory tokens,
        uint256[] memory amounts
    ) internal pure returns (ISignatureTransfer.PermitBatchTransferFrom memory) {
        return set(permit, asTokenPermissions(tokens, amounts));
    }

    function set(
        ISignatureTransfer.PermitBatchTransferFrom memory permit,
        uint256 index,
        ISignatureTransfer.TokenPermissions memory params
    ) internal pure returns (ISignatureTransfer.PermitBatchTransferFrom memory) {
        if (index >= permit.permitted.length) revert IndexOutOfBounds();
        permit.permitted[index] = params;
        return permit;
    }

    function set(
        ISignatureTransfer.PermitBatchTransferFrom memory permit,
        uint256 index,
        address token,
        uint256 amount
    ) internal pure returns (ISignatureTransfer.PermitBatchTransferFrom memory) {
        return set(permit, index, asTokenPermissions(token, amount));
    }

    function add(
        ISignatureTransfer.PermitBatchTransferFrom memory permit,
        ISignatureTransfer.TokenPermissions memory params
    ) internal pure returns (ISignatureTransfer.PermitBatchTransferFrom memory) {
        ISignatureTransfer.TokenPermissions[] memory permitted = permit.permitted;
        assembly ("memory-safe") {
            mstore(permitted, add(mload(permitted), 1))
        }

        permitted[permitted.length - 1] = params;
        permit.permitted = permitted;

        return permit;
    }

    function add(
        ISignatureTransfer.PermitBatchTransferFrom memory permit,
        address token,
        uint256 amount
    ) internal pure returns (ISignatureTransfer.PermitBatchTransferFrom memory) {
        return add(permit, asTokenPermissions(token, amount));
    }

    function validate(
        ISignatureTransfer.PermitBatchTransferFrom memory permit
    ) internal pure returns (ISignatureTransfer.PermitBatchTransferFrom memory) {
        if (permit.deadline == 0) revert MissingRequiredField("deadline");
        if (permit.permitted.length == 0) revert MissingRequiredField("permitted");
        for (uint256 i; i < permit.permitted.length; ++i) {
            if (permit.permitted[i].token == address(0)) revert MissingRequiredField("permitted");
        }
        return permit;
    }

    function asPermitDetails(
        address token,
        uint256 amount,
        uint256 nonce
    ) internal pure returns (IAllowanceTransfer.PermitDetails memory) {
        return asPermitDetails(token, amount, 0, nonce);
    }

    function asPermitDetails(
        address token,
        uint256 amount,
        uint256 expiration,
        uint256 nonce
    ) internal pure returns (IAllowanceTransfer.PermitDetails memory) {
        if (token == address(0)) revert InvalidParameter("token");
        if (amount > type(uint160).max) revert InvalidParameter("amount");
        if (expiration > type(uint48).max) revert InvalidParameter("expiration");
        if (nonce > type(uint48).max) revert InvalidParameter("nonce");

        return IAllowanceTransfer.PermitDetails({
            token: token,
            amount: uint160(amount),
            expiration: uint48(expiration),
            nonce: uint48(nonce)
        });
    }

    function asPermitDetails(
        address[] memory tokens,
        uint256[] memory amounts,
        uint256[] memory nonces
    ) internal pure returns (IAllowanceTransfer.PermitDetails[] memory details) {
        uint256 n = tokens.length;
        if (n == 0) revert EmptyArray();
        if (n != amounts.length || n != nonces.length) revert LengthMismatch();

        details = new IAllowanceTransfer.PermitDetails[](n);
        for (uint256 i; i < n; ++i) {
            details[i] = asPermitDetails(tokens[i], amounts[i], nonces[i]);
        }
    }

    function asPermitDetails(
        address[] memory tokens,
        uint256[] memory amounts,
        uint256[] memory expirations,
        uint256[] memory nonces
    ) internal pure returns (IAllowanceTransfer.PermitDetails[] memory details) {
        uint256 n = tokens.length;
        if (n == 0) revert EmptyArray();
        if (n != amounts.length || n != expirations.length || n != nonces.length) revert LengthMismatch();

        details = new IAllowanceTransfer.PermitDetails[](n);
        for (uint256 i; i < n; ++i) {
            details[i] = asPermitDetails(tokens[i], amounts[i], expirations[i], nonces[i]);
        }
    }

    function asTokenPermissions(
        address token,
        uint256 amount
    ) internal pure returns (ISignatureTransfer.TokenPermissions memory) {
        if (token == address(0)) revert InvalidParameter("token");
        return ISignatureTransfer.TokenPermissions({token: token, amount: amount});
    }

    function asTokenPermissions(
        address[] memory tokens,
        uint256[] memory amounts
    ) internal pure returns (ISignatureTransfer.TokenPermissions[] memory permitted) {
        uint256 n = tokens.length;
        if (n == 0) revert EmptyArray();
        if (n != amounts.length) revert LengthMismatch();

        permitted = new ISignatureTransfer.TokenPermissions[](n);
        for (uint256 i; i < n; ++i) {
            permitted[i] = asTokenPermissions(tokens[i], amounts[i]);
        }
    }

    function asSignatureTransferDetails(
        address recipient,
        uint256 amount
    ) internal pure returns (ISignatureTransfer.SignatureTransferDetails memory) {
        if (recipient == address(0)) revert InvalidParameter("recipient");
        return ISignatureTransfer.SignatureTransferDetails({to: recipient, requestedAmount: amount});
    }

    function asSignatureTransferDetails(
        address[] memory recipients,
        uint256[] memory amounts
    ) internal pure returns (ISignatureTransfer.SignatureTransferDetails[] memory transferDetails) {
        uint256 n = recipients.length;
        if (n == 0) revert EmptyArray();
        if (n != amounts.length) revert LengthMismatch();

        transferDetails = new ISignatureTransfer.SignatureTransferDetails[](n);
        for (uint256 i; i < n; ++i) {
            transferDetails[i] = asSignatureTransferDetails(recipients[i], amounts[i]);
        }
    }
}
