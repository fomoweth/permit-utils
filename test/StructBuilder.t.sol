// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {IAllowanceTransfer} from "permit2/interfaces/IAllowanceTransfer.sol";
import {ISignatureTransfer} from "permit2/interfaces/ISignatureTransfer.sol";
import {StructBuilder} from "src/StructBuilder.sol";
import {ArrayHelpers} from "test/helpers/ArrayHelpers.sol";

contract StructBuilderTest is Test {
    using StructBuilder for *;

    address internal constant WETH_ADDRESS = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address internal constant WBTC_ADDRESS = 0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599;
    address internal constant DAI_ADDRESS = 0x6B175474E89094C44Da98b954EedeAC495271d0F;
    address internal constant USDC_ADDRESS = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address internal constant USDT_ADDRESS = 0xdAC17F958D2ee523a2206206994597C13D831ec7;

    address internal constant DEFAULT_SPENDER = address(0xDEADBEEF);
    uint256 internal constant DEFAULT_DEADLINE = 500;
    uint256 internal constant DEFAULT_NONCE = 18;

    // PermitSingle

    function test_init_permitSingle() public view {
        address spender = address(this);
        uint256 sigDeadline = block.timestamp + 5 minutes;

        IAllowanceTransfer.PermitSingle memory permit = StructBuilder.init(spender, sigDeadline);
        assertEq(permit.spender, spender);
        assertEq(permit.sigDeadline, sigDeadline);
    }

    function test_validate_permitSingle() public {
        IAllowanceTransfer.PermitDetails memory details = IAllowanceTransfer.PermitDetails({
            token: WETH_ADDRESS,
            amount: 10 ether,
            expiration: type(uint48).max,
            nonce: 18
        });

        vm.expectRevert(abi.encodeWithSelector(StructBuilder.MissingRequiredField.selector, "spender"));
        StructBuilder.init(address(0), DEFAULT_DEADLINE).set(details).validate();

        vm.expectRevert(abi.encodeWithSelector(StructBuilder.MissingRequiredField.selector, "sigDeadline"));
        StructBuilder.init(DEFAULT_SPENDER, 0).set(details).validate();

        vm.expectRevert(abi.encodeWithSelector(StructBuilder.MissingRequiredField.selector, "details"));
        address token = details.token;
        details.token = address(0);
        defaultPermitSingle().set(details).validate();
        details.token = token;

        IAllowanceTransfer.PermitSingle memory expected =
            IAllowanceTransfer.PermitSingle({details: details, spender: DEFAULT_SPENDER, sigDeadline: DEFAULT_DEADLINE});

        assertEq(defaultPermitSingle().set(details).validate(), expected);
    }

    function test_set_permitSingle() public pure {
        address token = WETH_ADDRESS;
        uint256 amount = 10 ether;
        uint256 expiration = type(uint48).max;
        uint256 nonce = 18;

        IAllowanceTransfer.PermitDetails memory details = IAllowanceTransfer.PermitDetails({
            token: token,
            amount: uint160(amount),
            expiration: uint48(expiration),
            nonce: uint48(nonce)
        });

        IAllowanceTransfer.PermitSingle memory expected =
            IAllowanceTransfer.PermitSingle({details: details, spender: DEFAULT_SPENDER, sigDeadline: DEFAULT_DEADLINE});

        assertEq(defaultPermitSingle().set(token, amount, expiration, nonce), expected);
        assertEq(defaultPermitSingle().set(details), expected);
    }

    function test_fuzz_set_permitSingle(IAllowanceTransfer.PermitDetails memory details) public pure {
        IAllowanceTransfer.PermitSingle memory expected =
            IAllowanceTransfer.PermitSingle({details: details, spender: DEFAULT_SPENDER, sigDeadline: DEFAULT_DEADLINE});

        assertEq(defaultPermitSingle().set(details), expected);
    }

    function test_fuzz_set_permitSingle(address token, uint256 amount, uint256 expiration, uint256 nonce) public {
        if (token == address(0)) {
            vm.expectRevert(abi.encodeWithSelector(StructBuilder.InvalidParameter.selector, "token"));
        } else if (amount > type(uint160).max) {
            vm.expectRevert(abi.encodeWithSelector(StructBuilder.InvalidParameter.selector, "amount"));
        } else if (expiration > type(uint48).max) {
            vm.expectRevert(abi.encodeWithSelector(StructBuilder.InvalidParameter.selector, "expiration"));
        } else if (nonce > type(uint48).max) {
            vm.expectRevert(abi.encodeWithSelector(StructBuilder.InvalidParameter.selector, "nonce"));
        }

        IAllowanceTransfer.PermitDetails memory details = IAllowanceTransfer.PermitDetails({
            token: token,
            amount: uint160(amount),
            expiration: uint48(expiration),
            nonce: uint48(nonce)
        });

        IAllowanceTransfer.PermitSingle memory expected =
            IAllowanceTransfer.PermitSingle({details: details, spender: DEFAULT_SPENDER, sigDeadline: DEFAULT_DEADLINE});

        assertEq(defaultPermitSingle().set(token, amount, expiration, nonce), expected);
    }

    // PermitBatch

    function test_init_permitBatch() public view {
        address spender = address(this);
        uint256 sigDeadline = block.timestamp + 5 minutes;
        uint256 capacity = 5;

        IAllowanceTransfer.PermitBatch memory permit = StructBuilder.init(spender, sigDeadline, capacity);
        assertEq(permit.spender, spender);
        assertEq(permit.sigDeadline, sigDeadline);
        assertEq(permit.details.length, capacity);
    }

    function test_validate_permitBatch() public {
        IAllowanceTransfer.PermitDetails[] memory details = new IAllowanceTransfer.PermitDetails[](5);
        details[0] = IAllowanceTransfer.PermitDetails({
            token: WETH_ADDRESS,
            amount: 50 ether,
            expiration: type(uint48).max,
            nonce: 0
        });
        details[1] =
            IAllowanceTransfer.PermitDetails({token: WBTC_ADDRESS, amount: 1e8, expiration: type(uint48).max, nonce: 1});
        details[2] = IAllowanceTransfer.PermitDetails({
            token: DAI_ADDRESS,
            amount: 100000 ether,
            expiration: type(uint48).max,
            nonce: 2
        });
        details[3] = IAllowanceTransfer.PermitDetails({
            token: USDC_ADDRESS,
            amount: 100000e6,
            expiration: type(uint48).max,
            nonce: 3
        });
        details[4] = IAllowanceTransfer.PermitDetails({
            token: USDT_ADDRESS,
            amount: 100000e6,
            expiration: type(uint48).max,
            nonce: 4
        });

        vm.expectRevert(abi.encodeWithSelector(StructBuilder.MissingRequiredField.selector, "spender"));
        StructBuilder.init(address(0), DEFAULT_DEADLINE, details.length).set(details).validate();

        vm.expectRevert(abi.encodeWithSelector(StructBuilder.MissingRequiredField.selector, "sigDeadline"));
        StructBuilder.init(DEFAULT_SPENDER, 0, details.length).set(details).validate();

        vm.expectRevert(abi.encodeWithSelector(StructBuilder.MissingRequiredField.selector, "details"));
        defaultPermitBatch(0).validate();

        IAllowanceTransfer.PermitBatch memory expected =
            IAllowanceTransfer.PermitBatch({details: details, spender: DEFAULT_SPENDER, sigDeadline: DEFAULT_DEADLINE});

        IAllowanceTransfer.PermitBatch memory permit = defaultPermitBatch(details.length);
        assertEq(permit.set(details).validate(), expected);

        for (uint256 i; i < details.length; ++i) {
            vm.expectRevert(abi.encodeWithSelector(StructBuilder.MissingRequiredField.selector, "details"));
            address token = details[i].token;
            details[i].token = address(0);
            permit.set(details).validate();
            details[i].token = token;
        }
    }

    function test_set_permitBatch() public pure {
        uint256 length = 5;
        address[] memory tokens = ArrayHelpers.populate(WETH_ADDRESS, length);
        uint256[] memory amounts = ArrayHelpers.populate(type(uint160).max, length);
        uint256[] memory expirations = ArrayHelpers.populate(type(uint48).max, length);
        uint256[] memory nonces = expirations;

        IAllowanceTransfer.PermitDetails[] memory details =
            StructBuilder.asPermitDetails(tokens, amounts, expirations, nonces);

        IAllowanceTransfer.PermitBatch memory expected =
            IAllowanceTransfer.PermitBatch({details: details, spender: DEFAULT_SPENDER, sigDeadline: DEFAULT_DEADLINE});

        assertEq(defaultPermitBatch(length).set(tokens, amounts, expirations, nonces), expected);
        assertEq(defaultPermitBatch(length).set(details), expected);
    }

    function test_set_permitBatch_revertsWithInvalidParameter() public {
        uint256 length = 5;
        address[] memory tokens = ArrayHelpers.populate(WETH_ADDRESS, length);
        uint256[] memory amounts = ArrayHelpers.populate(type(uint160).max, length);
        uint256[] memory expirations = ArrayHelpers.populate(type(uint48).max, length);
        uint256[] memory nonces = expirations;

        IAllowanceTransfer.PermitBatch memory permit = defaultPermitBatch(length);

        for (uint256 i; i < length; ++i) {
            address token = tokens[i];
            tokens[i] = address(0);
            vm.expectRevert(abi.encodeWithSelector(StructBuilder.InvalidParameter.selector, "token"));
            permit.set(tokens, amounts, expirations, nonces);
            tokens[i] = token;

            ++amounts[i];
            vm.expectRevert(abi.encodeWithSelector(StructBuilder.InvalidParameter.selector, "amount"));
            permit.set(tokens, amounts, expirations, nonces);
            --amounts[i];

            ++expirations[i];
            vm.expectRevert(abi.encodeWithSelector(StructBuilder.InvalidParameter.selector, "expiration"));
            permit.set(tokens, amounts, expirations, expirations);
            --expirations[i];

            ++nonces[i];
            vm.expectRevert(abi.encodeWithSelector(StructBuilder.InvalidParameter.selector, "nonce"));
            permit.set(tokens, amounts, expirations, nonces);
            --nonces[i];
        }
    }

    function test_fuzz_set_permitBatch(IAllowanceTransfer.PermitDetails[] memory details) public {
        if (details.length == 0) {
            vm.expectRevert(StructBuilder.EmptyArray.selector);
            defaultPermitBatch(details.length).set(details);
            return;
        }

        IAllowanceTransfer.PermitBatch memory expected =
            IAllowanceTransfer.PermitBatch({details: details, spender: DEFAULT_SPENDER, sigDeadline: DEFAULT_DEADLINE});

        assertEq(defaultPermitBatch(details.length).set(details), expected);

        (address[] memory tokens, uint160[] memory amounts, uint48[] memory expirations, uint48[] memory nonces) =
            ArrayHelpers.destructure(details);

        if (_checkZeroAddress(tokens)) {
            vm.expectRevert(abi.encodeWithSelector(StructBuilder.InvalidParameter.selector, "token"));
        }

        assertEq(
            defaultPermitBatch(details.length).set(tokens, _cast(amounts), _cast(expirations), _cast(nonces)), expected
        );
    }

    function test_fuzz_set_permitBatch(
        address[] memory tokens,
        uint256[] memory amounts,
        uint256[] memory expirations,
        uint256[] memory nonces
    ) public {
        if (tokens.length == 0) {
            vm.expectRevert(StructBuilder.EmptyArray.selector);
            defaultPermitBatch(tokens.length).set(tokens, amounts, expirations, nonces);
        } else if (
            tokens.length != amounts.length || tokens.length != expirations.length || tokens.length != nonces.length
        ) {
            vm.expectRevert(StructBuilder.LengthMismatch.selector);
            defaultPermitBatch(tokens.length).set(tokens, amounts, expirations, nonces);
        } else if (_checkZeroAddress(tokens)) {
            vm.expectRevert(abi.encodeWithSelector(StructBuilder.InvalidParameter.selector, "token"));
            defaultPermitBatch(tokens.length).set(tokens, amounts, expirations, nonces);
        } else if (_checkOverflows(amounts, type(uint160).max)) {
            vm.expectRevert(abi.encodeWithSelector(StructBuilder.InvalidParameter.selector, "amount"));
            defaultPermitBatch(tokens.length).set(tokens, amounts, expirations, nonces);
        } else if (_checkOverflows(expirations, type(uint48).max)) {
            vm.expectRevert(abi.encodeWithSelector(StructBuilder.InvalidParameter.selector, "expiration"));
            defaultPermitBatch(tokens.length).set(tokens, amounts, expirations, nonces);
        } else if (_checkOverflows(nonces, type(uint48).max)) {
            vm.expectRevert(abi.encodeWithSelector(StructBuilder.InvalidParameter.selector, "nonce"));
            defaultPermitBatch(tokens.length).set(tokens, amounts, expirations, nonces);
        } else {
            IAllowanceTransfer.PermitDetails[] memory details =
                StructBuilder.asPermitDetails(tokens, amounts, expirations, nonces);

            IAllowanceTransfer.PermitBatch memory expected = IAllowanceTransfer.PermitBatch({
                details: details,
                spender: DEFAULT_SPENDER,
                sigDeadline: DEFAULT_DEADLINE
            });

            assertEq(defaultPermitBatch(tokens.length).set(tokens, amounts, expirations, nonces), expected);
            assertEq(defaultPermitBatch(tokens.length).set(details), expected);
        }
    }

    function test_fuzz_set_permitBatch(uint8 length, uint8 index, IAllowanceTransfer.PermitDetails memory details)
        public
    {
        if (index >= length) {
            vm.expectRevert(StructBuilder.IndexOutOfBounds.selector);
            defaultPermitBatch(length).set(index, details);
        } else {
            assertEq(defaultPermitBatch(length).set(index, details).details[index], details);
        }
    }

    function test_fuzz_set_permitBatch(
        uint8 length,
        uint8 index,
        address token,
        uint256 amount,
        uint256 expiration,
        uint256 nonce
    ) public {
        bool shouldRevert;
        if (shouldRevert = token == address(0)) {
            vm.expectRevert(abi.encodeWithSelector(StructBuilder.InvalidParameter.selector, "token"));
        } else if (shouldRevert = amount > type(uint160).max) {
            vm.expectRevert(abi.encodeWithSelector(StructBuilder.InvalidParameter.selector, "amount"));
        } else if (shouldRevert = expiration > type(uint48).max) {
            vm.expectRevert(abi.encodeWithSelector(StructBuilder.InvalidParameter.selector, "expiration"));
        } else if (shouldRevert = nonce > type(uint48).max) {
            vm.expectRevert(abi.encodeWithSelector(StructBuilder.InvalidParameter.selector, "nonce"));
        } else if (shouldRevert = index >= length) {
            vm.expectRevert(StructBuilder.IndexOutOfBounds.selector);
        }

        IAllowanceTransfer.PermitBatch memory permit =
            defaultPermitBatch(length).set(index, token, amount, expiration, nonce);

        if (!shouldRevert) {
            assertEq(permit.details[index].token, token);
            assertEq(permit.details[index].amount, amount);
            assertEq(permit.details[index].expiration, expiration);
            assertEq(permit.details[index].nonce, nonce);
        }
    }

    function test_fuzz_add_permitBatch(IAllowanceTransfer.PermitDetails memory details) public pure {
        IAllowanceTransfer.PermitBatch memory permit = defaultPermitBatch(0).add(details);
        assertEq(permit.details.length, 1);
        assertEq(permit.details[0], details);
    }

    function test_fuzz_add_permitBatch(address token, uint256 amount, uint256 expiration, uint256 nonce) public {
        if (token == address(0)) {
            vm.expectRevert(abi.encodeWithSelector(StructBuilder.InvalidParameter.selector, "token"));
        } else if (amount > type(uint160).max) {
            vm.expectRevert(abi.encodeWithSelector(StructBuilder.InvalidParameter.selector, "amount"));
        } else if (expiration > type(uint48).max) {
            vm.expectRevert(abi.encodeWithSelector(StructBuilder.InvalidParameter.selector, "expiration"));
        } else if (nonce > type(uint48).max) {
            vm.expectRevert(abi.encodeWithSelector(StructBuilder.InvalidParameter.selector, "nonce"));
        }

        IAllowanceTransfer.PermitBatch memory permit = defaultPermitBatch(0).add(token, amount, expiration, nonce);
        assertEq(permit.details.length, 1);
        assertEq(permit.details[0].token, token);
        assertEq(permit.details[0].amount, amount);
        assertEq(permit.details[0].expiration, expiration);
        assertEq(permit.details[0].nonce, nonce);
    }

    function test_fuzz_add_permitBatch(IAllowanceTransfer.PermitDetails[] memory details) public pure {
        vm.assume(details.length != 0);

        IAllowanceTransfer.PermitBatch memory permit = defaultPermitBatch(0);
        for (uint256 i; i < details.length; ++i) {
            permit = permit.add(details[i]);
            assertEq(permit.details[i], details[i]);
        }
        assertEq(permit.details.length, details.length);
        assertEq(permit.details, details);
    }

    function test_fuzz_asPermitDetails(address token, uint256 amount, uint256 expiration, uint256 nonce) public {
        if (token == address(0)) {
            vm.expectRevert(abi.encodeWithSelector(StructBuilder.InvalidParameter.selector, "token"));
        } else if (amount > type(uint160).max) {
            vm.expectRevert(abi.encodeWithSelector(StructBuilder.InvalidParameter.selector, "amount"));
        } else if (expiration > type(uint48).max) {
            vm.expectRevert(abi.encodeWithSelector(StructBuilder.InvalidParameter.selector, "expiration"));
        } else if (nonce > type(uint48).max) {
            vm.expectRevert(abi.encodeWithSelector(StructBuilder.InvalidParameter.selector, "nonce"));
        }

        IAllowanceTransfer.PermitDetails memory expected = IAllowanceTransfer.PermitDetails({
            token: token,
            amount: uint160(amount),
            expiration: uint48(expiration),
            nonce: uint48(nonce)
        });

        assertEq(StructBuilder.asPermitDetails(token, amount, expiration, nonce), expected);
    }

    function test_fuzz_asPermitDetails(
        address[] memory tokens,
        uint256[] memory amounts,
        uint256[] memory expirations,
        uint256[] memory nonces
    ) public {
        bool shouldRevert;
        if (shouldRevert = tokens.length == 0) {
            vm.expectRevert(StructBuilder.EmptyArray.selector);
        } else if (
            shouldRevert = (
                tokens.length != amounts.length || tokens.length != expirations.length || tokens.length != nonces.length
            )
        ) {
            vm.expectRevert(StructBuilder.LengthMismatch.selector);
        } else if (shouldRevert = _checkZeroAddress(tokens)) {
            vm.expectRevert(abi.encodeWithSelector(StructBuilder.InvalidParameter.selector, "token"));
        } else if (shouldRevert = _checkOverflows(amounts, type(uint160).max)) {
            vm.expectRevert(abi.encodeWithSelector(StructBuilder.InvalidParameter.selector, "amount"));
        } else if (shouldRevert = _checkOverflows(expirations, type(uint48).max)) {
            vm.expectRevert(abi.encodeWithSelector(StructBuilder.InvalidParameter.selector, "expiration"));
        } else if (shouldRevert = _checkOverflows(nonces, type(uint48).max)) {
            vm.expectRevert(abi.encodeWithSelector(StructBuilder.InvalidParameter.selector, "nonce"));
        }

        IAllowanceTransfer.PermitDetails[] memory details =
            StructBuilder.asPermitDetails(tokens, amounts, expirations, nonces);

        if (!shouldRevert) {
            (address[] memory _tokens, uint160[] memory _amounts, uint48[] memory _expirations, uint48[] memory _nonces)
            = ArrayHelpers.destructure(details);

            assertEq(tokens, _tokens);
            assertEq(amounts, _cast(_amounts));
            assertEq(expirations, _cast(_expirations));
            assertEq(nonces, _cast(_nonces));
        }
    }

    // PermitTransferFrom

    function test_init_transferSingle() public view {
        uint256 nonce = 180;
        uint256 deadline = block.timestamp + 5 minutes;

        ISignatureTransfer.PermitTransferFrom memory permit = StructBuilder.init(nonce, deadline);
        assertEq(permit.nonce, nonce);
        assertEq(permit.deadline, deadline);
    }

    function test_validate_transferSingle() public {
        ISignatureTransfer.TokenPermissions memory permitted =
            ISignatureTransfer.TokenPermissions({token: WETH_ADDRESS, amount: 10 ether});

        vm.expectRevert(abi.encodeWithSelector(StructBuilder.MissingRequiredField.selector, "deadline"));
        StructBuilder.init(DEFAULT_NONCE, 0).set(permitted).validate();

        vm.expectRevert(abi.encodeWithSelector(StructBuilder.MissingRequiredField.selector, "permitted"));
        address token = permitted.token;
        permitted.token = address(0);
        defaultPermitTransfer().set(permitted).validate();
        permitted.token = token;

        ISignatureTransfer.PermitTransferFrom memory expected = ISignatureTransfer.PermitTransferFrom({
            permitted: permitted,
            nonce: DEFAULT_NONCE,
            deadline: DEFAULT_DEADLINE
        });

        assertEq(defaultPermitTransfer().set(permitted).validate(), expected);
    }

    function test_set_transferSingle() public pure {
        address token = WETH_ADDRESS;
        uint256 amount = 10 ether;

        ISignatureTransfer.TokenPermissions memory permitted =
            ISignatureTransfer.TokenPermissions({token: token, amount: amount});

        ISignatureTransfer.PermitTransferFrom memory expected = ISignatureTransfer.PermitTransferFrom({
            permitted: permitted,
            nonce: DEFAULT_NONCE,
            deadline: DEFAULT_DEADLINE
        });

        assertEq(defaultPermitTransfer().set(token, amount), expected);
        assertEq(defaultPermitTransfer().set(permitted), expected);
    }

    function test_fuzz_set_transferSingle(ISignatureTransfer.TokenPermissions calldata permitted) public pure {
        ISignatureTransfer.PermitTransferFrom memory expected = ISignatureTransfer.PermitTransferFrom({
            permitted: permitted,
            nonce: DEFAULT_NONCE,
            deadline: DEFAULT_DEADLINE
        });

        assertEq(defaultPermitTransfer().set(permitted), expected);
    }

    function test_fuzz_set_transferSingle(address token, uint256 amount) public {
        ISignatureTransfer.PermitTransferFrom memory expected = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({token: token, amount: amount}),
            nonce: DEFAULT_NONCE,
            deadline: DEFAULT_DEADLINE
        });

        if (token == address(0)) {
            vm.expectRevert(abi.encodeWithSelector(StructBuilder.InvalidParameter.selector, "token"));
        }
        assertEq(defaultPermitTransfer().set(token, amount), expected);
    }

    // PermitBatchTransferFrom

    function test_init_transferBatch() public view {
        uint256 nonce = 180;
        uint256 deadline = block.timestamp + 5 minutes;
        uint256 capacity = 5;

        ISignatureTransfer.PermitBatchTransferFrom memory permit = StructBuilder.init(nonce, deadline, capacity);
        assertEq(permit.nonce, nonce);
        assertEq(permit.deadline, deadline);
        assertEq(permit.permitted.length, capacity);
    }

    function test_validate_transferBatch() public {
        ISignatureTransfer.TokenPermissions[] memory permitted = new ISignatureTransfer.TokenPermissions[](5);
        permitted[0] = ISignatureTransfer.TokenPermissions({token: WETH_ADDRESS, amount: 50 ether});
        permitted[1] = ISignatureTransfer.TokenPermissions({token: WBTC_ADDRESS, amount: 1e8});
        permitted[2] = ISignatureTransfer.TokenPermissions({token: DAI_ADDRESS, amount: 100000 ether});
        permitted[3] = ISignatureTransfer.TokenPermissions({token: USDC_ADDRESS, amount: 100000e6});
        permitted[4] = ISignatureTransfer.TokenPermissions({token: USDT_ADDRESS, amount: 100000e6});

        vm.expectRevert(abi.encodeWithSelector(StructBuilder.MissingRequiredField.selector, "deadline"));
        StructBuilder.init(DEFAULT_NONCE, 0, permitted.length).set(permitted).validate();

        ISignatureTransfer.PermitBatchTransferFrom memory expected = ISignatureTransfer.PermitBatchTransferFrom({
            permitted: permitted,
            nonce: DEFAULT_NONCE,
            deadline: DEFAULT_DEADLINE
        });

        ISignatureTransfer.PermitBatchTransferFrom memory permit = defaultPermitBatchTransfer(permitted.length);
        assertEq(permit.set(permitted).validate(), expected);

        for (uint256 i; i < permitted.length; ++i) {
            vm.expectRevert(abi.encodeWithSelector(StructBuilder.MissingRequiredField.selector, "permitted"));
            address token = permitted[i].token;
            permitted[i].token = address(0);
            permit.set(permitted).validate();
            permitted[i].token = token;
        }
    }

    function test_set_transferBatch() public pure {
        uint256 length = 5;
        address[] memory tokens = ArrayHelpers.populate(WETH_ADDRESS, length);
        uint256[] memory amounts = ArrayHelpers.populate(50 ether, length);

        ISignatureTransfer.TokenPermissions[] memory permitted = StructBuilder.asTokenPermissions(tokens, amounts);

        ISignatureTransfer.PermitBatchTransferFrom memory expected = ISignatureTransfer.PermitBatchTransferFrom({
            permitted: permitted,
            nonce: DEFAULT_NONCE,
            deadline: DEFAULT_DEADLINE
        });

        assertEq(defaultPermitBatchTransfer(length).set(tokens, amounts), expected);
        assertEq(defaultPermitBatchTransfer(length).set(permitted), expected);
    }

    function test_fuzz_set_transferBatch(ISignatureTransfer.TokenPermissions[] memory permitted) public {
        if (permitted.length == 0) {
            vm.expectRevert(StructBuilder.EmptyArray.selector);
            defaultPermitBatchTransfer(permitted.length).set(permitted);
            return;
        }

        ISignatureTransfer.PermitBatchTransferFrom memory expected = ISignatureTransfer.PermitBatchTransferFrom({
            permitted: permitted,
            nonce: DEFAULT_NONCE,
            deadline: DEFAULT_DEADLINE
        });

        assertEq(defaultPermitBatchTransfer(permitted.length).set(permitted), expected);

        (address[] memory tokens, uint256[] memory amounts) = ArrayHelpers.destructure(permitted);

        if (_checkZeroAddress(tokens)) {
            vm.expectRevert(abi.encodeWithSelector(StructBuilder.InvalidParameter.selector, "token"));
        }

        assertEq(defaultPermitBatchTransfer(permitted.length).set(tokens, amounts), expected);
    }

    function test_fuzz_set_transferBatch(address[] memory tokens, uint256[] memory amounts) public {
        if (tokens.length == 0) {
            vm.expectRevert(StructBuilder.EmptyArray.selector);
            defaultPermitBatchTransfer(tokens.length).set(tokens, amounts);
        } else if (tokens.length != amounts.length) {
            vm.expectRevert(StructBuilder.LengthMismatch.selector);
            defaultPermitBatchTransfer(tokens.length).set(tokens, amounts);
        } else if (_checkZeroAddress(tokens)) {
            vm.expectRevert(abi.encodeWithSelector(StructBuilder.InvalidParameter.selector, "token"));
            defaultPermitBatchTransfer(tokens.length).set(tokens, amounts);
        } else {
            ISignatureTransfer.TokenPermissions[] memory permitted = StructBuilder.asTokenPermissions(tokens, amounts);

            ISignatureTransfer.PermitBatchTransferFrom memory expected = ISignatureTransfer.PermitBatchTransferFrom({
                permitted: permitted,
                nonce: DEFAULT_NONCE,
                deadline: DEFAULT_DEADLINE
            });

            assertEq(defaultPermitBatchTransfer(tokens.length).set(tokens, amounts), expected);
            assertEq(defaultPermitBatchTransfer(tokens.length).set(permitted), expected);
        }
    }

    function test_fuzz_set_transferBatch(
        uint8 length,
        uint8 index,
        ISignatureTransfer.TokenPermissions memory permitted
    ) public {
        if (index >= length) {
            vm.expectRevert(StructBuilder.IndexOutOfBounds.selector);
            defaultPermitBatchTransfer(length).set(index, permitted);
        } else {
            assertEq(defaultPermitBatchTransfer(length).set(index, permitted).permitted[index], permitted);
        }
    }

    function test_fuzz_set_transferBatch(uint8 length, uint8 index, address token, uint256 amount) public {
        bool shouldRevert;
        if (shouldRevert = token == address(0)) {
            vm.expectRevert(abi.encodeWithSelector(StructBuilder.InvalidParameter.selector, "token"));
        } else if (shouldRevert = index >= length) {
            vm.expectRevert(StructBuilder.IndexOutOfBounds.selector);
        }

        ISignatureTransfer.PermitBatchTransferFrom memory permit =
            defaultPermitBatchTransfer(length).set(index, token, amount);

        if (!shouldRevert) {
            assertEq(permit.permitted[index].token, token);
            assertEq(permit.permitted[index].amount, amount);
        }
    }

    function test_fuzz_add_transferBatch(ISignatureTransfer.TokenPermissions[] memory permitted) public pure {
        vm.assume(permitted.length != 0);

        ISignatureTransfer.PermitBatchTransferFrom memory permit = defaultPermitBatchTransfer(0);
        for (uint256 i; i < permitted.length; ++i) {
            permit = permit.add(permitted[i]);
            assertEq(permit.permitted[i], permitted[i]);
        }
        assertEq(permit.permitted.length, permitted.length);
        assertEq(permit.permitted, permitted);
    }

    function test_fuzz_add_transferBatch(ISignatureTransfer.TokenPermissions memory permitted) public pure {
        ISignatureTransfer.PermitBatchTransferFrom memory permit = defaultPermitBatchTransfer(0).add(permitted);
        assertEq(permit.permitted.length, 1);
        assertEq(permit.permitted[0], permitted);
    }

    function test_fuzz_add_transferBatch(address token, uint256 amount) public {
        if (token == address(0)) {
            vm.expectRevert(abi.encodeWithSelector(StructBuilder.InvalidParameter.selector, "token"));
        }

        ISignatureTransfer.PermitBatchTransferFrom memory permit = defaultPermitBatchTransfer(0).add(token, amount);
        assertEq(permit.permitted.length, 1);
        assertEq(permit.permitted[0].token, token);
        assertEq(permit.permitted[0].amount, amount);
    }

    function test_fuzz_asTokenPermissions(address token, uint256 amount) public {
        if (token == address(0)) {
            vm.expectRevert(abi.encodeWithSelector(StructBuilder.InvalidParameter.selector, "token"));
        }

        ISignatureTransfer.TokenPermissions memory expected =
            ISignatureTransfer.TokenPermissions({token: token, amount: amount});

        assertEq(StructBuilder.asTokenPermissions(token, amount), expected);
    }

    function test_fuzz_asTokenPermissions(address[] memory tokens, uint256[] memory amounts) public {
        bool shouldRevert;
        if (shouldRevert = tokens.length == 0) {
            vm.expectRevert(StructBuilder.EmptyArray.selector);
        } else if (shouldRevert = tokens.length != amounts.length) {
            vm.expectRevert(StructBuilder.LengthMismatch.selector);
        } else if (shouldRevert = _checkZeroAddress(tokens)) {
            vm.expectRevert(abi.encodeWithSelector(StructBuilder.InvalidParameter.selector, "token"));
        }

        ISignatureTransfer.TokenPermissions[] memory permitted = StructBuilder.asTokenPermissions(tokens, amounts);

        if (!shouldRevert) {
            (address[] memory _tokens, uint256[] memory _amounts) = ArrayHelpers.destructure(permitted);
            assertEq(tokens, _tokens);
            assertEq(amounts, _amounts);
        }
    }

    function defaultPermitSingle() internal pure returns (IAllowanceTransfer.PermitSingle memory) {
        return StructBuilder.init(DEFAULT_SPENDER, DEFAULT_DEADLINE);
    }

    function defaultPermitBatch(uint256 capacity) internal pure returns (IAllowanceTransfer.PermitBatch memory) {
        return StructBuilder.init(DEFAULT_SPENDER, DEFAULT_DEADLINE, capacity);
    }

    function defaultPermitTransfer() internal pure returns (ISignatureTransfer.PermitTransferFrom memory) {
        return StructBuilder.init(DEFAULT_NONCE, DEFAULT_DEADLINE);
    }

    function defaultPermitBatchTransfer(uint256 capacity)
        internal
        pure
        returns (ISignatureTransfer.PermitBatchTransferFrom memory)
    {
        return StructBuilder.init(DEFAULT_NONCE, DEFAULT_DEADLINE, capacity);
    }

    function assertEq(IAllowanceTransfer.PermitSingle memory x, IAllowanceTransfer.PermitSingle memory y)
        internal
        pure
    {
        assertEq(abi.encode(x), abi.encode(y));
    }

    function assertEq(IAllowanceTransfer.PermitBatch memory x, IAllowanceTransfer.PermitBatch memory y) internal pure {
        assertEq(abi.encode(x), abi.encode(y));
    }

    function assertEq(IAllowanceTransfer.PermitDetails memory x, IAllowanceTransfer.PermitDetails memory y)
        internal
        pure
    {
        assertEq(abi.encode(x), abi.encode(y));
    }

    function assertEq(IAllowanceTransfer.PermitDetails[] memory x, IAllowanceTransfer.PermitDetails[] memory y)
        internal
        pure
    {
        assertEq(abi.encode(x), abi.encode(y));
    }

    function assertEq(ISignatureTransfer.PermitTransferFrom memory x, ISignatureTransfer.PermitTransferFrom memory y)
        internal
        pure
    {
        assertEq(abi.encode(x), abi.encode(y));
    }

    function assertEq(
        ISignatureTransfer.PermitBatchTransferFrom memory x,
        ISignatureTransfer.PermitBatchTransferFrom memory y
    ) internal pure {
        assertEq(abi.encode(x), abi.encode(y));
    }

    function assertEq(ISignatureTransfer.TokenPermissions memory x, ISignatureTransfer.TokenPermissions memory y)
        internal
        pure
    {
        assertEq(abi.encode(x), abi.encode(y));
    }

    function assertEq(ISignatureTransfer.TokenPermissions[] memory x, ISignatureTransfer.TokenPermissions[] memory y)
        internal
        pure
    {
        assertEq(abi.encode(x), abi.encode(y));
    }

    function assertEq(
        ISignatureTransfer.SignatureTransferDetails memory x,
        ISignatureTransfer.SignatureTransferDetails memory y
    ) internal pure {
        assertEq(abi.encode(x), abi.encode(y));
    }

    function assertEq(
        ISignatureTransfer.SignatureTransferDetails[] memory x,
        ISignatureTransfer.SignatureTransferDetails[] memory y
    ) internal pure {
        assertEq(abi.encode(x), abi.encode(y));
    }

    function _checkZeroAddress(address[] memory array) private pure returns (bool) {
        for (uint256 i; i < array.length; ++i) {
            if (array[i] == address(0)) return true;
        }
        return false;
    }

    function _checkOverflows(uint256[] memory array, uint256 limit) private pure returns (bool) {
        for (uint256 i; i < array.length; ++i) {
            if (array[i] > limit) return true;
        }
        return false;
    }

    function _cast(uint160[] memory input) private pure returns (uint256[] memory output) {
        assembly ("memory-safe") {
            output := input
        }
    }

    function _cast(uint48[] memory input) private pure returns (uint256[] memory output) {
        assembly ("memory-safe") {
            output := input
        }
    }
}
