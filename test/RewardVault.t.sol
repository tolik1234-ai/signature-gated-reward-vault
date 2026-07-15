// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {RewardVault} from "../src/RewardVault.sol";
import {MockERC20} from "./mocks/MockERC20.sol";

contract RewardVaultTest is Test {
    bytes32 constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    RewardVault public vault;
    MockERC20 public token;

    address public admin = makeAddr("admin");
    address public upgrader = makeAddr("upgrader");

    uint256 public signerPrivateKey = 0xA11CE;
    address public signer;

    uint256 public invalidPrivateKey = 123;

    function setUp() public {
        signer = vm.addr(signerPrivateKey);

        token = new MockERC20();

        bytes memory initData = abi.encodeCall(RewardVault.initialize, (admin, signer, upgrader, address(token)));

        RewardVault rewardVault = new RewardVault();

        ERC1967Proxy proxy = new ERC1967Proxy(address(rewardVault), initData);
        vault = RewardVault(address(proxy));

        token.mint(address(vault), 1000 * 10 ** 18);
    }

    function test_SetUpAssignsRolesCorrectly() public view {
        assertTrue(vault.hasRole(vault.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(vault.hasRole(vault.SIGNER_ROLE(), signer));
        assertTrue(vault.hasRole(vault.UPGRADER_ROLE(), upgrader));
    }

    function test_ClaimTransfersReward() public {
        address user = makeAddr("user");
        uint256 amount = 100 * 10 ** 18;
        uint256 nonce = 0;
        uint256 deadline = block.timestamp + 1 hours;

        RewardVault.ClaimRequest memory req =
            RewardVault.ClaimRequest({account: user, amount: amount, nonce: nonce, deadline: deadline});

        // TODO 1: structHash = keccak256(abi.encode(
        bytes32 structHash =
            keccak256(abi.encode(vault.CLAIM_REQUEST_TYPEHASH(), req.account, req.amount, req.nonce, req.deadline));

        bytes32 domainSeparator = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("RewardVault")),
                keccak256(bytes("1")),
                block.chainid,
                address(vault)
            )
        );

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);

        bytes memory signature = abi.encodePacked(r, s, v);

        uint256 userBalanceBefore = token.balanceOf(req.account);
        uint256 vaultBalanceBefore = token.balanceOf(address(vault));

        vault.claim(req, signature);

        assertEq(token.balanceOf(req.account) - userBalanceBefore, req.amount);
        assertEq(vaultBalanceBefore - token.balanceOf(address(vault)), req.amount);
        assertEq(vault.userNonces(req.account), 1);
    }

    function test_RevertWhen_DeadlineExpired() public {
        RewardVault.ClaimRequest memory req = RewardVault.ClaimRequest({
            account: makeAddr("user"), amount: 10 * 10 ** 18, nonce: 0, deadline: block.timestamp + 1 hours
        });
        bytes memory signature = _signClaim(req, signerPrivateKey);

        // TODO: vm.warp — перемотать время так, чтобы req.deadline оказался в прошлом
        vm.warp(2 hours);
        // TODO: vm.expectRevert (какой вариант? аргументы есть — подумай, какой из способов выше подходит)
        vm.expectPartialRevert(RewardVault.DeadlineWasReached.selector);
        // TODO: vault.claim(req, signature)
        vault.claim(req, signature);
    }

    function test_RevertWhen_NonceMismatch() public {
        // TODO: собери req с заведомо неверным nonce, подпиши, ожидай NoncesInStorageAndTransactionWasMismatch
        RewardVault.ClaimRequest memory req = RewardVault.ClaimRequest({
            account: makeAddr("user"), amount: 10 * 10 ** 18, nonce: 1, deadline: block.timestamp + 1 hours
        });
        bytes memory signature = _signClaim(req, signerPrivateKey);

        vm.expectRevert(abi.encodeWithSelector(RewardVault.NoncesInStorageAndTransactionWasMismatch.selector, 1, 0));
        vault.claim(req, signature);
    }

    function test_RevertWhen_SignerLacksRole() public {
        // TODO: собери валидный req, подпиши ключом БЕЗ SIGNER_ROLE, ожидай SignerHasNotSignerRole
        RewardVault.ClaimRequest memory req = RewardVault.ClaimRequest({
            account: makeAddr("user"), amount: 10 * 10 ** 18, nonce: 0, deadline: block.timestamp + 1 hours
        });
        bytes memory signature = _signClaim(req, invalidPrivateKey);

        vm.expectRevert(abi.encodeWithSelector(RewardVault.SignerHasNotSignerRole.selector, vm.addr(invalidPrivateKey)));
        vault.claim(req, signature);
    }

    function test_RevertWhen_InsufficientVaultBalance() public {
        // TODO: собери req с amount больше баланса vault, ожидай NotEnoughTokenInContract
        RewardVault.ClaimRequest memory req = RewardVault.ClaimRequest({
            account: makeAddr("user"), amount: 1000 * 10 ** 18 + 1, nonce: 0, deadline: block.timestamp + 1 hours
        });
        bytes memory signature = _signClaim(req, signerPrivateKey);

        vm.expectRevert(RewardVault.NotEnoughTokenInContract.selector);
        vault.claim(req, signature);
    }

    function test_RevertWhen_SignatureReplayed() public {
        // TODO: сделай один успешный claim (как в happy path тесте)
        RewardVault.ClaimRequest memory req = RewardVault.ClaimRequest({
            account: makeAddr("user"), amount: 10 * 10 ** 18, nonce: 0, deadline: block.timestamp + 1 hours
        });
        bytes memory signature = _signClaim(req, signerPrivateKey);
        vault.claim(req, signature);
        // Повторяем vault.claim с теми же req и signature: nonce уже сдвинулся на 1,
        // а в req по-прежнему nonce = 0, поэтому сработает проверка nonce, а не подписи.
        vm.expectRevert(abi.encodeWithSelector(RewardVault.NoncesInStorageAndTransactionWasMismatch.selector, 0, 1));
        vault.claim(req, signature);
    }

    function test_RevertWhen_InitializeCalledTwice() public {
        // TODO: vault уже инициализирован в setUp — просто вызови vault.initialize(...) ещё раз
        //       с любыми валидными адресами, ожидай RewardVault.InvalidInitialization.selector
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        vault.initialize(admin, signer, upgrader, address(token));
    }

    function test_RevertWhen_ZeroAddressInInitialize() public {
        // Тут нельзя переиспользовать vault из setUp — он уже инициализирован.
        // Разверни НОВУЮ пару implementation + proxy (как в setUp), но с token = address(0).
        // TODO 1: RewardVault newImpl = new RewardVault();
        // TODO 2: bytes memory badInitData = abi.encodeCall(RewardVault.initialize, (admin, signer, upgrader, address(0)));
        // TODO 3: vm.expectRevert(RewardVault.InputAddressCantBeZero.selector);
        // TODO 4: new ERC1967Proxy(address(newImpl), badInitData);
        //         (сам вызов new и должен упасть — initialize реветит внутри delegatecall,
        //          а он выполняется прямо в конструкторе ERC1967Proxy)
    }

    function test_RevertWhen_NonUpgraderCallsUpgrade() public {
        address attacker = makeAddr("attacker");

        // TODO 1: vm.prank(attacker)
        // TODO 2: vm.expectRevert(abi.encodeWithSelector(
        //             IAccessControl.AccessControlUnauthorizedAccount.selector, attacker, vault.UPGRADER_ROLE()))
        //         (порядок вызова expectRevert/prank — подумай, что должно идти раньше)
        // TODO 3: vault.upgradeToAndCall(address(0xdead), "") — адрес неважен, до проверки реализации дело не дойдёт
    }

    function _signClaim(RewardVault.ClaimRequest memory req, uint256 privateKey)
        internal
        view
        returns (bytes memory signature)
    {
        bytes32 structHash =
            keccak256(abi.encode(vault.CLAIM_REQUEST_TYPEHASH(), req.account, req.amount, req.nonce, req.deadline));

        bytes32 domainSeparator = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("RewardVault")),
                keccak256(bytes("1")),
                block.chainid,
                address(vault)
            )
        );

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        signature = abi.encodePacked(r, s, v);
    }
}
