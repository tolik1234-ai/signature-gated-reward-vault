// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {RewardVault} from "../src/RewardVault.sol";
import {MockERC20} from "./mocks/MockERC20.sol";
import {RewardVaultV2} from "./mocks/RewardVaultV2.sol";

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

        vm.warp(2 hours);
        vm.expectPartialRevert(RewardVault.DeadlineWasReached.selector);
        vault.claim(req, signature);
    }

    function test_RevertWhen_NonceMismatch() public {
        RewardVault.ClaimRequest memory req = RewardVault.ClaimRequest({
            account: makeAddr("user"), amount: 10 * 10 ** 18, nonce: 1, deadline: block.timestamp + 1 hours
        });
        bytes memory signature = _signClaim(req, signerPrivateKey);

        vm.expectRevert(abi.encodeWithSelector(RewardVault.NoncesInStorageAndTransactionWasMismatch.selector, 1, 0));
        vault.claim(req, signature);
    }

    function test_RevertWhen_SignerLacksRole() public {
        RewardVault.ClaimRequest memory req = RewardVault.ClaimRequest({
            account: makeAddr("user"), amount: 10 * 10 ** 18, nonce: 0, deadline: block.timestamp + 1 hours
        });
        bytes memory signature = _signClaim(req, invalidPrivateKey);

        vm.expectRevert(abi.encodeWithSelector(RewardVault.SignerHasNotSignerRole.selector, vm.addr(invalidPrivateKey)));
        vault.claim(req, signature);
    }

    function test_RevertWhen_InsufficientVaultBalance() public {
        RewardVault.ClaimRequest memory req = RewardVault.ClaimRequest({
            account: makeAddr("user"), amount: 1000 * 10 ** 18 + 1, nonce: 0, deadline: block.timestamp + 1 hours
        });
        bytes memory signature = _signClaim(req, signerPrivateKey);

        vm.expectRevert(RewardVault.NotEnoughTokenInContract.selector);
        vault.claim(req, signature);
    }

    function test_RevertWhen_SignatureReplayed() public {
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
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        vault.initialize(admin, signer, upgrader, address(token));
    }

    function test_RevertWhen_ZeroAddressInInitialize() public {
        RewardVault newImpl = new RewardVault();
        bytes memory badInitData = abi.encodeCall(RewardVault.initialize, (admin, signer, upgrader, address(0)));
        vm.expectRevert(RewardVault.InputAddressCantBeZero.selector);
        new ERC1967Proxy(address(newImpl), badInitData);
    }

    function test_RevertWhen_NonUpgraderCallsUpgrade() public {
        address attacker = makeAddr("attacker");
        bytes32 upgraderRole = vault.UPGRADER_ROLE();

        vm.prank(attacker);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, attacker, upgraderRole)
        );
        vault.upgradeToAndCall(address(0xdead), "");
    }

    function test_UpgradeByUpgraderSucceedsAndPreservesState() public {
        RewardVaultV2 newImpl = new RewardVaultV2();

        vm.prank(upgrader);
        vault.upgradeToAndCall(address(newImpl), "");

        RewardVaultV2 vaultV2 = RewardVaultV2(address(vault));

        assertEq(vaultV2.version(), "v2");

        assertTrue(vault.hasRole(vault.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(vault.hasRole(vault.SIGNER_ROLE(), signer));
        assertTrue(vault.hasRole(vault.UPGRADER_ROLE(), upgrader));

        assertEq(address(vaultV2.token()), address(token));
    }

    function test_ClaimStillWorksAfterUpgrade() public {
        RewardVault.ClaimRequest memory req = RewardVault.ClaimRequest({
            account: makeAddr("user"), amount: 10 * 10 ** 18, nonce: 0, deadline: block.timestamp + 1 hours
        });
        bytes memory signature = _signClaim(req, signerPrivateKey);
        vault.claim(req, signature);

        RewardVaultV2 newImpl = new RewardVaultV2();
        vm.prank(upgrader);
        vault.upgradeToAndCall(address(newImpl), "");

        RewardVault.ClaimRequest memory req2 = RewardVault.ClaimRequest({
            account: makeAddr("user"), amount: 10 * 10 ** 18, nonce: 1, deadline: block.timestamp + 1 hours
        });
        bytes memory signature2 = _signClaim(req2, signerPrivateKey);

        vault.claim(req2, signature2);

        assertEq(vault.userNonces(makeAddr("user")), 2);
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
