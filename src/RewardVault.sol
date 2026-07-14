// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title RewardVault
/// @notice Upgradeable reward vault: users claim tokens by presenting an EIP-712 signature
///         issued by an address holding SIGNER_ROLE.
/// @dev UUPS-upgradeable (see _authorizeUpgrade), role-based access via AccessControl, replay
///      protection via a per-user nonce and a deadline embedded in the signed data.
contract RewardVault is Initializable, AccessControlUpgradeable, UUPSUpgradeable, EIP712Upgradeable {
    using SafeERC20 for IERC20;
    using ECDSA for bytes32;

    /// @notice Role whose signatures are accepted as valid when calling claim.
    bytes32 public constant SIGNER_ROLE = keccak256("SIGNER_ROLE");

    /// @notice Role allowed to authorize contract upgrades.
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    /// @notice EIP-712 type hash ("shape fingerprint") for the ClaimRequest struct.
    /// @dev Must match the struct fields below exactly (order and types). The frontend must use
    ///      the identical type description when signing.
    bytes32 public constant CLAIM_REQUEST_TYPEHASH =
        keccak256("ClaimRequest(address account,uint256 amount,uint256 nonce,uint256 deadline)");

    /// @notice Data for a single reward claim — what gets signed off-chain.
    /// @dev Field order must match CLAIM_REQUEST_TYPEHASH.
    struct ClaimRequest {
        address account; // who the reward is for
        uint256 amount; // how many tokens
        uint256 nonce; // expected sequence number — prevents signature replay
        uint256 deadline; // unix timestamp after which the signature is no longer valid
    }

    /// @notice The token used to pay out rewards.
    IERC20 public token;

    /// @notice Next expected nonce for each address.
    mapping(address => uint256) public userNonces;

    /// @notice One of the addresses passed to initialize was the zero address.
    error InputAddressCantBeZero();

    /// @notice The signature's validity window has passed (block.timestamp exceeded req.deadline).
    error DeadlineWasReached(uint256 _deadline, uint256 _currentTime);

    /// @notice The nonce in the request does not match the one stored for this user.
    error NoncesInStorageAndTransactionWasMismatch(uint256 trNonce, uint256 stNonce);

    /// @notice The address recovered from the signature does not hold SIGNER_ROLE.
    error SignerHasNotSignerRole(address _signer);

    /// @notice The contract's token balance is insufficient to pay out the requested amount.
    error NotEnoughTokenInContract();

    /// @notice A reward was successfully paid out to a user.
    /// @param user recipient address
    /// @param amount amount paid out
    /// @param timestamp time of payout (block.timestamp)
    event TokenWasClaimed(address user, uint256 amount, uint256 timestamp);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the proxy: grants roles and sets the reward token.
    /// @dev Called exactly once, through ERC1967Proxy, right after deployment.
    /// @param _admin will receive DEFAULT_ADMIN_ROLE
    /// @param _signer will receive SIGNER_ROLE
    /// @param _upgrader will receive UPGRADER_ROLE
    /// @param _token address of the ERC20 token used to pay out rewards
    function initialize(address _admin, address _signer, address _upgrader, address _token) external initializer {
        __AccessControl_init();
        __EIP712_init("RewardVault", "1");

        if (_admin == address(0) || _signer == address(0) || _upgrader == address(0) || _token == address(0)) {
            revert InputAddressCantBeZero();
        }

        _grantRole(SIGNER_ROLE, _signer);
        _grantRole(UPGRADER_ROLE, _upgrader);
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);

        token = IERC20(_token);
    }

    /// @notice Claims a reward using a signature issued by an address holding SIGNER_ROLE.
    /// @dev Order: checks (deadline, nonce, balance) -> recover signer -> update nonce ->
    ///      transfer tokens. This follows Checks-Effects-Interactions.
    /// @param req the claim data (recipient, amount, nonce, deadline)
    /// @param signature EIP-712 signature over req, issued by a signer holding SIGNER_ROLE
    function claim(ClaimRequest calldata req, bytes calldata signature) external {
        /// forge-lint: disable-next-line(block-timestamp)
        if (req.deadline < block.timestamp) revert DeadlineWasReached(req.deadline, block.timestamp);
        if (req.nonce != userNonces[req.account]) {
            revert NoncesInStorageAndTransactionWasMismatch(req.nonce, userNonces[req.account]);
        }
        if (token.balanceOf(address(this)) < req.amount) revert NotEnoughTokenInContract();

        bytes32 structHash =
            keccak256(abi.encode(CLAIM_REQUEST_TYPEHASH, req.account, req.amount, req.nonce, req.deadline));

        bytes32 digest = _hashTypedDataV4(structHash);

        address signer = digest.recover(signature);
        if (!hasRole(SIGNER_ROLE, signer)) revert SignerHasNotSignerRole(signer);

        userNonces[req.account]++;

        token.safeTransfer(req.account, req.amount);

        emit TokenWasClaimed(req.account, req.amount, block.timestamp);
    }

    /// @notice Restricts upgrades to addresses holding UPGRADER_ROLE.
    /// @dev Empty body — all protection lives in the onlyRole modifier.
    function _authorizeUpgrade(address newImplementation) internal override onlyRole(UPGRADER_ROLE) {}
}
