// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract RewardVault is Initializable, AccessControlUpgradeable, UUPSUpgradeable, EIP712Upgradeable {
    using SafeERC20 for IERC20;
    using ECDSA for bytes32;

    bytes32 public constant SIGNER_ROLE = keccak256("SIGNER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    bytes32 public constant CLAIM_REQUEST_TYPEHASH =
        keccak256("ClaimRequest(address account,uint256 amount,uint256 nonce,uint256 deadline)");

    struct ClaimRequest {
        address account;
        uint256 amount;
        uint256 nonce;
        uint256 deadline;
    }

    IERC20 public token;

    // user => nonce
    mapping(address => uint256) public userNonces;

    error InputAddressCantBeZero();
    error DeadlineWasReached(uint256 _deadline, uint256 _currentTime);
    error NoncesInStorageAndTransactionWasMismatch(uint256 trNonce, uint256 stNonce);
    error SignerHasNotSignerRole(address _signer);
    error NotEnoughTokenInContract();

    event TokenWasClaimed(address user, uint256 amount, uint256 timestamp);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

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

    function claim(ClaimRequest calldata req, bytes calldata signature) external {
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

    function _authorizeUpgrade(address newImplementation) internal override onlyRole(UPGRADER_ROLE) {}
}
