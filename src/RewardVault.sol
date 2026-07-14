// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract RewardVault is
    Initializable,
    AccessControlUpgradeable,
    UUPSUpgradeable,
    EIP712Upgradeable
{
    using SafeERC20 for IERC20;
    using ECDSA for bytes32;

    bytes32 public constant SIGNER_ROLE = keccak256("SIGNER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    IERC20 public token;

        // user => nonce
    mapping(address => uint256) public userNonces;

    error InputAddressCantBeZero();

    // state-переменные (токен, nonce-mapping и т.д.) — Слой 2

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(bytes memory _initData) external initializer {
        __AccessControl_init();
        __UUPSUpgradeable_init();
        __EIP712_init("RewardVault", "1");

        (address _admin, address _signer, address _upgrader, address _token) =
            abi.decode(_initData, (address, address, address, address));
        if (_admin == address(0) || _signer == address(0) || _upgrader == address(0) || _token == address(0)) revert InputAddressCantBeZero();

        _grantRole(SIGNER_ROLE, _signer);
        _grantRole(UPGRADER_ROLE, _upgrader);
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);

        token = IERC20(_token);
    }

    function _authorizeUpgrade(address newImplementation)
        internal
        override
        onlyRole(UPGRADER_ROLE)
    {}











    function getInitData(
        address _admin,
        address _signer,
        address _upgrader,
        address _token) external pure returns (bytes memory){
        return abi.encode(_admin, _signer, _upgrader, _token);
    }
}
