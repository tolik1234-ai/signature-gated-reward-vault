// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

import {RewardVault} from "../../src/RewardVault.sol";

contract RewardVaultV2 is RewardVault {
    function version() external pure returns (string memory) {
        return "v2";
    }
}
