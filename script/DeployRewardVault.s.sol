// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {RewardVault} from "../src/RewardVault.sol";

contract DeployRewardVault is Script {
    function run() external returns (address proxyAddress) {

        address admin = vm.envAddress("ADMIN_ADDRESS");
        address signer = vm.envAddress("SIGNER_ADDRESS");
        address upgrader = vm.envAddress("UPGRADER_ADDRESS");
        address token = vm.envAddress("TOKEN_ADDRESS");

        vm.startBroadcast();

        RewardVault rewardVault = new RewardVault();

        bytes memory initData = abi.encodeCall(RewardVault.initialize, (admin, signer, upgrader, token));

        ERC1967Proxy proxy = new ERC1967Proxy(address(rewardVault), initData);

        vm.stopBroadcast();

        return address(proxy);
    }
}
