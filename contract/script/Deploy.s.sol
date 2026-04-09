// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../src/TappRegistry.sol";
import "../src/proxy/UpgradeableBeacon.sol";
import "../src/proxy/BeaconProxy.sol";

/// @notice Deploy TappRegistry using the BeaconProxy + UpgradeableBeacon pattern.
///
///         Required env vars:
///           MIN_STAKE_AMOUNT  — minimum stake per node, in wei
///           LOCK_PERIOD       — lock period in seconds after removeNode
///
///         Run:
///           forge script script/Deploy.s.sol \
///             --rpc-url $RPC_URL \
///             --broadcast \
///             --private-key $PRIVATE_KEY
contract DeployTappRegistry is Script {

    function run() external {
        uint256 minStake   = vm.envUint("MIN_STAKE_AMOUNT");
        uint256 lockPeriod = vm.envUint("LOCK_PERIOD");

        vm.startBroadcast();

        // 1. Deploy implementation (constructor locks it against direct initialize)
        TappRegistry impl = new TappRegistry();
        console.log("Implementation:", address(impl));

        // 2. Deploy UpgradeableBeacon pointing at implementation
        UpgradeableBeacon beacon = new UpgradeableBeacon(address(impl), msg.sender);
        console.log("Beacon:        ", address(beacon));

        // 3. Encode initializer and deploy BeaconProxy
        bytes memory initData = abi.encodeWithSignature(
            "initialize(uint256,uint256)",
            minStake,
            lockPeriod
        );
        BeaconProxy proxy = new BeaconProxy(address(beacon), initData);
        console.log("Proxy (stable):", address(proxy));

        vm.stopBroadcast();

        console.log("\nMin stake (wei):", minStake);
        console.log("Lock period (s):", lockPeriod);
        console.log("\nSet in config:  TAPP_REGISTRY_CONTRACT=", address(proxy));
    }
}
