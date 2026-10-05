// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../src/TappRegistry.sol";
import "../src/proxy/UpgradeableBeacon.sol";

/// @notice Upgrade TappRegistry: deploy new implementation and point beacon at it.
///         Only for chains where the broadcasting key itself owns the beacon (local /
///         dev). On testnet and mainnet the owner is a wallet or the timelock: use
///         `go run ./cmd/upgrade/ --network <net>`, which deploys with any key and
///         prints the switch for the owner to sign.
///
///         Required env vars:
///           BEACON_ADDRESS  — UpgradeableBeacon address
///
///         Run:
///           forge script script/Upgrade.s.sol \
///             --rpc-url $RPC_URL \
///             --broadcast \
///             --private-key $PRIVATE_KEY
contract UpgradeTappRegistry is Script {

    function run() external {
        address beaconAddr = vm.envAddress("BEACON_ADDRESS");

        vm.startBroadcast();

        // 1. Deploy new implementation
        TappRegistry newImpl = new TappRegistry();
        console.log("New Implementation:", address(newImpl));

        // 2. Upgrade beacon to point at new impl
        UpgradeableBeacon beacon = UpgradeableBeacon(beaconAddr);
        beacon.upgradeTo(address(newImpl));
        console.log("Beacon upgraded:   ", beaconAddr);

        vm.stopBroadcast();
    }
}
