// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {TappRegistry} from "../src/TappRegistry.sol";
import {UpgradeableBeacon} from "../src/proxy/UpgradeableBeacon.sol";
import {BeaconProxy} from "../src/proxy/BeaconProxy.sol";

contract TappRegistryTest is Test {
    TappRegistry public registry;

    uint256 constant MIN_STAKE   = 1 ether;
    uint256 constant LOCK_PERIOD = 7 days;

    address owner  = makeAddr("owner");
    address user   = makeAddr("user");
    address hacker = makeAddr("hacker");
    address node1  = makeAddr("node1");
    address node2  = makeAddr("node2");

    string  constant APP_ID       = "my-app";
    bytes   constant COMPOSE_HASH = hex"aabb";
    bytes   constant VOLUMES_HASH = hex"ccdd";
    string  constant TEE_URL_1    = "https://node1.example.com";
    string  constant TEE_URL_2    = "https://node2.example.com";

    bytes[] imageHashes;

    function setUp() public {
        TappRegistry impl = new TappRegistry();
        UpgradeableBeacon beacon = new UpgradeableBeacon(address(impl), address(this));
        bytes memory initData = abi.encodeCall(TappRegistry.initialize, (MIN_STAKE, LOCK_PERIOD));
        BeaconProxy proxy = new BeaconProxy(address(beacon), initData);
        registry = TappRegistry(payable(address(proxy)));

        vm.deal(owner,  10 ether);
        vm.deal(user,   10 ether);
        vm.deal(hacker, 10 ether);

        imageHashes.push(hex"1111");
        imageHashes.push(hex"2222");
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    function _register() internal {
        vm.prank(owner);
        registry.registerApp{value: MIN_STAKE}(
            APP_ID, COMPOSE_HASH, VOLUMES_HASH, imageHashes, node1, TEE_URL_1
        );
    }

    function _registerTwo() internal {
        _register();
        vm.prank(owner);
        registry.addNode{value: MIN_STAKE}(APP_ID, node2, TEE_URL_2);
    }

    // ─── registerApp ──────────────────────────────────────────────────────────

    function test_RegisterApp_StoresAppInfo() public {
        _register();
        TappRegistry.AppInfo memory info = registry.getAppInfo(APP_ID);
        assertEq(info.owner,       owner);
        assertEq(info.composeHash, COMPOSE_HASH);
        assertEq(info.volumesHash, VOLUMES_HASH);
        assertGt(info.registeredAt, 0);
    }

    function test_RegisterApp_AddsFirstNode() public {
        _register();
        TappRegistry.NodeInfo memory node = registry.getNode(APP_ID, node1);
        assertEq(node.teeUrl,      TEE_URL_1);
        assertEq(node.stakeAmount, MIN_STAKE);
        assertGt(node.addedAt,     0);

        address[] memory list = registry.getNodeList(APP_ID);
        assertEq(list.length, 1);
        assertEq(list[0], node1);
    }

    function test_RegisterApp_Revert_AlreadyExists() public {
        _register();
        vm.expectRevert("app already exists");
        vm.prank(owner);
        registry.registerApp{value: MIN_STAKE}(
            APP_ID, COMPOSE_HASH, VOLUMES_HASH, imageHashes, node1, TEE_URL_1
        );
    }

    function test_RegisterApp_Revert_InsufficientStake() public {
        vm.expectRevert("insufficient stake");
        vm.prank(owner);
        registry.registerApp{value: 0.5 ether}(
            APP_ID, COMPOSE_HASH, VOLUMES_HASH, imageHashes, node1, TEE_URL_1
        );
    }

    // ─── updateApp ────────────────────────────────────────────────────────────

    function test_UpdateApp_UpdatesHashes() public {
        _register();
        bytes memory newCompose = hex"ffff";
        vm.prank(owner);
        registry.updateApp(APP_ID, newCompose, VOLUMES_HASH, imageHashes);
        assertEq(registry.getAppInfo(APP_ID).composeHash, newCompose);
    }

    function test_UpdateApp_IncrementsAckVersion() public {
        _register();
        assertEq(registry.getAckVersion(APP_ID), 1);
        vm.prank(owner);
        registry.updateApp(APP_ID, COMPOSE_HASH, VOLUMES_HASH, imageHashes);
        assertEq(registry.getAckVersion(APP_ID), 2);
    }

    function test_UpdateApp_InvalidatesPriorAck() public {
        _register();
        vm.prank(user);
        registry.acknowledgeApp(APP_ID);
        assertTrue(registry.isAcknowledged(user, APP_ID));

        vm.prank(owner);
        registry.updateApp(APP_ID, hex"ffff", VOLUMES_HASH, imageHashes);
        assertFalse(registry.isAcknowledged(user, APP_ID));
    }

    function test_UpdateApp_Revert_NotOwner() public {
        _register();
        vm.expectRevert("not app owner");
        vm.prank(hacker);
        registry.updateApp(APP_ID, COMPOSE_HASH, VOLUMES_HASH, imageHashes);
    }

    // ─── addNode ──────────────────────────────────────────────────────────────

    function test_AddNode() public {
        _register();
        vm.prank(owner);
        registry.addNode{value: MIN_STAKE}(APP_ID, node2, TEE_URL_2);

        TappRegistry.NodeInfo memory node = registry.getNode(APP_ID, node2);
        assertEq(node.stakeAmount, MIN_STAKE);
        assertEq(node.teeUrl,      TEE_URL_2);

        address[] memory list = registry.getNodeList(APP_ID);
        assertEq(list.length, 2);
    }

    function test_AddNode_IncrementsAckVersion() public {
        _register();
        assertEq(registry.getAckVersion(APP_ID), 1);
        vm.prank(owner);
        registry.addNode{value: MIN_STAKE}(APP_ID, node2, TEE_URL_2);
        assertEq(registry.getAckVersion(APP_ID), 2);
    }

    function test_AddNode_InvalidatesPriorAck() public {
        _register();
        vm.prank(user);
        registry.acknowledgeApp(APP_ID);
        assertTrue(registry.isAcknowledged(user, APP_ID));

        vm.prank(owner);
        registry.addNode{value: MIN_STAKE}(APP_ID, node2, TEE_URL_2);
        assertFalse(registry.isAcknowledged(user, APP_ID));
    }

    function test_AddNode_Revert_NotOwner() public {
        _register();
        vm.expectRevert("not app owner");
        vm.prank(hacker);
        registry.addNode{value: MIN_STAKE}(APP_ID, node2, TEE_URL_2);
    }

    function test_AddNode_Revert_NodeAlreadyExists() public {
        _register();
        vm.expectRevert("node already exists");
        vm.prank(owner);
        registry.addNode{value: MIN_STAKE}(APP_ID, node1, TEE_URL_1);
    }

    function test_AddNode_Revert_InsufficientStake() public {
        _register();
        vm.expectRevert("insufficient stake");
        vm.prank(owner);
        registry.addNode{value: 0.1 ether}(APP_ID, node2, TEE_URL_2);
    }

    // ─── updateNode ───────────────────────────────────────────────────────────

    function test_UpdateNode_ReplacesSignerAndTeeUrl() public {
        _register();
        vm.prank(owner);
        registry.updateNode(APP_ID, node1, node2, TEE_URL_2);

        // old node gone
        assertEq(registry.getNode(APP_ID, node1).addedAt, 0);
        // new node present
        TappRegistry.NodeInfo memory n = registry.getNode(APP_ID, node2);
        assertEq(n.teeUrl,      TEE_URL_2);
        assertEq(n.stakeAmount, MIN_STAKE);

        address[] memory list = registry.getNodeList(APP_ID);
        assertEq(list.length, 1);
        assertEq(list[0], node2);
    }

    function test_UpdateNode_IncrementsAckVersion() public {
        _register();
        vm.prank(owner);
        registry.updateNode(APP_ID, node1, node2, TEE_URL_2);
        assertEq(registry.getAckVersion(APP_ID), 2);
    }

    function test_UpdateNode_InvalidatesPriorAck() public {
        _register();
        vm.prank(user);
        registry.acknowledgeApp(APP_ID);
        assertTrue(registry.isAcknowledged(user, APP_ID));

        vm.prank(owner);
        registry.updateNode(APP_ID, node1, node2, TEE_URL_2);
        assertFalse(registry.isAcknowledged(user, APP_ID));
    }

    function test_UpdateNode_Revert_OldNodeNotFound() public {
        _register();
        vm.expectRevert("old node not found");
        vm.prank(owner);
        registry.updateNode(APP_ID, node2, makeAddr("node3"), TEE_URL_2);
    }

    function test_UpdateNode_Revert_NewSignerAlreadyExists() public {
        _registerTwo();
        vm.expectRevert("new signer already exists");
        vm.prank(owner);
        registry.updateNode(APP_ID, node1, node2, TEE_URL_2);
    }

    function test_UpdateNode_Revert_NotOwner() public {
        _register();
        vm.expectRevert("not app owner");
        vm.prank(hacker);
        registry.updateNode(APP_ID, node1, node2, TEE_URL_2);
    }

    // ─── removeNode ───────────────────────────────────────────────────────────

    function test_RemoveNode_RemovesFromList() public {
        _registerTwo();
        vm.prank(owner);
        registry.removeNode(APP_ID, node1);

        address[] memory list = registry.getNodeList(APP_ID);
        assertEq(list.length, 1);
        assertEq(registry.getNode(APP_ID, node1).addedAt, 0);
    }

    function test_RemoveNode_LocksStakeInOwnerBalance() public {
        _register();
        vm.prank(owner);
        registry.removeNode(APP_ID, node1);

        TappRegistry.LockedEntry[] memory entries = registry.getLockedBalance(owner);
        assertEq(entries.length, 1);
        assertEq(entries[0].amount,   MIN_STAKE);
        assertEq(entries[0].unlockAt, block.timestamp + LOCK_PERIOD);
    }

    function test_RemoveNode_LastNode_UnregistersApp() public {
        _register();
        vm.prank(owner);
        registry.removeNode(APP_ID, node1);

        // app info cleared
        assertEq(registry.getAppInfo(APP_ID).owner, address(0));
        assertEq(registry.getNodeList(APP_ID).length, 0);
    }

    function test_RemoveNode_DoesNotInvalidateAck() public {
        _registerTwo();
        vm.prank(user);
        registry.acknowledgeApp(APP_ID);

        vm.prank(owner);
        registry.removeNode(APP_ID, node1);

        assertTrue(registry.isAcknowledged(user, APP_ID));
    }

    function test_RemoveNode_Revert_NotOwner() public {
        _register();
        vm.expectRevert("not app owner");
        vm.prank(hacker);
        registry.removeNode(APP_ID, node1);
    }

    function test_RemoveNode_Revert_NodeNotFound() public {
        _register();
        vm.expectRevert("node not found");
        vm.prank(owner);
        registry.removeNode(APP_ID, node2);
    }

    // ─── withdraw ─────────────────────────────────────────────────────────────

    function test_Withdraw_AfterLock() public {
        _register();
        vm.prank(owner);
        registry.removeNode(APP_ID, node1);

        vm.warp(block.timestamp + LOCK_PERIOD + 1);

        uint256 before = owner.balance;
        vm.prank(owner);
        registry.withdraw();
        assertEq(owner.balance - before, MIN_STAKE);

        // entry cleared
        assertEq(registry.getLockedBalance(owner).length, 0);
    }

    function test_Withdraw_MultipleEntries() public {
        _registerTwo();
        vm.prank(owner);
        registry.removeNode(APP_ID, node1);
        vm.prank(owner);
        registry.removeNode(APP_ID, node2);

        vm.warp(block.timestamp + LOCK_PERIOD + 1);

        uint256 before = owner.balance;
        vm.prank(owner);
        registry.withdraw();
        assertEq(owner.balance - before, 2 * MIN_STAKE);
    }

    function test_Withdraw_Revert_StillLocked() public {
        _register();
        vm.prank(owner);
        registry.removeNode(APP_ID, node1);

        vm.expectRevert("nothing to withdraw");
        vm.prank(owner);
        registry.withdraw();
    }

    function test_Withdraw_Revert_NothingToWithdraw() public {
        vm.expectRevert("nothing to withdraw");
        vm.prank(owner);
        registry.withdraw();
    }

    // ─── acknowledgeApp ───────────────────────────────────────────────────────

    function test_AcknowledgeApp() public {
        _register();
        vm.prank(user);
        registry.acknowledgeApp(APP_ID);
        assertTrue(registry.isAcknowledged(user, APP_ID));
        assertEq(registry.getAckCount(APP_ID), 1);
    }

    function test_AcknowledgeApp_MultipleUsers() public {
        _register();
        vm.prank(user);
        registry.acknowledgeApp(APP_ID);
        vm.prank(hacker);
        registry.acknowledgeApp(APP_ID);
        assertEq(registry.getAckCount(APP_ID), 2);
    }

    function test_AcknowledgeApp_ReAckAfterInvalidation() public {
        _register();
        vm.prank(user);
        registry.acknowledgeApp(APP_ID);
        assertEq(registry.getAckCount(APP_ID), 1);

        vm.prank(owner);
        registry.updateApp(APP_ID, hex"ffff", VOLUMES_HASH, imageHashes);
        assertFalse(registry.isAcknowledged(user, APP_ID));

        vm.prank(user);
        registry.acknowledgeApp(APP_ID);
        assertTrue(registry.isAcknowledged(user, APP_ID));
        assertEq(registry.getAckCount(APP_ID), 1);
    }

    function test_AcknowledgeApp_DuplicateIsNoop() public {
        _register();
        vm.prank(user);
        registry.acknowledgeApp(APP_ID);
        assertEq(registry.getAckCount(APP_ID), 1);

        // re-acking the same version must not revert and must not double-count
        vm.prank(user);
        registry.acknowledgeApp(APP_ID);
        assertEq(registry.getAckCount(APP_ID), 1);
        assertTrue(registry.isAcknowledged(user, APP_ID));
    }

    function test_AcknowledgeApp_Revert_AppNotFound() public {
        vm.expectRevert("app not found");
        vm.prank(user);
        registry.acknowledgeApp(APP_ID);
    }

    function test_AcknowledgeApps_BatchAcksAllListed() public {
        _register();
        string memory APP_ID_2 = "my-app-2";
        vm.prank(owner);
        registry.registerApp{value: MIN_STAKE}(
            APP_ID_2, COMPOSE_HASH, VOLUMES_HASH, imageHashes, node2, TEE_URL_2
        );

        string[] memory ids = new string[](2);
        ids[0] = APP_ID;
        ids[1] = APP_ID_2;
        vm.prank(user);
        registry.acknowledgeApps(ids);

        assertTrue(registry.isAcknowledged(user, APP_ID));
        assertTrue(registry.isAcknowledged(user, APP_ID_2));
        assertEq(registry.getAckCount(APP_ID), 1);
        assertEq(registry.getAckCount(APP_ID_2), 1);
    }

    function test_AcknowledgeApps_Revert_AnyMissingRevertsBatch() public {
        _register();

        string[] memory ids = new string[](2);
        ids[0] = APP_ID;
        ids[1] = "does-not-exist";
        vm.expectRevert("app not found");
        vm.prank(user);
        registry.acknowledgeApps(ids);

        // The whole batch must have reverted — even the valid entry stays un-acked.
        assertFalse(registry.isAcknowledged(user, APP_ID));
        assertEq(registry.getAckCount(APP_ID), 0);
    }

    function test_AcknowledgeApps_DuplicatesWithinBatchAreNoop() public {
        _register();

        string[] memory ids = new string[](3);
        ids[0] = APP_ID;
        ids[1] = APP_ID;
        ids[2] = APP_ID;
        vm.prank(user);
        registry.acknowledgeApps(ids);

        assertTrue(registry.isAcknowledged(user, APP_ID));
        assertEq(registry.getAckCount(APP_ID), 1);
    }

    function test_RevokeAcknowledgements_BatchRevokesAllListed() public {
        _register();
        string memory APP_ID_2 = "my-app-2";
        vm.prank(owner);
        registry.registerApp{value: MIN_STAKE}(
            APP_ID_2, COMPOSE_HASH, VOLUMES_HASH, imageHashes, node2, TEE_URL_2
        );

        string[] memory ids = new string[](2);
        ids[0] = APP_ID;
        ids[1] = APP_ID_2;
        vm.startPrank(user);
        registry.acknowledgeApps(ids);
        registry.revokeAcknowledgements(ids);
        vm.stopPrank();

        assertFalse(registry.isAcknowledged(user, APP_ID));
        assertFalse(registry.isAcknowledged(user, APP_ID_2));
        assertEq(registry.getAckCount(APP_ID), 0);
        assertEq(registry.getAckCount(APP_ID_2), 0);
    }

    function test_BatchAck_EmptyArrayIsNoop() public {
        _register();
        string[] memory empty = new string[](0);
        vm.startPrank(user);
        registry.acknowledgeApps(empty);
        registry.revokeAcknowledgements(empty);
        vm.stopPrank();
        assertFalse(registry.isAcknowledged(user, APP_ID));
        assertEq(registry.getAckCount(APP_ID), 0);
    }

    // ─── Admin ────────────────────────────────────────────────────────────────

    function test_SetMinStakeAmount() public {
        registry.setMinStakeAmount(2 ether);
        assertEq(registry.minStakeAmount(), 2 ether);
    }

    function test_SetMinStakeAmount_Revert_NotAdmin() public {
        vm.expectRevert("not admin");
        vm.prank(user);
        registry.setMinStakeAmount(2 ether);
    }

    function test_SetLockPeriod() public {
        registry.setLockPeriod(14 days);
        assertEq(registry.lockPeriod(), 14 days);
    }

    function test_TransferAdmin() public {
        registry.transferAdmin(user);
        assertEq(registry.admin(), user);

        vm.prank(user);
        registry.setMinStakeAmount(3 ether);

        vm.expectRevert("not admin");
        registry.setMinStakeAmount(4 ether);
    }

    function test_TransferAdmin_Revert_ZeroAddress() public {
        vm.expectRevert("zero address");
        registry.transferAdmin(address(0));
    }

    // ─── Upgrade ──────────────────────────────────────────────────────────────

    function test_Upgrade_PreservesState() public {
        _register();
        vm.prank(user);
        registry.acknowledgeApp(APP_ID);

        TappRegistry.AppInfo memory infoBefore = registry.getAppInfo(APP_ID);
        assertTrue(registry.isAcknowledged(user, APP_ID));

        TappRegistry newImpl = new TappRegistry();
        bytes32 beaconSlot = 0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50;
        address beaconAddr = address(uint160(uint256(vm.load(address(registry), beaconSlot))));
        UpgradeableBeacon(beaconAddr).upgradeTo(address(newImpl));

        TappRegistry.AppInfo memory infoAfter = registry.getAppInfo(APP_ID);
        assertEq(infoAfter.owner,       infoBefore.owner);
        assertEq(infoAfter.composeHash, infoBefore.composeHash);
        assertTrue(registry.isAcknowledged(user, APP_ID));
    }

    // ─── revokeAcknowledgement ────────────────────────────────────────────────

    function test_RevokeAcknowledgement_ClearsAck() public {
        _register();
        vm.prank(user);
        registry.acknowledgeApp(APP_ID);
        assertTrue(registry.isAcknowledged(user, APP_ID));
        assertEq(registry.getAckCount(APP_ID), 1);

        vm.prank(user);
        registry.revokeAcknowledgement(APP_ID);

        assertFalse(registry.isAcknowledged(user, APP_ID));
        assertEq(registry.getAckCount(APP_ID), 0);
    }

    function test_RevokeAcknowledgement_Noop_WhenNeverAcked() public {
        _register();
        vm.prank(user);
        registry.revokeAcknowledgement(APP_ID);   // must not revert, must not underflow ackCount
        assertEq(registry.getAckCount(APP_ID), 0);
    }

    function test_RevokeAcknowledgement_AllowsReAck() public {
        _register();
        vm.prank(user);
        registry.acknowledgeApp(APP_ID);
        vm.prank(user);
        registry.revokeAcknowledgement(APP_ID);

        vm.prank(user);
        registry.acknowledgeApp(APP_ID);
        assertTrue(registry.isAcknowledged(user, APP_ID));
        assertEq(registry.getAckCount(APP_ID), 1);
    }

    // ─── Invalidators ─────────────────────────────────────────────────────────

    function test_Invalidator_Authorize_Then_InvalidateAcks() public {
        _register();
        address sibling = makeAddr("sibling");

        vm.prank(owner);
        registry.authorizeInvalidator(APP_ID, sibling);
        assertTrue(registry.isAuthorizedInvalidator(APP_ID, sibling));

        vm.prank(user);
        registry.acknowledgeApp(APP_ID);
        assertTrue(registry.isAcknowledged(user, APP_ID));

        uint256 v0 = registry.getAckVersion(APP_ID);
        vm.prank(sibling);
        registry.invalidateAcks(APP_ID);
        assertEq(registry.getAckVersion(APP_ID), v0 + 1);
        assertFalse(registry.isAcknowledged(user, APP_ID));
    }

    function test_Invalidator_AuthorizeIdempotent() public {
        _register();
        address sibling = makeAddr("sibling");
        vm.prank(owner);
        registry.authorizeInvalidator(APP_ID, sibling);
        vm.prank(owner);
        registry.authorizeInvalidator(APP_ID, sibling);   // must not revert
        assertTrue(registry.isAuthorizedInvalidator(APP_ID, sibling));
    }

    function test_Invalidator_Revoke_ThenInvalidateAcks_Reverts() public {
        _register();
        address sibling = makeAddr("sibling");
        vm.prank(owner);
        registry.authorizeInvalidator(APP_ID, sibling);
        vm.prank(owner);
        registry.revokeInvalidator(APP_ID, sibling);

        assertFalse(registry.isAuthorizedInvalidator(APP_ID, sibling));
        vm.expectRevert("not authorized");
        vm.prank(sibling);
        registry.invalidateAcks(APP_ID);
    }

    function test_Invalidator_Authorize_Revert_NotOwner() public {
        _register();
        vm.expectRevert("not app owner");
        vm.prank(hacker);
        registry.authorizeInvalidator(APP_ID, makeAddr("sibling"));
    }

    function test_Invalidator_Authorize_Revert_ZeroAddress() public {
        _register();
        vm.expectRevert("zero invalidator");
        vm.prank(owner);
        registry.authorizeInvalidator(APP_ID, address(0));
    }

    function test_Invalidator_InvalidateAcks_Revert_NotAuthorized() public {
        _register();
        vm.expectRevert("not authorized");
        vm.prank(hacker);
        registry.invalidateAcks(APP_ID);
    }

    function test_Invalidator_InvalidateAcks_Revert_AppNotFound() public {
        vm.expectRevert("app not found");
        vm.prank(makeAddr("sibling"));
        registry.invalidateAcks("nonexistent");
    }

    // ─── Zero-address signer protection ───────────────────────────────────────

    function test_RegisterApp_Revert_ZeroSigner() public {
        vm.expectRevert("zero signer address");
        vm.prank(owner);
        registry.registerApp{value: MIN_STAKE}(
            APP_ID, COMPOSE_HASH, VOLUMES_HASH, imageHashes, address(0), TEE_URL_1
        );
    }

    function test_AddNode_Revert_ZeroSigner() public {
        _register();
        vm.expectRevert("zero signer address");
        vm.prank(owner);
        registry.addNode{value: MIN_STAKE}(APP_ID, address(0), TEE_URL_2);
    }

    function test_UpdateNode_Revert_ZeroNewSigner() public {
        _register();
        vm.expectRevert("zero signer address");
        vm.prank(owner);
        registry.updateNode(APP_ID, node1, address(0), TEE_URL_2);
    }

    // ─── updateNode same-signer URL update ────────────────────────────────────

    function test_UpdateNode_SameSigner_UpdatesUrlOnly() public {
        _register();
        string memory newUrl = "https://node1.new.example.com";
        vm.prank(owner);
        registry.updateNode(APP_ID, node1, node1, newUrl);

        TappRegistry.NodeInfo memory n = registry.getNode(APP_ID, node1);
        assertEq(n.teeUrl,      newUrl);
        assertEq(n.stakeAmount, MIN_STAKE);

        address[] memory list = registry.getNodeList(APP_ID);
        assertEq(list.length, 1);
        assertEq(list[0], node1);
    }

    function test_UpdateNode_SameSigner_BumpsAckVersion() public {
        _register();
        vm.prank(user);
        registry.acknowledgeApp(APP_ID);
        assertTrue(registry.isAcknowledged(user, APP_ID));

        vm.prank(owner);
        registry.updateNode(APP_ID, node1, node1, "https://changed");
        assertFalse(registry.isAcknowledged(user, APP_ID));
    }

    // ─── removeNode last-node event reports real version ─────────────────────

    function test_RemoveNode_LastNode_NodeUpdatedReportsBumpedVersion() public {
        _register();
        uint256 v0 = registry.getAckVersion(APP_ID);

        vm.recordLogs();
        vm.prank(owner);
        registry.removeNode(APP_ID, node1);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 sig = keccak256("NodeUpdated(string,address,address,uint256,uint256,uint256)");
        uint256 reported;
        bool found;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == sig) {
                (, , reported) = abi.decode(logs[i].data, (uint256, uint256, uint256));
                found = true;
                break;
            }
        }
        assertTrue(found, "NodeUpdated not emitted");
        assertEq(reported, v0 + 1);
        assertEq(registry.getAckVersion(APP_ID), v0 + 1);
    }

    // ─── Fuzz ─────────────────────────────────────────────────────────────────

    function test_Fuzz_StakeAmount(uint96 stake) public {
        vm.assume(stake >= MIN_STAKE);
        vm.deal(owner, stake);
        vm.prank(owner);
        registry.registerApp{value: stake}(
            APP_ID, COMPOSE_HASH, VOLUMES_HASH, imageHashes, node1, TEE_URL_1
        );
        assertEq(registry.getNode(APP_ID, node1).stakeAmount, stake);
    }

    function test_Fuzz_AckVersionMonotonicallyIncreases(uint8 updates) public {
        _register();
        uint256 prev = 0;
        for (uint256 i = 0; i < updates; i++) {
            vm.prank(owner);
            registry.updateApp(APP_ID, COMPOSE_HASH, VOLUMES_HASH, imageHashes);
            uint256 curr = registry.getAckVersion(APP_ID);
            assertGt(curr, prev);
            prev = curr;
        }
    }
}
