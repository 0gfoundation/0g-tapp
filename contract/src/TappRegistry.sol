// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title  TappRegistry
/// @notice On-chain registry + stake manager for 0G Trusted Application Platform apps.
/// @dev    Upgradeable via BeaconProxy + UpgradeableBeacon pattern (ERC-1967).
///         Storage layout is fixed; use __gap for future fields.
///
///         App model
///         ---------
///         Every app is logically a cluster. A "single-node app" is a cluster with
///         one node. Shared code identity (composeHash, etc.) is at the app level;
///         per-node differentiation (signerAddress, teeUrl) lives in NodeInfo.
///         registerApp always adds the first node atomically.
///         When the last node is removed the app is automatically unregistered.
///
///         Staking
///         -------
///         Stake is per node. Each addNode / registerApp call requires
///         msg.value >= minStakeAmount. After removeNode, the stake is locked for
///         lockPeriod seconds in the owner's locked balance. The owner may call
///         withdraw() at any time to collect all matured entries.
///
///         Acknowledge
///         -----------
///         Each app has an ackVersion counter. Users acknowledge a specific version;
///         their acknowledgement becomes stale whenever the counter increments.
///         updateApp, updateNode, addNode, and replaceNode all increment the counter.
///         removeNode does not (shrinking the cluster does not increase trust risk).
///
///         Off-chain workflow:
///           1. Read app info + node list via getAppInfo / getNodeList.
///           2. Pick a node; fetch attestation evidence from its teeUrl.
///           3. Submit evidence to an RA service; confirm the returned signerAddress
///              and codeHash match on-chain values.
///           4. Call acknowledgeApp(appId) to record acknowledgement on-chain.
contract TappRegistry {

    // ─── Structs ──────────────────────────────────────────────────────────────

    struct AppInfo {
        /// @dev SHA384 of the normalised docker-compose yaml (shared by all nodes)
        bytes   composeHash;
        /// @dev SHA384 of all mount/volume files (shared by all nodes)
        bytes   volumesHash;
        /// @dev Docker image digests, one per service in compose order (shared)
        bytes[] imageHashes;
        address owner;
        uint256 registeredAt;
    }

    struct NodeInfo {
        /// @dev Node-specific URL to fetch TEE attestation evidence
        string  teeUrl;
        uint256 addedAt;
        uint256 stakeAmount;
    }

    struct LockedEntry {
        uint256 amount;
        /// @dev Timestamp after which the owner may withdraw this entry
        uint256 unlockAt;
    }

    // ─── State (storage layout — must not reorder or remove between upgrades) ─
    //
    // slot 0 (packed): _locked | _initialized
    bool private _locked;
    bool private _initialized;

    // slot 1
    mapping(string => AppInfo) private _apps;
    // slot 2 — appId => signerAddress => NodeInfo (addedAt==0 means node does not exist)
    mapping(string => mapping(address => NodeInfo)) private _nodes;
    // slot 3 — active node list; entries are removed when a node is removed
    mapping(string => address[]) private _nodeList;
    // slot 4 — owner => locked stake entries pending withdrawal
    mapping(address => LockedEntry[]) private _lockedBalance;
    // slot 5 — user => appId => ackVersion at time of acknowledgement (0 = never acked)
    mapping(address => mapping(string => uint256)) private _acks;
    // slot 6
    mapping(string => uint256) private _ackCounts;
    // slot 7 — incremented by registerApp / updateApp / addNode / updateNode / removeNode(last)
    mapping(string => uint256) private _appAckVersions;

    // slot 8
    address public admin;
    // slot 9 — minimum stake per node, in wei
    uint256 public minStakeAmount;
    // slot 10 — node stake lock period after removeNode, in seconds
    uint256 public lockPeriod;

    // slots 11–59: reserved for future upgrades
    uint256[49] private __gap;

    // ─── Events ───────────────────────────────────────────────────────────────

    event AppRegistered(string indexed appId, address indexed owner, bytes composeHash, bytes volumesHash, bytes[] imageHashes);
    event AppUpdated(string indexed appId, uint256 newAckVersion, bytes composeHash, bytes volumesHash, bytes[] imageHashes);
    event AppUnregistered(string indexed appId, address indexed owner);
    /// @dev oldSigner==0 means add, newSigner==0 means remove, both non-zero means replace.
    ///      stakeAmount and unlockAt are only set on add/remove; zero for replace.
    ///      newAckVersion is non-zero for add/replace (ack invalidated); zero for remove.
    event NodeUpdated(string indexed appId, address indexed oldSigner, address indexed newSigner, uint256 stakeAmount, uint256 unlockAt, uint256 newAckVersion);
    event StakeWithdrawn(address indexed owner, uint256 amount);
    event AppAcknowledged(string indexed appId, address indexed user, uint256 ackVersion);
    event MinStakeUpdated(uint256 oldAmount, uint256 newAmount);
    event LockPeriodUpdated(uint256 oldPeriod, uint256 newPeriod);
    event AdminTransferred(address indexed previousAdmin, address indexed newAdmin);

    // ─── Modifiers ────────────────────────────────────────────────────────────

    modifier onlyAdmin() {
        require(msg.sender == admin, "not admin");
        _;
    }

    modifier onlyAppOwner(string calldata appId) {
        require(_apps[appId].owner == msg.sender, "not app owner");
        _;
    }

    modifier nonReentrant() {
        require(!_locked, "reentrant");
        _locked = true;
        _;
        _locked = false;
    }

    modifier initializer() {
        require(!_initialized, "already initialized");
        _initialized = true;
        _;
    }

    // ─── Constructor / Initializer ────────────────────────────────────────────

    /// @dev Locks the implementation so initialize() cannot be called on it directly.
    constructor() {
        _initialized = true;
    }

    /// @notice Initialise the proxy. Called once via BeaconProxy through delegatecall.
    /// @param _minStakeAmount Minimum stake per node in wei (e.g. 1 ether)
    /// @param _lockPeriod     Lock period in seconds after removeNode (e.g. 7 days)
    function initialize(uint256 _minStakeAmount, uint256 _lockPeriod) external initializer {
        admin          = msg.sender;
        minStakeAmount = _minStakeAmount;
        lockPeriod     = _lockPeriod;
    }

    // ─── Admin ────────────────────────────────────────────────────────────────

    function setMinStakeAmount(uint256 amount) external onlyAdmin {
        emit MinStakeUpdated(minStakeAmount, amount);
        minStakeAmount = amount;
    }

    function setLockPeriod(uint256 period) external onlyAdmin {
        emit LockPeriodUpdated(lockPeriod, period);
        lockPeriod = period;
    }

    function transferAdmin(address newAdmin) external onlyAdmin {
        require(newAdmin != address(0), "zero address");
        emit AdminTransferred(admin, newAdmin);
        admin = newAdmin;
    }

    // ─── App ──────────────────────────────────────────────────────────────────

    /// @notice Register a new app and add its first node atomically.
    ///         msg.value is the stake for the first node (>= minStakeAmount).
    /// @param appId               Unique application identifier
    /// @param composeHash         SHA384 of the normalised docker-compose yaml
    /// @param volumesHash         SHA384 of all mount/volume files
    /// @param imageHashes         Docker image digests, one per service in compose order
    /// @param firstSignerAddress  TEE EVM address of the first node
    /// @param firstTeeUrl         Evidence URL of the first node
    function registerApp(
        string   calldata appId,
        bytes    calldata composeHash,
        bytes    calldata volumesHash,
        bytes[]  calldata imageHashes,
        address           firstSignerAddress,
        string   calldata firstTeeUrl
    ) external payable {
        require(_apps[appId].owner == address(0), "app already exists");
        require(msg.value >= minStakeAmount, "insufficient stake");

        _apps[appId] = AppInfo({
            composeHash:  composeHash,
            volumesHash:  volumesHash,
            imageHashes:  imageHashes,
            owner:        msg.sender,
            registeredAt: block.timestamp
        });

        ++_appAckVersions[appId];
        _addNode(appId, firstSignerAddress, firstTeeUrl, msg.value, 0);

        emit AppRegistered(appId, msg.sender, composeHash, volumesHash, imageHashes);
    }

    /// @notice Update the shared code metadata for an app (e.g. after re-deployment).
    ///         Increments ackVersion, invalidating all prior acknowledgements.
    function updateApp(
        string  calldata appId,
        bytes   calldata composeHash,
        bytes   calldata volumesHash,
        bytes[] calldata imageHashes
    ) external onlyAppOwner(appId) {
        AppInfo storage app = _apps[appId];
        app.composeHash = composeHash;
        app.volumesHash = volumesHash;
        app.imageHashes = imageHashes;

        uint256 newVersion = ++_appAckVersions[appId];
        emit AppUpdated(appId, newVersion, composeHash, volumesHash, imageHashes);
    }

    // ─── Nodes ────────────────────────────────────────────────────────────────

    /// @notice Add a node to an existing app. Only the app owner may add nodes.
    ///         msg.value is the stake for this node (>= minStakeAmount).
    ///         Increments ackVersion because a new cluster member changes trust assumptions.
    function addNode(
        string  calldata appId,
        address          signerAddress,
        string  calldata teeUrl
    ) external payable onlyAppOwner(appId) {
        require(msg.value >= minStakeAmount, "insufficient stake");
        require(_nodes[appId][signerAddress].addedAt == 0, "node already exists");

        uint256 newVersion = ++_appAckVersions[appId];
        _addNode(appId, signerAddress, teeUrl, msg.value, newVersion);
    }

    /// @notice Update a node's signer address and/or teeUrl.
    ///         Requires the old node to exist; applies new values unconditionally.
    ///         Stake carries over. Always increments ackVersion.
    ///         Only the app owner may call this.
    function updateNode(
        string  calldata appId,
        address          oldSigner,
        address          newSigner,
        string  calldata teeUrl
    ) external onlyAppOwner(appId) {
        require(_nodes[appId][oldSigner].addedAt != 0, "old node not found");
        require(_nodes[appId][newSigner].addedAt == 0, "new signer already exists");

        uint256 stake = _nodes[appId][oldSigner].stakeAmount;

        // Replace signer in nodeList (no-op if same)
        address[] storage list = _nodeList[appId];
        for (uint256 i = 0; i < list.length; i++) {
            if (list[i] == oldSigner) { list[i] = newSigner; break; }
        }

        // Replace node entry
        delete _nodes[appId][oldSigner];
        _nodes[appId][newSigner] = NodeInfo({teeUrl: teeUrl, addedAt: block.timestamp, stakeAmount: stake});

        uint256 newVersion = ++_appAckVersions[appId];
        emit NodeUpdated(appId, oldSigner, newSigner, 0, 0, newVersion);
    }

    /// @notice Remove a node. Stake is locked for lockPeriod seconds in the owner's
    ///         locked balance. If this was the last node, the app is unregistered.
    ///         Only the app owner may remove nodes.
    function removeNode(
        string  calldata appId,
        address          signerAddress
    ) external onlyAppOwner(appId) {
        NodeInfo storage node = _nodes[appId][signerAddress];
        require(node.addedAt != 0, "node not found");

        address owner    = _apps[appId].owner;
        uint256 stake    = node.stakeAmount;
        uint256 unlockAt = block.timestamp + lockPeriod;

        // Lock stake in owner's balance
        _lockedBalance[owner].push(LockedEntry({amount: stake, unlockAt: unlockAt}));

        // Remove node from active set
        delete _nodes[appId][signerAddress];
        address[] storage list = _nodeList[appId];
        for (uint256 i = 0; i < list.length; i++) {
            if (list[i] == signerAddress) {
                list[i] = list[list.length - 1];
                list.pop();
                break;
            }
        }

        emit NodeUpdated(appId, signerAddress, address(0), stake, unlockAt, 0);

        // If last node, unregister the app
        if (list.length == 0) {
            delete _apps[appId];
            ++_appAckVersions[appId];
            emit AppUnregistered(appId, owner);
        }
    }

    /// @notice Withdraw all matured locked stake entries for the caller.
    function withdraw() external nonReentrant {
        LockedEntry[] storage entries = _lockedBalance[msg.sender];
        uint256 total = 0;
        uint256 i = 0;
        while (i < entries.length) {
            if (block.timestamp >= entries[i].unlockAt) {
                total += entries[i].amount;
                entries[i] = entries[entries.length - 1];
                entries.pop();
            } else {
                i++;
            }
        }
        require(total > 0, "nothing to withdraw");
        (bool ok,) = msg.sender.call{value: total}("");
        require(ok, "transfer failed");
        emit StakeWithdrawn(msg.sender, total);
    }

    // ─── Acknowledge ──────────────────────────────────────────────────────────

    /// @notice Record that the caller has manually verified this app's TEE evidence.
    ///         Records the current ackVersion; becomes stale if updateApp or
    ///         updateNode is called afterwards.
    function acknowledgeApp(string calldata appId) external {
        require(_apps[appId].owner != address(0), "app not found");

        uint256 version = _appAckVersions[appId];
        require(_acks[msg.sender][appId] != version + 1, "already acknowledged");

        // Store version+1 so that version==0 (initial) is distinguishable from "never acked"
        if (_acks[msg.sender][appId] == 0) {
            _ackCounts[appId]++;
        }
        _acks[msg.sender][appId] = version + 1;

        emit AppAcknowledged(appId, msg.sender, version);
    }

    // ─── Views ────────────────────────────────────────────────────────────────

    function getAppInfo(string calldata appId) external view returns (AppInfo memory) {
        return _apps[appId];
    }

    function getAckVersion(string calldata appId) external view returns (uint256) {
        return _appAckVersions[appId];
    }

    function getNode(
        string  calldata appId,
        address          signerAddress
    ) external view returns (NodeInfo memory) {
        return _nodes[appId][signerAddress];
    }

    /// @notice Active node list. Entries are removed immediately when a node is removed.
    function getNodeList(string calldata appId) external view returns (address[] memory) {
        return _nodeList[appId];
    }

    /// @notice All locked stake entries for an owner.
    function getLockedBalance(address owner) external view returns (LockedEntry[] memory) {
        return _lockedBalance[owner];
    }

    /// @notice Returns true if the user has acknowledged the current app version.
    function isAcknowledged(address user, string calldata appId) external view returns (bool) {
        uint256 version = _appAckVersions[appId];
        return _acks[user][appId] == version + 1;
    }

    /// @notice Total number of unique users who have ever acknowledged this app.
    function getAckCount(string calldata appId) external view returns (uint256) {
        return _ackCounts[appId];
    }

    // ─── Internal ─────────────────────────────────────────────────────────────

    function _addNode(
        string  memory appId,
        address        signerAddress,
        string  memory teeUrl,
        uint256        stakeAmount,
        uint256        newAckVersion
    ) internal {
        _nodes[appId][signerAddress] = NodeInfo({
            teeUrl:      teeUrl,
            addedAt:     block.timestamp,
            stakeAmount: stakeAmount
        });
        _nodeList[appId].push(signerAddress);

        emit NodeUpdated(appId, address(0), signerAddress, stakeAmount, 0, newAckVersion);
    }
}
