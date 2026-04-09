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
///         App liveness is determined off-chain (app is live while it has staked nodes).
///
///         Staking
///         -------
///         Stake is per node. Each addNode / registerApp call requires
///         msg.value >= minStakeAmount. After removeNode, stake is locked for
///         lockPeriod seconds before the owner may withdraw.
///
///         Acknowledge
///         -----------
///         Each app has an ackVersion counter. Users acknowledge a specific version;
///         their acknowledgement becomes stale whenever the counter increments.
///         updateApp and updateNode both increment the counter (code or node changed).
///         addNode and removeNode do not (cluster trust is maintained by inter-node RA).
///
///         Off-chain workflow:
///           1. Read app info + node list via getAppInfo / getNodeList.
///           2. Pick a node; fetch attestation evidence from its teeUrl.
///           3. Submit evidence to an RA service; confirm the returned signerAddress
///              and codeHash match on-chain values.
///           4. Call acknowledgeApp(appId) to record acknowledgement on-chain.
///
///         Future: extend acknowledgeApp to accept evidence + RA-service signature
///         for fully on-chain automated remote attestation.
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

    struct UnstakeRequest {
        uint256 amount;
        /// @dev Timestamp after which the owner may withdraw
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
    // slot 3 — append-only; includes removed nodes
    mapping(string => address[]) private _nodeList;
    // slot 4 — appId => signerAddress => pending UnstakeRequest
    mapping(string => mapping(address => UnstakeRequest)) private _nodeUnstakeReqs;
    // slot 5 — user => appId => ackVersion at time of acknowledgement (0 = never acked)
    mapping(address => mapping(string => uint256)) private _acks;
    // slot 6
    mapping(string => uint256) private _ackCounts;
    // slot 7 — incremented by updateApp / updateNode; invalidates all prior acks
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

    event AppRegistered(string indexed appId, address indexed owner);
    event AppUpdated(string indexed appId, uint256 newAckVersion);
    event NodeAdded(string indexed appId, address indexed signerAddress, uint256 stakeAmount);
    event NodeUpdated(string indexed appId, address indexed signerAddress, uint256 newAckVersion);
    event NodeRemoved(string indexed appId, address indexed signerAddress, uint256 unlockAt);
    event NodeStakeWithdrawn(string indexed appId, address indexed signerAddress, uint256 amount);
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

        _addNode(appId, firstSignerAddress, firstTeeUrl, msg.value);

        emit AppRegistered(appId, msg.sender);
    }

    /// @notice Update the shared code metadata for an app (e.g. after re-deployment).
    ///         Increments ackVersion, invalidating all prior acknowledgements.
    function updateApp(
        string  calldata appId,
        bytes   calldata composeHash,
        bytes   calldata volumesHash,
        bytes[] calldata imageHashes
    ) external onlyAppOwner(appId) {
        require(_apps[appId].owner != address(0), "app not found");

        AppInfo storage app = _apps[appId];
        app.composeHash = composeHash;
        app.volumesHash = volumesHash;
        app.imageHashes = imageHashes;

        uint256 newVersion = ++_appAckVersions[appId];
        emit AppUpdated(appId, newVersion);
    }

    // ─── Nodes ────────────────────────────────────────────────────────────────

    /// @notice Add a node to an existing app. Only the app owner may add nodes.
    ///         msg.value is the stake for this node (>= minStakeAmount).
    ///         Does NOT invalidate existing acknowledgements (new node is trusted
    ///         via inter-node mutual RA).
    function addNode(
        string  calldata appId,
        address          signerAddress,
        string  calldata teeUrl
    ) external payable onlyAppOwner(appId) {
        require(_apps[appId].owner != address(0), "app not found");
        require(msg.value >= minStakeAmount, "insufficient stake");
        require(_nodes[appId][signerAddress].addedAt == 0, "node already exists");

        _addNode(appId, signerAddress, teeUrl, msg.value);
    }

    /// @notice Update a node's evidence URL (e.g. after an endpoint change).
    ///         Increments ackVersion, invalidating all prior acknowledgements.
    function updateNode(
        string  calldata appId,
        address          signerAddress,
        string  calldata teeUrl
    ) external onlyAppOwner(appId) {
        NodeInfo storage node = _nodes[appId][signerAddress];
        require(node.addedAt != 0, "node not found");
        require(_nodeUnstakeReqs[appId][signerAddress].unlockAt == 0, "node being removed");

        node.teeUrl = teeUrl;

        uint256 newVersion = ++_appAckVersions[appId];
        emit NodeUpdated(appId, signerAddress, newVersion);
    }

    /// @notice Remove a node and start the stake lock period.
    ///         Only the app owner may remove nodes.
    ///         Does NOT invalidate existing acknowledgements.
    function removeNode(
        string  calldata appId,
        address          signerAddress
    ) external onlyAppOwner(appId) {
        NodeInfo storage node = _nodes[appId][signerAddress];
        require(node.addedAt != 0, "node not found");
        require(_nodeUnstakeReqs[appId][signerAddress].unlockAt == 0, "removal already pending");

        uint256 unlockAt = block.timestamp + lockPeriod;
        _nodeUnstakeReqs[appId][signerAddress] = UnstakeRequest({
            amount:   node.stakeAmount,
            unlockAt: unlockAt
        });
        node.stakeAmount = 0; // prevent double-removal

        emit NodeRemoved(appId, signerAddress, unlockAt);
    }

    /// @notice Withdraw a removed node's stake after the lock period elapses.
    function withdrawNodeStake(
        string  calldata appId,
        address          signerAddress
    ) external nonReentrant onlyAppOwner(appId) {
        UnstakeRequest memory req = _nodeUnstakeReqs[appId][signerAddress];
        require(req.unlockAt != 0, "no unstake request");
        require(block.timestamp >= req.unlockAt, "stake still locked");

        delete _nodeUnstakeReqs[appId][signerAddress];
        (bool ok,) = msg.sender.call{value: req.amount}("");
        require(ok, "transfer failed");

        emit NodeStakeWithdrawn(appId, signerAddress, req.amount);
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

    /// @notice All signer addresses ever added to the app (including removed ones).
    ///         A removed node has stakeAmount==0 and a pending UnstakeRequest.
    function getNodeList(string calldata appId) external view returns (address[] memory) {
        return _nodeList[appId];
    }

    function getNodeUnstakeRequest(
        string  calldata appId,
        address          signerAddress
    ) external view returns (UnstakeRequest memory) {
        return _nodeUnstakeReqs[appId][signerAddress];
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
        uint256        stakeAmount
    ) internal {
        _nodes[appId][signerAddress] = NodeInfo({
            teeUrl:      teeUrl,
            addedAt:     block.timestamp,
            stakeAmount: stakeAmount
        });
        _nodeList[appId].push(signerAddress);

        emit NodeAdded(appId, signerAddress, stakeAmount);
    }
}
