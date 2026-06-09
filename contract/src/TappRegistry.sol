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

    // slot 11 — appId => contract => is authorized to call invalidateAcks
    mapping(string => mapping(address => bool)) private _authorizedInvalidators;

    // slots 12–59: reserved for future upgrades
    uint256[48] private __gap;

    // ─── Events ───────────────────────────────────────────────────────────────

    event AppRegistered(string indexed appId, address indexed owner, bytes composeHash, bytes volumesHash, bytes[] imageHashes);
    event AppUpdated(string indexed appId, uint256 newAckVersion, bytes composeHash, bytes volumesHash, bytes[] imageHashes);
    event AppUnregistered(string indexed appId, address indexed owner);
    /// @dev oldSigner==0 means add, newSigner==0 means remove, both non-zero means replace.
    ///      stakeAmount and unlockAt are only set on add/remove; zero for replace.
    ///      newAckVersion is non-zero whenever the ack version was bumped by this call
    ///      (add, replace, or remove of the last node); zero for non-last-node removes.
    event NodeUpdated(string indexed appId, address indexed oldSigner, address indexed newSigner, uint256 stakeAmount, uint256 unlockAt, uint256 newAckVersion);
    event StakeWithdrawn(address indexed owner, uint256 amount);
    event AppAcknowledged(string indexed appId, address indexed user, uint256 ackVersion);
    event AppAcknowledgementRevoked(string indexed appId, address indexed user);
    event InvalidatorAuthorized(string indexed appId, address indexed invalidator);
    event InvalidatorRevoked(string indexed appId, address indexed invalidator);
    event AcksInvalidated(string indexed appId, address indexed invalidator, uint256 newAckVersion);
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
    ///         Pass newSigner == oldSigner to update only the teeUrl.
    ///         Only the app owner may call this.
    function updateNode(
        string  calldata appId,
        address          oldSigner,
        address          newSigner,
        string  calldata teeUrl
    ) external onlyAppOwner(appId) {
        require(newSigner != address(0), "zero signer address");
        require(_nodes[appId][oldSigner].addedAt != 0, "old node not found");
        require(
            newSigner == oldSigner || _nodes[appId][newSigner].addedAt == 0,
            "new signer already exists"
        );

        uint256 stake = _nodes[appId][oldSigner].stakeAmount;

        if (newSigner != oldSigner) {
            address[] storage list = _nodeList[appId];
            for (uint256 i = 0; i < list.length; i++) {
                if (list[i] == oldSigner) { list[i] = newSigner; break; }
            }
            delete _nodes[appId][oldSigner];
        }
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

        // If last node, unregister the app and bump ackVersion before emitting,
        // so NodeUpdated reflects the real post-bump version.
        uint256 newAckVersion = 0;
        if (list.length == 0) {
            delete _apps[appId];
            newAckVersion = ++_appAckVersions[appId];
        }

        emit NodeUpdated(appId, signerAddress, address(0), stake, unlockAt, newAckVersion);

        if (newAckVersion != 0) {
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
    ///         updateNode is called afterwards. Idempotent: re-acking the same
    ///         version is a no-op (no revert, no event).
    function acknowledgeApp(string calldata appId) external {
        _acknowledgeApp(appId);
    }

    /// @notice Batch version of acknowledgeApp. All-or-nothing: if any appId
    ///         does not exist, the entire batch reverts. Per-app idempotency is
    ///         preserved (re-acking the same version emits no event). Duplicates
    ///         within the array are allowed; the second occurrence is a no-op.
    function acknowledgeApps(string[] calldata appIds) external {
        uint256 n = appIds.length;
        for (uint256 i = 0; i < n; i++) {
            _acknowledgeApp(appIds[i]);
        }
    }

    /// @notice Withdraw the caller's acknowledgement for an app. After this,
    ///         isAcknowledged(caller, appId) returns false until they ack again.
    ///         No-op if the caller has no current ack.
    function revokeAcknowledgement(string calldata appId) external {
        _revokeAcknowledgement(appId);
    }

    /// @notice Batch version of revokeAcknowledgement. No-op per appId for which
    ///         the caller has no current ack. Does not check that the apps exist
    ///         (revoking against a stale or missing app is harmless and clears
    ///         stale entries).
    function revokeAcknowledgements(string[] calldata appIds) external {
        uint256 n = appIds.length;
        for (uint256 i = 0; i < n; i++) {
            _revokeAcknowledgement(appIds[i]);
        }
    }

    function _acknowledgeApp(string calldata appId) internal {
        require(_apps[appId].owner != address(0), "app not found");

        uint256 version = _appAckVersions[appId];
        uint256 prior   = _acks[msg.sender][appId];
        if (prior == version + 1) return;

        // Store version+1 so that version==0 (initial) is distinguishable from "never acked"
        if (prior == 0) {
            _ackCounts[appId]++;
        }
        _acks[msg.sender][appId] = version + 1;

        emit AppAcknowledged(appId, msg.sender, version);
    }

    function _revokeAcknowledgement(string calldata appId) internal {
        uint256 prior = _acks[msg.sender][appId];
        if (prior == 0) return;

        delete _acks[msg.sender][appId];
        if (_ackCounts[appId] > 0) {
            _ackCounts[appId]--;
        }

        emit AppAcknowledgementRevoked(appId, msg.sender);
    }

    // ─── Invalidators ─────────────────────────────────────────────────────────
    //
    // Sibling contracts whose on-chain state is part of the dapp's user-facing
    // surface (e.g. SandboxServing's prices) can be authorized by the app owner
    // to bump _appAckVersions[appId]. This lets price/policy changes invalidate
    // existing user acks without abusing updateApp (which is for code identity).

    /// @notice Authorize a sibling contract to call invalidateAcks for this app.
    ///         Only the app owner may authorize.
    function authorizeInvalidator(string calldata appId, address invalidator)
        external
        onlyAppOwner(appId)
    {
        require(invalidator != address(0), "zero invalidator");
        if (_authorizedInvalidators[appId][invalidator]) return;
        _authorizedInvalidators[appId][invalidator] = true;
        emit InvalidatorAuthorized(appId, invalidator);
    }

    /// @notice Revoke a previously-authorized invalidator.
    ///         Only the app owner may revoke.
    function revokeInvalidator(string calldata appId, address invalidator)
        external
        onlyAppOwner(appId)
    {
        if (!_authorizedInvalidators[appId][invalidator]) return;
        delete _authorizedInvalidators[appId][invalidator];
        emit InvalidatorRevoked(appId, invalidator);
    }

    /// @notice Bump the app's ackVersion, invalidating every existing user ack
    ///         for this app. Callable only by an authorized invalidator.
    function invalidateAcks(string calldata appId) external {
        require(_apps[appId].owner != address(0), "app not found");
        require(_authorizedInvalidators[appId][msg.sender], "not authorized");
        uint256 newVersion = ++_appAckVersions[appId];
        emit AcksInvalidated(appId, msg.sender, newVersion);
    }

    /// @notice Returns true if `invalidator` is currently authorized to call
    ///         invalidateAcks for `appId`.
    function isAuthorizedInvalidator(string calldata appId, address invalidator)
        external
        view
        returns (bool)
    {
        return _authorizedInvalidators[appId][invalidator];
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
        require(signerAddress != address(0), "zero signer address");
        _nodes[appId][signerAddress] = NodeInfo({
            teeUrl:      teeUrl,
            addedAt:     block.timestamp,
            stakeAmount: stakeAmount
        });
        _nodeList[appId].push(signerAddress);

        emit NodeUpdated(appId, address(0), signerAddress, stakeAmount, 0, newAckVersion);
    }
}
