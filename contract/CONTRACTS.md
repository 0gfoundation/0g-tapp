# TappRegistry Contract Registry

---

## Testnet (0G Galileo, chain ID 16602)

Explorer: https://chainscan-galileo.0g.ai
RPC: https://evmrpc-testnet.0g.ai

> For development and integration testing. Data may be reset at any time.

```env
TAPP_REGISTRY_CONTRACT=0x2Ce80374318B1d7Fb3345724457a182E0ad165c9
```

**Deployed:** 2026-06-23  **Deployer:** `0xea695C312CE119dE347425B29AFf85371c9d1837`
**Min stake:** 1 0G (`1000000000000000000` wei)  **Lock period:** 86400 s (1 day)
All three contracts source-verified on the explorer.
Registry `admin` and beacon owner were moved to
`0x73443d8C05c74F8C2F5D499Da2597a1EE49E431b` on 2026-09-05 (no timelock here —
upgrades apply immediately, which is intended for a dev chain).

| Contract | Address |
|----------|---------|
| TappRegistry Implementation (initial) | `0xaeddc6b6A6b9d4a9513Cc2322bbb78DFF97DA459` |
| TappRegistry Implementation (getNode resolves inherit) | `0x6987fD9afe6e2430bF5AD85cfBC8c63487d4e4BD` |
| **TappRegistry Implementation (current, v0.1.0 — adds `version()`)** | `0x9Ea52Ef383e8eA3fe7F0890309D3C62b2FC1Ac2B` |
| UpgradeableBeacon | `0x1Cd7544068AdC525b9Cb21cC13aF25D95a53645E` |
| **BeaconProxy (stable)** | `0x2Ce80374318B1d7Fb3345724457a182E0ad165c9` |

**Upgrades**

| Date | New Implementation | Upgrade Tx | Notes |
|------|--------------------|-----------|-------|
| 2026-07-07 | `0x9Ea52Ef383e8eA3fe7F0890309D3C62b2FC1Ac2B` | `0x8a003a1a05c381f59bf213c19e2340b63094ad3230d84e0f42ac9c71d7f84505` | Add `version()` view (baseline `0.1.0`); storage layout unchanged, source-verified |

**`getNode` returns 5 fields** — `(teeUrl, addedAt, stakeAmount, composeHash, volumesHash)`.
Sanity check you are talking to this registry: `cast call <proxy> "version()(string)"`
returns `"0.1.0"`.

e2e exercised on app `0g-kms`: register-onchain (app-level default + first node
inherit), add-node-onchain (per-node override), update-node-onchain — all verified
on-chain via getNode/getAppInfo.

---

## Mainnet (0G, chain ID 16661)

RPC: https://evmrpc.0g.ai

```env
TAPP_REGISTRY_CONTRACT=0x54874F536301c993922Dd95097e3902e7FBfe612
```

**Deployed:** 2026-09-04 **Deployer:** `0x60BF67E31784af4E58371cBEfd7a5B6c00C3EBe4` (throwaway,
retains no authority) **Min stake:** 10 OG (initial, will be raised to 100)
**Lock period:** 604800 s (7 days) **Implementation:** v0.1.0 (has `version()`, 5-field `getNode`)
All four contracts (impl, beacon, proxy, timelock) source-verified on https://chainscan.0g.ai.

| Contract | Address |
|----------|---------|
| TappRegistry Implementation | `0xf399583d108346e48aDF54cd8727d7433C652949` |
| UpgradeableBeacon | `0x32fFeDa56E1e12646661E1fe9B17c13D2709975f` |
| **BeaconProxy (stable)** | `0x54874F536301c993922Dd95097e3902e7FBfe612` |
| TimelockController (beacon owner) | `0xD070792b1dB64F858ACE3E5443f2d21c0edE0BAc` |

**Authority** — the deployer key holds nothing:

- Beacon owner = TimelockController, minDelay **86400 s (1 day)**: every upgrade is
  scheduled on-chain and executable only a day later.
- Timelock proposer / executor / admin = `0x73443d8C05c74F8C2F5D499Da2597a1EE49E431b`.
- Registry `admin` (setMinStakeAmount / setLockPeriod / transferAdmin) =
  `0x73443d8C05c74F8C2F5D499Da2597a1EE49E431b`.

**Upgrading:** deploy the new implementation, then use `0g-agentic-id`'s
`ScheduleUpgrade.s.sol` / `ExecuteUpgrade.s.sol` (its OZ scripts match this beacon's
`upgradeTo(address)`) with `TIMELOCK=0xD070…0BAc BEACON=0x32fF…975f`, run as the
proposer key. Direct `beacon.upgradeTo` no longer works — only the timelock can call it.

---

## Contract Architecture

```
tapp-cli / user  ──►  BeaconProxy  (stable address, all state lives here)
                           │ reads impl from beacon
                           ▼
                   UpgradeableBeacon  (stores current impl, owned by deployer)
                           │ delegatecall
                           ▼
                   TappRegistry impl  (pure logic, stateless, replaceable)
```

**The proxy address never changes.** Upgrades only replace the implementation.

**App model:** `composeHash`/`volumesHash`/`imageHashes` at the app level are the
**shared defaults** for all nodes. A node MAY override `composeHash`/`volumesHash` in
its `NodeInfo` (for node-specific config); the effective value for a node is its own
override if non-empty, else the app-level default. `imageHashes` are always shared.
`registerApp`/`updateApp` set the app-level defaults; `addNode`/`updateNode` take an
optional per-node override (empty = inherit).

---

## Go Tools

All contract operations are handled by Go tools under `contract/cmd/`. Docker is required only for compilation (forge runs inside a container to work around host GLIBC constraints).

### Compile

Compiles Solidity via Docker and extracts ABIs to `internal/chain/abi/`.

```bash
cd contract
go run ./cmd/compile/
```

After an ABI change, regenerate Go bindings:

```bash
$(go env GOPATH)/bin/abigen \
  --abi internal/chain/abi/TappRegistry.json \
  --pkg chain --type TappRegistry \
  --out internal/chain/tapp_registry.go
```

### Deploy (first time)

```bash
cd contract
go run ./cmd/deploy/ \
  --rpc   https://evmrpc-testnet.0g.ai \
  --key   0x<DEPLOYER_PRIVATE_KEY>     \
  --stake 1000000000000000000          \
  --lock  86400
```

Output lists Implementation, Beacon, and Proxy addresses. Set the Proxy as `TAPP_REGISTRY_CONTRACT`.

### Upgrade

Edit `src/TappRegistry.sol`, recompile, then:

```bash
cd contract
go run ./cmd/upgrade/ \
  --rpc    https://evmrpc-testnet.0g.ai     \
  --key    0x<DEPLOYER_PRIVATE_KEY>         \
  --beacon 0x<UPGRADEABLE_BEACON_ADDRESS>
```

Deploys a new implementation and calls `beacon.upgradeTo`. The proxy address is unchanged.

### Verify

```bash
cd contract
go run ./cmd/verify/ --proxy 0x<BEACON_PROXY_ADDRESS>
```

Auto-discovers impl, beacon, and proxy from the given BeaconProxy address. Checks which are unverified, extracts constructor args from on-chain data, submits source, and polls for results. All three contracts are verified in one command.

---

## tapp-cli Usage

### Register app on-chain

```bash
tapp-cli \
  --server http://<TAPP_SERVER>:50051 \
  --private-key 0x<PRIVATE_KEY> \
  register-onchain \
  --app-id <APP_ID> \
  --rpc-url <RPC_URL> \
  --contract <TAPP_REGISTRY_CONTRACT> \
  --stake-wei 1000000000000000000
```

### Add a node

```bash
tapp-cli \
  --server http://<NEW_NODE>:50051 \
  --private-key 0x<PRIVATE_KEY> \
  add-node-onchain \
  --app-id <APP_ID> \
  --rpc-url <RPC_URL> \
  --contract <TAPP_REGISTRY_CONTRACT> \
  --stake-wei 1000000000000000000
```

### Update app hashes (after redeployment)

`update-onchain` updates the app-level shared defaults (compose/volumes/images). If a
specific node diverges from the defaults, set its per-node override with
`update-node-onchain` (same old/new signer to keep the node; it fetches that node's
current compose/volumes from `--server`).

```bash
tapp-cli \
  --server http://<TAPP_SERVER>:50051 \
  --private-key 0x<PRIVATE_KEY> \
  update-onchain \
  --app-id <APP_ID> \
  --rpc-url <RPC_URL> \
  --contract <TAPP_REGISTRY_CONTRACT>
```

---

## On-chain Queries

```bash
# Current implementation address
docker run --rm --entrypoint cast ghcr.io/foundry-rs/foundry:latest \
  call <BEACON> "implementation()(address)" --rpc-url <RPC_URL>

# minStakeAmount
docker run --rm --entrypoint cast ghcr.io/foundry-rs/foundry:latest \
  call <PROXY> "minStakeAmount()(uint256)" --rpc-url <RPC_URL>

# App info — composeHash/volumesHash here are the app-level SHARED DEFAULTS; imageHashes
# is always shared. A node may override compose/volumes (see getNode below).
docker run --rm --entrypoint cast ghcr.io/foundry-rs/foundry:latest \
  call <PROXY> "getAppInfo(string)((bytes,bytes,bytes[],address,uint256))" "<APP_ID>" --rpc-url <RPC_URL>

# Node info — teeUrl, addedAt, stakeAmount, composeHash, volumesHash. getNode returns the
# node's EFFECTIVE compose/volumes: its own override if set, else the app-level default
# resolved in. (Storage holds empty = inherit; the raw override is in the NodeCode event.)
docker run --rm --entrypoint cast ghcr.io/foundry-rs/foundry:latest \
  call <PROXY> "getNode(string,address)((string,uint256,uint256,bytes,bytes))" "<APP_ID>" "<SIGNER>" --rpc-url <RPC_URL>
```
