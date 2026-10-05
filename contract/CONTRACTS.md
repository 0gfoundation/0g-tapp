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
| TappRegistry Implementation (v0.1.0 — adds `version()`) | `0x9Ea52Ef383e8eA3fe7F0890309D3C62b2FC1Ac2B` |
| **TappRegistry Implementation (current, v0.2.0 — app-owner transfer)** | `0xa10a561C3Bf2c2dE3013845Cc2ed3eb5a218D3b8` |
| UpgradeableBeacon | `0x1Cd7544068AdC525b9Cb21cC13aF25D95a53645E` |
| **BeaconProxy (stable)** | `0x2Ce80374318B1d7Fb3345724457a182E0ad165c9` |

**Upgrades**

| Date | New Implementation | Upgrade Tx | Notes |
|------|--------------------|-----------|-------|
| 2026-07-07 | `0x9Ea52Ef383e8eA3fe7F0890309D3C62b2FC1Ac2B` | `0x8a003a1a05c381f59bf213c19e2340b63094ad3230d84e0f42ac9c71d7f84505` | Add `version()` view (baseline `0.1.0`); storage layout unchanged, source-verified |
| 2026-10-05 | `0xa10a561C3Bf2c2dE3013845Cc2ed3eb5a218D3b8` | `0x9541c3bb9c413bc8844f23066405a0671623833627a43c34304981576e5a2445` | `0.2.0`: two-step app-owner transfer. One new slot from `__gap`; `cmd/upgrade --check` confirmed 15 values unchanged (admin, stake parameters, and 0g-kms / 0g-agentic-id / 0g-agentic-id-sandbox-provider / 0g-tappscan records). Source-verified |

**`getNode` returns 5 fields** — `(teeUrl, addedAt, stakeAmount, composeHash, volumesHash)`.
Sanity check you are talking to this registry: `cast call <proxy> "version()(string)"`
returns `"0.2.0"`.

e2e exercised on app `0g-kms`: register-onchain (app-level default + first node
inherit), add-node-onchain (per-node override), update-node-onchain — all verified
on-chain via getNode/getAppInfo.

> A superseded earlier deployment lives at proxy `0x95a0BF4148b30F6F8D86870534c51df46Da5511c`
> (no `version()`, 3-field `getNode`); some long-lived apps (testnet sandbox
> provider / attestor) are still registered there. Details in git history.

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

## Implementation 0.2.0 (app ownership transfer)

**Testnet: deployed 2026-10-05** (see its upgrades table). **Mainnet: pending** —
the proxy still answers `version()` = `"0.1.0"`. Adds a two-step app-owner transfer:

| Function | Who | Effect |
|---|---|---|
| `transferAppOwnership(appId, newOwner)` | app owner | nominate (`address(0)` cancels; again = replace) |
| `acceptAppOwnership(appId)` | the nominee | becomes owner; nomination cleared |
| `pendingAppOwner(appId)` → address | anyone | current nominee, or `address(0)` |

Events `AppOwnershipTransferStarted(appId, owner, pendingOwner)` and
`AppOwnershipTransferred(appId, previousOwner, newOwner)`.

- **Stake**: live nodes' stake travels with the app (`removeNode` refunds whoever
  owns the app then); stake already locked to the old owner stays theirs.
- **Acks** are not bumped: no code changes, and every change the new owner can
  make bumps the ack version anyway.
- A nomination is deleted when the app unregisters (last `removeNode`), so a stale
  nominee can never accept a later registration of the same id.
- **Storage**: one new mapping at slot 12, taken from `__gap` (48 → 47); slots
  0–11 unchanged. `test_Upgrade_From010_PreservesStateAndStartsWithNothingPending`
  upgrades a populated 0.1.0 proxy and checks every field.

Rollout with `go run ./cmd/upgrade/` (Go Tools below), which keeps the beacon
owner's key off the machine doing the work. Testnet: the owner (`0x73443d…`) signs
the printed `upgradeTo`. Mainnet: the owner is the timelock — its proposer
(`0x87605ec8…`) schedules, and after the 1-day delay an executor executes. Then
`go run ./cmd/verify/ --network <net>`. Record each in its network's upgrades table
and flip this section to "deployed". Both paths have been rehearsed end to end on
local forks of the live networks: state unchanged, the new functions live.

The 0.1.0 implementations live on both networks (testnet `0x9Ea52Ef3…`, mainnet
`0xf399583d…`) are byte-identical, metadata aside, to the 0.1.0 fixture the
upgrade test runs against.

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

Deploy, upgrade and verify are Go tools under `contract/cmd/`. They read forge's build
output directly, so the one prerequisite is:

```bash
cd contract && forge build
```

All three take `--network testnet|mainnet`, which supplies the RPC, chain id, explorer
and the registry's proxy address; `--rpc` / `--chain-id` override it for a local
anvil fork. A command refuses an RPC that is not on the network's chain.

Keys: `--keystore <file>` (a foundry/geth keystore — `~/.foundry/keystores/<name>`;
password prompted, or `--password-file`), or `PRIVATE_KEY` in the environment.
`--key 0x…` still works for throwaway keys, with a warning: it is visible in the
process list and the shell history. Exactly one source: giving two is refused, so
an owner key left in the environment can never be used in place of the throwaway
named on the command line.

### Deploy (first time)

```bash
PRIVATE_KEY=0x<throwaway> go run ./cmd/deploy/ --network testnet \
  --stake 1000000000000000000 --lock 86400 \
  --beacon-owner 0x<timelock or wallet> --admin 0x<wallet>
```

The deploy key needs gas and nothing else. The beacon is created with
`--beacon-owner` (who may upgrade) as its owner, so that power never passes through
the deploy key; `--admin` (stake parameters) is handed over straight after, since
`initialize()` records its caller. Both are read back and must match. On mainnet
both are required and `--beacon-owner` must be a contract (the timelock) — checked
before anything is deployed, so a typo costs nothing. Output lists the proxy (`TAPP_REGISTRY_CONTRACT`), beacon,
implementation and the authority in force.

### Upgrade

```bash
PRIVATE_KEY=0x<throwaway> go run ./cmd/upgrade/ --network testnet     # or mainnet
go run ./cmd/upgrade/ --network testnet --check 0x<new implementation>
```

The key only pays for putting the new implementation on chain. The switch
(`beacon.upgradeTo`) belongs to the beacon owner, and the tool reads what that is:

| beacon owner | what happens |
|---|---|
| this key | the switch is sent (dev chains) |
| a wallet (testnet: `0x73443d…`) | the exact transaction is printed for the owner to sign elsewhere — wallet, hardware key — after simulating it **as** the owner |
| a TimelockController (mainnet) | the schedule and execute transactions are printed, with the delay read from it; `--proposer <addr>` simulates the schedule as that proposer |

`--check <impl>` confirms the beacon moved and that the switch itself changed
nothing: the registry's admin, stake parameters, and for `--apps` (default
`0g-kms`) app info, node list and ack version, read at the block before the
switch and the block of it — so a day of ordinary activity behind a timelock is not
mistaken for a change. An RPC that prunes history (the 0G testnet's) cannot answer
for old blocks; then the snapshot taken when the upgrade was prepared
(`upgrade-state.<proxy>.txt`) is compared with now. Before the switch, for a
timelock, it reports whether the operation is unscheduled, pending (until when) or
ready. `--impl <addr>` re-prints the switch for an
implementation already deployed.

Rehearse on a fork first — it costs nothing and runs the real state:

```bash
anvil --fork-url https://evmrpc.0g.ai --port 8545 &
PRIVATE_KEY=<an anvil account> go run ./cmd/upgrade/ --network mainnet --rpc http://127.0.0.1:8545 \
  --proposer 0x87605ec8e10eb373c1d070e15e5d78fac4d7621d --apps 0g-kms,0g-agentic-id
# impersonate the proposer (anvil_impersonateAccount), send the schedule tx,
# evm_increaseTime 86401, send the execute tx, then --check
```

### Verify

```bash
go run ./cmd/verify/ --network testnet      # or mainnet
```

Auto-discovers impl, beacon and proxy behind the network's registry (or `--proxy`),
skips what is already verified, extracts constructor args from on-chain data, submits
source and polls. Run it again after an upgrade and it verifies the new
implementation.

### Compile (only to regenerate the Go bindings in `internal/chain/`)

`go run ./cmd/compile/` builds via Docker and extracts ABIs to `internal/chain/abi/`;
then `abigen` regenerates `internal/chain/tapp_registry.go`. The tools above do not
need them.

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
