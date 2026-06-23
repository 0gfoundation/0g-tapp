# TappRegistry Contract Registry

---

## Testnet (0G Galileo, chain ID 16602)

Explorer: https://chainscan-galileo.0g.ai
RPC: https://evmrpc-testnet.0g.ai

### Dev

> For local development and integration testing. Data may be reset at any time.

**Deployed:** 2026-04-10
**Deployer:** `0xB831371eb2703305f1d9F8542163633D0675CEd7`
**Min stake:** 1 0G (`1000000000000000000` wei)
**Lock period:** 86400 s (1 day)

| Contract | Address | Tx Hash |
|----------|---------|---------|
| TappRegistry Implementation (initial) | `0xE03de87Dc82ABeacD48deEDCAA6D607Fa6EA05b6` | `0x465379c54d379b9a7b5be0e2442eaf32e363419aabf40e8817b8d65704687f32` |
| **TappRegistry Implementation (current)** | `0x259c066ef1030a42cDf1bea5Acc928e49aa46822` | `0x7e1b4d078544e5ba877a1f4eb816fa19be5adbae8d9e4aa36e9c9bfedcc0714a` |
| UpgradeableBeacon | `0x8fD880b7FCc9f0170a6F2aA58Ee90B4A012a509E` | `0x92a77f5c52cce763b8e9d26d30efbe0ce305a63019a4f0fd842744dd9c2b1fc0` |
| **BeaconProxy (stable)** | `0x95a0BF4148b30F6F8D86870534c51df46Da5511c` | `0x1e360fa0236bf3b2857ee7c69ce4680415ea5bfa34ac9b6826f2d643249f33ee` |

**Upgrades:**

| Date | New Implementation | Upgrade Tx | Notes |
|------|--------------------|-----------|-------|
| 2026-06-02 | `0xcE835faCd6381aaFA3fA2DB921DbFb2209f4523c` | `0x6390a0c5fcb9002c379a0f14378a2139e5499a09127427d73675051beba49ee0` | Add user revoke ack + authorize/revoke invalidator + invalidateAcks |
| 2026-06-02 | `0x259c066ef1030a42cDf1bea5Acc928e49aa46822` | `0x21542dd5a4edb72925419bfc7d71380739e40fbbac063dea3aa022619ec73046` | Add batch acknowledgeApps / revokeAcknowledgements |

```env
TAPP_REGISTRY_CONTRACT=0x95a0BF4148b30F6F8D86870534c51df46Da5511c
```

#### Per-node-compose e2e test instance (branch `fix/tappregistry-per-node-compose-hash`)

> Standalone throwaway instance deployed to e2e-test the per-node compose/volumes
> change (issue #535). NOT the canonical Dev registry above — the live beacon was
> not touched. Safe to discard. All three contracts source-verified on the explorer.

**Deployed:** 2026-06-23  **Deployer:** `0xea695C312CE119dE347425B29AFf85371c9d1837`
**Min stake:** 1 0G  **Lock:** 86400 s

| Contract | Address |
|----------|---------|
| TappRegistry Implementation | `0xaeddc6b6A6b9d4a9513Cc2322bbb78DFF97DA459` |
| UpgradeableBeacon | `0x1Cd7544068AdC525b9Cb21cC13aF25D95a53645E` |
| **BeaconProxy (stable)** | `0x2Ce80374318B1d7Fb3345724457a182E0ad165c9` |

e2e exercised on app `0g-kms`: register-onchain (app-level default + first node
inherit), add-node-onchain (per-node override), update-node-onchain — all verified
on-chain via getNode/getAppInfo.

### Testnet

> To be deployed.

---

## Mainnet

> To be deployed.

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

# Node info — teeUrl, addedAt, stakeAmount, composeHash, volumesHash. The compose/volumes
# here are this node's OVERRIDE; empty means it inherits the app-level default above.
docker run --rm --entrypoint cast ghcr.io/foundry-rs/foundry:latest \
  call <PROXY> "getNode(string,address)((string,uint256,uint256,bytes,bytes))" "<APP_ID>" "<SIGNER>" --rpc-url <RPC_URL>
```
