# TappRegistry Contract Registry

---

## Testnet (0G Galileo, chain ID 16602)

Explorer: https://chainscan-galileo.0g.ai
RPC: https://evmrpc-testnet.0g.ai

### Dev

> For local development and integration testing. Data may be reset at any time.

**Deployed:** 2026-04-09
**Deployer:** `0xa3b0779461beDF9Ddacb0D113766494Facc7E306`
**Min stake:** 1 0G (`1000000000000000000` wei)
**Lock period:** 86400 s (1 day)

| Contract | Address | Tx Hash |
|----------|---------|---------|
| TappRegistry Implementation | `0x15Ce553cb6ff5AD10FA83c1cd6337B45C444E0c4` | `0x98aa240c124d6344bf253458bac9e339838af0fe56c5656cb3ac07f51c1fb4ff` |
| UpgradeableBeacon | `0x603F626990D07686cfa7c9B3c000D1B5D7E4301e` | `0xcbe6ea340769d8d499ef2f57c1bdda88f5b9399f9142a6e094e3211e8268f800` |
| **BeaconProxy (stable)** | `0x650212889341E8Aa253E5319be2460C0642D8eb4` | `0x6c158fb02f3d03c7f63dc1e65930827c4469a2f1ebde66615b9f4fe5137d6f44` |

```env
TAPP_REGISTRY_CONTRACT=0x650212889341E8Aa253E5319be2460C0642D8eb4
```

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

---

## Deployment (First Time)

> **TODO:** Replace the Docker/forge approach below with a native Rust deploy binary
> (`cargo run --bin deploy-contract`), similar to how 0g-sandbox uses `go run ./cmd/deploy/`.
> Read bytecode from `contract/out/` artifacts and deploy via ethers-rs — no Docker dependency.

### Prerequisites

- Docker (to run Foundry, works around GLIBC version constraint on the host)
- Deployer private key with sufficient 0G balance for gas

### 1. Build

```bash
docker run --rm \
  --entrypoint forge \
  -v /path/to/0g-tapp/contract:/contract \
  -w /contract \
  ghcr.io/foundry-rs/foundry:latest \
  build
```

### 2. Deploy

```bash
docker run --rm \
  --entrypoint forge \
  -v /path/to/0g-tapp/contract:/contract \
  -w /contract \
  -e MIN_STAKE_AMOUNT=1000000000000000000 \
  -e LOCK_PERIOD=86400 \
  -e FOUNDRY_DISABLE_NIGHTLY_WARNING=1 \
  ghcr.io/foundry-rs/foundry:latest \
  script script/Deploy.s.sol \
    --rpc-url <RPC_URL> \
    --broadcast \
    --private-key 0x<DEPLOYER_PRIVATE_KEY> \
    --legacy \
    --gas-price 3000000000 \
    -vvv
```

Output:
```
Implementation: 0x...
Beacon:         0x...
Proxy (stable): 0x...   ← set this as TAPP_REGISTRY_CONTRACT
```

| Env var | Description |
|---------|-------------|
| `MIN_STAKE_AMOUNT` | Minimum stake per node in wei. `1000000000000000000` = 1 0G |
| `LOCK_PERIOD` | Stake lock period after `removeNode` in seconds. `86400` = 1 day |

> **Note:** 0G testnet requires `--legacy` transaction type. EIP-1559 gas estimation fails on this network.

---

## Upgrade

Deploy a new implementation and point the beacon at it. **The proxy address does not change.**

### 1. Edit and rebuild

```bash
# Edit src/TappRegistry.sol, then rebuild
docker run --rm \
  --entrypoint forge \
  -v /path/to/0g-tapp/contract:/contract \
  -w /contract \
  ghcr.io/foundry-rs/foundry:latest \
  build
```

### 2. Run upgrade script

```bash
docker run --rm \
  --entrypoint forge \
  -v /path/to/0g-tapp/contract:/contract \
  -w /contract \
  -e BEACON_ADDRESS=<BEACON_ADDRESS> \
  -e FOUNDRY_DISABLE_NIGHTLY_WARNING=1 \
  ghcr.io/foundry-rs/foundry:latest \
  script script/Upgrade.s.sol \
    --rpc-url <RPC_URL> \
    --broadcast \
    --private-key 0x<DEPLOYER_PRIVATE_KEY> \
    --legacy \
    --gas-price 3000000000 \
    -vvv
```

Output:
```
New Implementation: 0x...
Beacon upgraded:    0x...
```

### 3. Verify

```bash
# Confirm beacon points to new impl
cast call <BEACON> "implementation()(address)" --rpc-url <RPC_URL>
```

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

> Use Docker if `cast` is not available on the host (`docker run --rm --entrypoint cast ghcr.io/foundry-rs/foundry:latest ...`).

```bash
# Current implementation address
cast call <BEACON> "implementation()(address)" --rpc-url <RPC_URL>

# minStakeAmount
cast call <PROXY> "minStakeAmount()(uint256)" --rpc-url <RPC_URL>

# App info
cast call <PROXY> "getAppInfo(string)((bytes,bytes,bytes[],address,uint256))" "<APP_ID>" --rpc-url <RPC_URL>
```
