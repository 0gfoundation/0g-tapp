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
| TappRegistry Implementation | `0xE03de87Dc82ABeacD48deEDCAA6D607Fa6EA05b6` | `0x465379c54d379b9a7b5be0e2442eaf32e363419aabf40e8817b8d65704687f32` |
| UpgradeableBeacon | `0x8fD880b7FCc9f0170a6F2aA58Ee90B4A012a509E` | `0x92a77f5c52cce763b8e9d26d30efbe0ce305a63019a4f0fd842744dd9c2b1fc0` |
| **BeaconProxy (stable)** | `0x95a0BF4148b30F6F8D86870534c51df46Da5511c` | `0x1e360fa0236bf3b2857ee7c69ce4680415ea5bfa34ac9b6826f2d643249f33ee` |

```env
TAPP_REGISTRY_CONTRACT=0x95a0BF4148b30F6F8D86870534c51df46Da5511c
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

# App info
docker run --rm --entrypoint cast ghcr.io/foundry-rs/foundry:latest \
  call <PROXY> "getAppInfo(string)((bytes,bytes,bytes[],address,uint256))" "<APP_ID>" --rpc-url <RPC_URL>
```
