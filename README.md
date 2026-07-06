# 0G Tapp

0G Tapp is a Trusted Application Platform that provides secure application deployment and execution within Trusted Execution Environments (TEE). It enables confidential computing with runtime measurement and attestation capabilities.

## Features

- **TEE-based Execution**: Run applications in secure enclaves (TDX, SEV, SGX)
- **Runtime Measurement**: Cryptographic measurement of application deployments
- **Remote Attestation**: Generate and verify attestation evidence
- **Docker Compose Integration**: Deploy containerized applications easily
- **gRPC API**: Comprehensive API for application lifecycle management
- **Signature-based Authentication**: EVM-compatible signature verification for access control
- **On-chain Registration**: Register apps and TEE nodes on TappRegistry smart contract
- **KMS Integration**: Fetch hardware-independent app secrets from a KMS cluster (decrypted locally within the TEE)

## Getting Started

### Prerequisites

- Alibaba Cloud account (for confidential computing instances)
- Docker and Docker Compose
- grpcurl (for testing)
- Rust toolchain (for building from source)

### Creating a Confidential Computing Instance

To run 0G Tapp, you need to create an Alibaba Cloud ECS instance with confidential computing support.

> **GCP (Intel TDX) variant**: To build a hardened, measured, attestable confidential image for Google Cloud from a stock Ubuntu 24.04 cloud image, see [`gcp-cvm/`](gcp-cvm/) — one-command build (`build-gcp-tapp.sh`), full SOP and root-cause notes in [`gcp-cvm/cryptpilot-gcp-boot-fix.md`](gcp-cvm/cryptpilot-gcp-boot-fix.md), and a security-hardening audit (removes SSH / cloud-init / google-guest-agent / metadata startup-scripts and other backdoor vectors).

#### Step 1: Import the Confidential Image

1. Navigate to [Alibaba Cloud Custom Image Import](https://www.alibabacloud.com/help/en/ecs/user-guide/import-a-custom-image#a79650c1bdp04)

2. Import the confidential image with the following parameters:
   - **Image File URL**: `https://confidential-disk.oss-cn-beijing.aliyuncs.com/0g-tapp-confidential-gpu.qcow2`
   - **Operating System Type**: Linux
   - **Operating System Version**: Aliyun
   - **Architecture**: 64-bit Operating System
   - **Boot Mode**: UEFI
   - **Image Format**: QCOW2

#### Step 2: Configure NVMe Driver Support

After the image import completes:
1. Go to the image details page
2. Change **NVMe Driver** setting to **Supported**

#### Step 3: Create ECS Instance

Create a new ECS instance with the following specifications:
- **Region**: China (Beijing) - Zone L
- **Instance Type**: `ecs.gn8v-tee.4xlarge`
- **Image**: Select the imported confidential image

Once the instance is created and running, 0G Tapp service will start automatically.

### Deploying Applications on 0G Tapp

#### Starting an Application

Use the provided example script to deploy an application:

```bash
./start_app.sh --host HOST --port PORT --app-id APP_ID [OPTIONS]

# Example with owner credentials
export TAPP_OWNER_PRIVATE_KEY="0x..."
./start_app.sh --host your-cvm-instance-host --port 50051 --app-id my-nginx-app --use-owner

# Example with custom private key
./start_app.sh --host localhost --port 50051 --app-id my-app --private-key 0xabcd1234...
```

**Options:**
- `--host HOST`: gRPC server host (default: localhost)
- `--port PORT`: gRPC server port (default: 50051)
- `--app-id APP_ID`: Application ID (default: test-broker-app)
- `--private-key KEY`: Private key for signing (required unless using presets)
- `--compose-file FILE`: Docker compose file (default: examples/docker-compose.yml)
- `--use-owner`: Use pre-configured owner credentials (requires TAPP_OWNER_PRIVATE_KEY env var)
- `--use-whitelist`: Use pre-configured whitelist user credentials (requires TAPP_WHITELIST_PRIVATE_KEY env var)

**What happens:**
1. The script submits a StartApp request with Docker Compose configuration
2. Files referenced in volume mounts (e.g., `./config.yml:/app/config.yml`) are automatically uploaded. Paths that escape the compose directory (e.g., `../shared/config.yml`) are rejected with a clear error — copy such files into the compose directory and use a `./` path.
3. Returns a task ID for tracking deployment progress
4. The application deployment is cryptographically measured and extended to TEE runtime measurements

#### Stopping an Application

Stop and remove a deployed application:

```bash
./stop_app.sh --host HOST --port PORT --app-id APP_ID [OPTIONS]

# Example with owner credentials
export TAPP_OWNER_PRIVATE_KEY="0x..."
./stop_app.sh --host your-cvm-instance-host --port 50051 --app-id my-nginx-app --use-owner

# Example with custom private key
./stop_app.sh --host localhost --port 50051 --app-id my-app --private-key 0xabcd1234...
```

**Options:**
- `--host HOST`: gRPC server host (default: localhost)
- `--port PORT`: gRPC server port (default: 50051)
- `--app-id APP_ID`: Application ID to stop (required)
- `--private-key KEY`: Private key for signing (required unless using presets)
- `--use-owner`: Use pre-configured owner credentials
- `--use-whitelist`: Use pre-configured whitelist user credentials

## Security

### Security Model: Malicious Deployer Protection

0G Tapp implements a **"Malicious Deployer" security model**, which provides the strongest security guarantees in the TEE application platform space. Under this model:

- **Even the deployer cannot compromise the application**
- **Deployers can only interact with the TDX instance through restricted gRPC interfaces** - they cannot arbitrarily access the TDX instance
- Applications run in isolated TEE environments with cryptographic integrity
- Runtime measurements ensure that deployed code matches what was intended
- Private keys are bound to specific application measurements and cannot be extracted
- TEE hardware protections prevent unauthorized access to application memory and secrets

This means that once an application is deployed and measured:
1. The deployer cannot access application secrets or private keys
2. The deployer cannot modify the running application without detection
3. All application state and data remain confidential within the TEE
4. Remote attestation allows third parties to verify application integrity

This security model is ideal for scenarios requiring maximum trust minimization, such as:
- Trustless automated executor account
- Multi-party computation platforms
- Decentralized oracle networks
- Privacy-preserving data processing
- Trustless application execution

### Trusted Execution Environment

All applications run within TEE boundaries and are cryptographically measured. The runtime measurements are extended to the TEE event log for remote attestation.

Attestation evidence returned by `GetEvidence` binds the application's TEE-derived signer (an Ethereum address derived inside the enclave) into the TDX `report_data` field — the first 20 bytes of `report_data` equal the signer address, with the remaining bytes zero-padded. Verifiers can match this against the signer address registered on `TappRegistry` to prove that a signed message and the on-chain identity both come from the same app running on this TEE.

### Measurement Design Philosophy

0G Tapp implements a carefully designed measurement strategy that balances security auditability with operational efficiency:

#### What Gets Measured

**✅ Operations that execute within the TEE:**
- **Successful operations**: Application deployments, configuration changes, and lifecycle operations that complete successfully
- **Failed operations**: Operations that were permitted but failed during execution (e.g., Docker deployment failures, resource constraints)

All measurements include:
- Operation type (start_app, stop_app, etc.)
- Application configuration hashes (Docker Compose, mount files, image hash)
- Owner identity (EVM address)
- Execution result (success/failed) and error details
- Timestamp

**❌ What is NOT measured:**

- **Permission check failures**: Operations blocked by authentication or authorization layers
- **Pre-execution validation failures**: Requests rejected before entering the TEE execution context

#### Rationale

The key principle is: **Measure what the TEE cannot judge, but must record for accountability.**

**Why measure successful operations:**
- Creates an immutable audit trail of all applications deployed in the TEE
- Enables remote parties to verify exactly what code is running
- Binds cryptographic identities to specific deployments

**Why measure failed operations:**
- Failed operations represent actual execution attempts that consumed TEE resources
- Repeated failures may indicate attack probing or system misconfiguration
- Provides complete forensic history for security analysis
- Users should be accountable for what they attempted, not just what succeeded

**Why NOT measure permission denials:**
- These are policy enforcement actions that happen before TEE execution
- TAPP can definitively determine authorization - no ambiguity exists
- Recording every rejected request would create noise without security value
- The TEE didn't execute anything, so there's nothing to audit from a runtime perspective

**Example:**
- ❌ User tries to deploy without proper authentication → **Rejected, not measured** (TAPP policy enforcement)
- ✅ User deploys a Docker container that fails to start → **Measured as failure** (TEE executed, outcome uncertain)
- ✅ User deploys a malicious container that runs successfully → **Measured as success** (TEE cannot judge intent, only record what happened)

This design ensures that TEE measurements provide a complete, tamper-proof record of all operations that actually executed within the trusted environment, while avoiding unnecessary overhead from policy enforcement actions.

For more details, see the [Tapp documentation](https://0g-labs.notion.site/0G-Tapp-2bed6515e143809dbf54df5477fd3db4).

## Building from Source

```bash
# Clone repository
git clone https://github.com/0glabs/0g-tapp.git
cd 0g-tapp

# Build
cargo build --release

# Run
./target/release/tapp-service --config config.toml
```

## Configuration

Create a `config.toml` file:

```toml
[server]
host = "0.0.0.0"
port = 50051

[server.permission]
enabled = true
owner_address = "0xYourOwnerAddressHere"
initial_whitelist = [
    "0xYourWhitelistAddressHere"
]

[boot]
socket_path = "/var/run/docker.sock"

[logging]
level = "info"
path = "/var/log/tapp/"

# Optional: KMS cluster for hardware-independent app secrets
[kms]
cluster_urls = [
    "http://kms-node-1:8080",
    "http://kms-node-2:8080",
]

# Optional: on-chain TappRegistry integration
[chain]
rpc_url = "https://evmrpc-testnet.0g.ai"
contract_address = "0x..."
```

## On-chain Registration

Register your app and TEE nodes on the TappRegistry contract using `tapp-cli`. These commands require `--private-key` (the deployer's Ethereum private key) and `--server` (the tapp gRPC endpoint, used both as the gRPC target and as the on-chain `teeUrl`).

```bash
# Register a new app (fetches hashes and signerAddress from --server automatically)
tapp-cli -s http://<tapp>:50051 -k 0x<deployer-key> register-onchain \
  --app-id my-app \
  --rpc-url https://evmrpc-testnet.0g.ai \
  --contract 0x<TappRegistry> \
  --stake-wei 1000000000000000000

# Update app hashes after redeployment
tapp-cli -s http://<tapp>:50051 -k 0x<deployer-key> update-onchain \
  --app-id my-app \
  --rpc-url https://evmrpc-testnet.0g.ai \
  --contract 0x<TappRegistry>

# Add a new TEE node to an existing app
tapp-cli -s http://<new-node>:50051 -k 0x<deployer-key> add-node-onchain \
  --app-id my-app \
  --rpc-url https://evmrpc-testnet.0g.ai \
  --contract 0x<TappRegistry> \
  --stake-wei 1000000000000000000

# Remove a node (starts lock period). Pass --signer-address explicitly when the
# node is unreachable; otherwise it is fetched from --server automatically.
tapp-cli -s http://<node>:50051 -k 0x<deployer-key> remove-node-onchain \
  --app-id my-app \
  --rpc-url https://evmrpc-testnet.0g.ai \
  --contract 0x<TappRegistry>

# Re-key a node: replace its old signer with a new one atomically (stake transfers
# directly, no withdrawal needed). New signer is fetched from --server unless
# --new-signer is provided.
tapp-cli -s http://<node>:50051 -k 0x<deployer-key> update-node-onchain \
  --app-id my-app \
  --rpc-url https://evmrpc-testnet.0g.ai \
  --contract 0x<TappRegistry>

# Withdraw all matured stake entries belonging to the caller (across all apps).
# Run this after the lock period elapses on any node you removed.
tapp-cli -s http://<any-tapp>:50051 -k 0x<deployer-key> withdraw \
  --rpc-url https://evmrpc-testnet.0g.ai \
  --contract 0x<TappRegistry>
```

### Verifying an App

`tapp-cli verify-app` checks that what a node actually runs matches what is registered on-chain.

**Chain mode** (pass `--contract` + `--rpc-url`): reads the registry, fetches evidence from every node's on-chain `teeUrl`, verifies each TDX quote via the CoCo Attestation Service, and reconciles the evidence (signer, compose, volumes, image) against the chain.

```bash
tapp-cli verify-app \
  --app-id my-app \
  --rpc-url https://evmrpc-testnet.0g.ai \
  --contract 0x<TappRegistry>
  # --as-endpoint host:port   # CoCo-AS gRPC endpoint, default 47.237.201.184:50004
```

**Direct mode** (omit `--contract`, pass `-s <server>`): verifies a single node's evidence + quote and shows what it attests, without on-chain reconciliation — useful for apps not yet registered.

```bash
tapp-cli -s http://<tapp>:50051 verify-app --app-id my-app
```

List the apps a server is currently running (read-only, no key needed):

```bash
tapp-cli -s http://<tapp>:50051 list-apps
```

### Managing Ack Invalidators

User acknowledgements (acks) on TappRegistry are tied to an app's `ackVersion`, which bumps automatically on `updateApp` and node changes. When a sibling contract (e.g. a pricing or policy contract) needs to invalidate existing user acks without changing the app's code identity, the app owner can authorize that contract as an **invalidator**. Authorized invalidators may call `invalidateAcks(appId)` to bump the version. Both commands are app-owner-only and idempotent (no-op if the state already matches).

```bash
# Authorize a sibling contract to invalidate user acks for this app
tapp-cli -k 0x<owner-key> authorize-invalidator-onchain \
  --app-id my-app \
  --rpc-url https://evmrpc-testnet.0g.ai \
  --contract 0x<TappRegistry> \
  --invalidator 0x<SiblingContract>

# Revoke a previously-authorized invalidator
tapp-cli -k 0x<owner-key> revoke-invalidator-onchain \
  --app-id my-app \
  --rpc-url https://evmrpc-testnet.0g.ai \
  --contract 0x<TappRegistry> \
  --invalidator 0x<SiblingContract>
```

## KMS Integration

When `[kms]` is configured, apps running inside the TEE can retrieve a hardware-independent, KMS-derived secret via the `GetSecretResource` gRPC call. This call is **local access only** (localhost / same-host Docker network).

```bash
# From inside the TEE or a local container:
grpcurl -plaintext -d '{"app_id": "my-app"}' localhost:50051 tapp.TappService/GetSecretResource
```

The returned `secret` bytes are the HKDF-derived app key from the KMS cluster, decrypted inside the TEE. The KMS authenticates the request by verifying the TEE node's on-chain registered `signerAddress`.
