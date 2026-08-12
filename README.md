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
- **Attested TLS**: Hand an app a TLS certificate whose public key is committed to by the attestation evidence, so a client can tie the connection it made to the TEE it verified

## Getting Started

### Prerequisites

- Alibaba Cloud account (for confidential computing instances)
- Docker and Docker Compose
- grpcurl (for testing)
- Rust toolchain (for building from source)

### Creating a Confidential Computing Instance

To run 0G Tapp, you need to create an Alibaba Cloud ECS instance with confidential computing support.

> **GCP (Intel TDX) variant**: To build a hardened, measured, attestable confidential image for Google Cloud from a stock Ubuntu 24.04 cloud image, see [`cvm/`](cvm/) — one-command build (`build-tapp.sh`), full SOP and root-cause notes in [`cvm/cryptpilot-gcp-boot-fix.md`](cvm/cryptpilot-gcp-boot-fix.md), and a security-hardening audit (removes SSH / cloud-init / google-guest-agent / metadata startup-scripts and other backdoor vectors).

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

Attestation evidence returned by `GetEvidence` commits the application's TEE-derived identity into the TDX `report_data` field. `report_data` is `sha512` of a small JSON object — `runtime_data` — that travels as a third field of the evidence alongside `quote` and `cc_eventlog`:

```json
{"nonce": "0x…", "signer": "0x…", "tls_public_key": "0x…"}
```

| field | meaning |
|---|---|
| `nonce` | Caller-supplied challenge, echoed back. A quote is self-authenticating but undated, so without a challenge a cached quote is indistinguishable from a fresh one. Pass `get-evidence --nonce <hex>` (≤64 bytes, must be random). |
| `signer` | The Ethereum address derived inside the enclave — the identity `TappRegistry` records. Verifiers match it against the registered `signerAddress` to prove a signed message and the on-chain identity come from the same app on this TEE. |
| `tls_public_key` | sha256 of the app's TLS SubjectPublicKeyInfo, when it has one. This is what lets a client tie the certificate it was handed during a TLS handshake to a TEE running this app. |

Empty fields are omitted rather than serialised as `""`, so evidence produced before a field existed and after it are byte-identical whenever the field is unused. Two consequences for verifiers:

- **A quote alone no longer names its signer** — the structure must accompany it. Nothing in the system passes a bare quote.
- **Hash the bytes exactly as transmitted.** Never re-serialise: there is then no canonical form for the two sides to agree on and drift apart over.

`sha512` is not arbitrary — `report_data` is 64 bytes and `sha512` fills it exactly, which is also what CoCo-AS expects when handed `runtime_data` and asked to check the binding itself.

Evidence from servers before v0.4.0 has no `runtime_data` field and a `report_data` whose first 20 bytes are the signer, zero-padded. Both readings are supported (`tapp-common/src/report_data.rs`, `tapp-common/src/verify.rs`); a missing field is reported as such rather than as a signer mismatch.

### App TLS certificates

`GetAppTlsCert` hands an application the two files a TLS server wants — `key_pem` and `cert_pem` (P-256) — plus a `csr_pem` for reissuing elsewhere and `public_key_sha256`. The certificate is self-signed unless `ca_url` is configured.

`GetAppCsr` returns a signing request for a domain of your choosing, so a public CA can certify the same key. It is **public** — a signing request carries a public key, a name and a proof of possession, all of which the resulting certificate publishes anyway — so it needs neither the socket nor a key, and the app need not exist yet. The two certificates are not alternatives: one key can carry both, and then a browser checking the CA's name and a verifier checking the attested key both pass on the same endpoint.

**To actually serve HTTPS from an app, see [`docs/APP_TLS.md`](docs/APP_TLS.md)** — a copyable compose file that works with an unmodified `nginx` or `envoy`. A sidecar (the `tls-init` sidecar) fetches the certificate into a shared volume and exits, so the application reads two ordinary PEM files and never speaks gRPC.

What makes it trustworthy is the binding, not the issuer: `public_key_sha256` is the value `report_data` commits to, so a client compares the key it was offered during the handshake against attested evidence. A self-signed certificate is not weaker for a client that performs that check — the issuer matters only to clients that will not, such as browsers driving off a system trust store. That is the one thing a CA adds.

`[server].tls_key_source` decides where the private key comes from, and the two options trade the same property in opposite directions:

| | derived from | survives a restart | what evidence then says |
|---|---|---|---|
| `local` (default) | this CVM's own signer, which never leaves it | **no** — the signer is regenerated every boot | "the endpoint I am talking to is *this TEE instance*" — the strongest statement available |
| `kms` | `(app_id, "tls")` at the KMS cluster | yes, and identical on every node of the app | "some TEE of this app" |

Certificate pinning, Certificate Transparency monitoring and ACME renewal all need a key that outlives a restart, so they need `kms`. `local` involves nothing external — no KMS, no on-chain registration — so it works from first boot, which is why it is the default; stability is what you opt into once something needs it. Set it in `config.toml` or at claim time with `claim-config --tls-key-source local|kms`.

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
bind_address = "0.0.0.0:50051"

# Recommended. Listened on IN ADDITION to bind_address, and the only transport that
# serves key material (GetAppSecretKey / GetSecretResource / GetAppTlsCert).
unix_socket_path = "/run/tapp/tapp.sock"

# Who may open it. 0600 admitted only root, which forced every app that fetches key
# material to run its container as root and give up real hardening for nothing — the
# socket's protection was never the file mode, since anything it is mounted into can
# read every app's keys. A container now keeps a non-root user and adds this group:
#   user: appuser
#   group_add: ["0"]
unix_socket_mode = "0660"
# unix_socket_gid = 1000      # a dedicated group instead of root

# Where app TLS private keys come from: "local" (default, bound to this instance,
# changes every boot) or "kms" (stable across restarts and shared by every node of
# the app, needs [kbs] and [chain]). See "App TLS certificates" above.
tls_key_source = "local"

# Optional CA for app TLS certificates. Unset, GetAppTlsCert self-signs — which is
# enough for any client that checks the public key against the attestation.
# ca_url = "http://ca:8080"

[server.permission]
enabled = true
# Owner is OPTIONAL: leave it unset and the tapp boots UNCLAIMED — the first
# valid signer of `tapp-cli claim-config` becomes the owner, recorded as a
# measured claim_config runtime event (keeps the CVM image owner-independent;
# one image = one set of reference values for every owner).
# Setting it here is the legacy baked-in mode and still works:
# owner_address = "0xYourOwnerAddressHere"
#
# Whitelist: use `tapp-cli add-to-whitelist` after claiming (each change is a
# measured runtime event). The old initial_whitelist config was removed.

[boot]
socket_path = "/var/run/docker.sock"

[logging]
level = "info"
format = "pretty"              # "json" or "pretty"
file_path = "/var/log/tapp/"   # daily-rotated files; on RAM-rootfs CVM images use the persistent disk, e.g. /data/log/tapp/
max_log_files = 7              # rotated daily files to keep; oldest deleted at startup and rotation (default: 7)

# Optional: KMS cluster for hardware-independent app secrets
[kbs]
node_urls = [
    "http://kms-node-1:9091",
    "http://kms-node-2:9091",
]

# Optional: on-chain TappRegistry integration
[chain]
rpc_url = "https://evmrpc-testnet.0g.ai"
contract_address = "0x..."
```

## Claiming Ownership (runtime owner claim)

CVM images are built **ownerless**: no owner is baked into the image, so a single
image (and a single set of boot-chain reference values) serves every owner. A
freshly booted tapp is UNCLAIMED — every owner-level RPC is rejected until someone
claims it:

```bash
tapp-cli -s http://<tapp>:50051 -k 0x<your-key> claim-config

# Or claim and configure in one call — chain, KMS cluster and TLS key source are
# all optional here if already present in config.toml:
tapp-cli -s http://<tapp>:50051 -k 0x<your-key> claim-config \
  --chain-rpc-url https://evmrpc-testnet.0g.ai \
  --chain-contract 0x<TappRegistry> \
  --kbs-urls "https://kms-1:9443,https://kms-2:9443" \
  --tls-key-source kms \
  --scan-url https://scan.example \
  --scan-pubkey 0x<sha256 of the verifier's TLS key>
```

### Trust anchors

Which KMS cluster a tapp draws key material from, and which verifier it believes about that
cluster's identity, can be changed after the claim — owner-only, and every change is extended
into the runtime measurement carrying the resulting anchors in full:

```bash
tapp-cli -s http://<tapp>:50051 -k 0x<owner-key> update-trust-anchors \
  --kbs-urls "https://kms-1:9443,https://kms-2:9443" \
  --scan-url https://scan.example --scan-pubkey 0x<sha256>
```

Mutable because a verifier serves TLS with a `local` key, re-derived at every one of its boots:
fixing the pin at claim time would mean one verifier restart invalidates every tapp at once and
the fleet has to be re-claimed. Measured because the event log is append-only, so a node that was
ever pointed at a counterfeit verifier cannot hide it — that is what makes runtime mutability
acceptable rather than a regression.

Omitted values are left alone. `--scan-url` must be https and must come with `--scan-pubkey`: a
URL without a pin is an unauthenticated channel carrying a verdict, which is worse than having no
verifier configured, because the answer would be trusted and is rewritable by anyone on the path.

### KMS node identity is verified

Before fetching key material the server pins the verifier against `--scan-pubkey`, asks it which
TLS keys the KMS app's nodes currently attest, and pins the KMS node against that set. The
certificates are self-signed and that is correct: what is checked is the public key the node's
attestation committed to, not an issuer — so this **replaces** certificate-authority validation
rather than adding to it.

The same check with ordinary tools, which is the point of publishing the set in curl's format:

```bash
curl -k --pinnedpubkey "$(curl -sk https://scan.example/api/apps/0g-kms/cert)" \
     https://<kms-node>:9443/peers
```

`-k` and `--pinnedpubkey` go together: `-k` turns off the CA check that a self-signed certificate
can never pass, leaving the pin as the real one. Either alone is useless — `-k` verifies nothing,
and `--pinnedpubkey` on its own stops at the CA error.

**No path degrades to unverified.** The set is cached so the verifier is not a hard dependency of
every fetch, but with no cache and no answer the server refuses rather than connecting blind:
falling back would let an attacker disable the check by taking the verifier offline. A pin
mismatch triggers one refresh — a node that rebooted has legitimately re-derived its key — and
then rejects.

Configure no verifier and the check does not happen, which is logged loudly at startup. That is
the weaker mode, kept possible because a tapp that has never been told which verifier to believe
cannot invent one.

- **First-come-first-served, exactly once per boot**: the request signer becomes
  the owner; later claims fail with the current owner. The CLI verifies the
  result end-to-end (server must report your address back as the live owner).
- **Measured**: the claim is extended into the runtime measurement as a
  `claim_config` event (same mechanism as `start_app`), so verifiers see WHO owns
  the node in the attestation evidence and can reconcile it with the on-chain
  registration — the owner moved from the golden values into the runtime event log.
- **Restart-safe**: the claimed owner is persisted under `/run` (tmpfs) — a
  tapp-server process restart cannot reopen the claim; a VM reboot clears both
  the state and the RTMRs, so a rebooted node is claimable (and re-measured) again.
- **Hijack window**: practically closed — don't expose :50051 before claiming
  (cloud firewall), and claim right after boot. Even if raced, the intruder's
  address is indelibly measured, your own claim fails immediately (instant
  detection), and the box holds no secrets yet — delete and recreate.

Legacy mode: setting `owner_address` in `config.toml` still works (the owner is
claimed automatically at startup and also measured).

## On-chain Registration

Register your app and TEE nodes on the TappRegistry contract using `tapp-cli`. These commands require `--private-key` (the deployer's Ethereum private key) and `--server` (the tapp gRPC endpoint, used both as the gRPC target and as the on-chain `teeUrl`).

### Register during start (recommended)

`start-app --register-onchain` idempotently registers the app BEFORE its
containers start: the server pulls the images and computes all hashes first
(measure-only), the CLI submits the transaction, and only after it confirms are
the containers started. Safe to re-run:

- app not registered on-chain → `registerApp` (this node becomes the first node)
- registered, but this node's signer not in the node list → `addNode`
- signer already a node → skip registration, just start

```bash
tapp-cli -s http://<tapp>:50051 -k 0x<deployer-key> start-app \
  -f docker-compose.yml --app-id my-app \
  --register-onchain \
  --rpc-url https://evmrpc-testnet.0g.ai \
  --contract 0x<TappRegistry> \
  --stake-wei 1000000000000000000
```

Without `--register-onchain`, `start-app` behaves exactly as before (no chain
interaction). The standalone commands below remain for registering an app that
is already running:

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

`tapp-cli verify-app` checks that what a node actually runs matches its reference values.
Two independent axes select which references are enforced:

- **`--contract` + `--rpc-url` → dynamic references** (on-chain): reconciles the runtime
  events against the registry — signer, compose, volumes, image, and **owner** (the
  `claim_config` event's owner vs the on-chain app owner) → `signer✓ compose✓ volumes✓ image✓ owner✓`.
- **`--policy-ids` → static references** (AS-registered boot-chain values): the AS enforces
  the policy and returns the AR4SI executables claim → `boot-chain ✓ (executables=3)`.

Whichever axis has NO reference supplied, verify-app prints that side's **measured values
verbatim** so you can compare manually:
- no `--contract` → prints owner / compose / images as attested;
- no `--policy-ids` → prints the boot-chain component digests in reference-value JSON
  (`{"measurement.<shim|grub|kernel|initrd|kernel_cmdline|uki>.SHA-384": [...]}`), directly
  diffable against `verifier/reference-values/<cloud>/<boot_format>/<version>/<env>.json`.

Both modes also print `tls key : <sha256>  (sha256 of the public key, attested)` when the app
has a TLS key, followed by the `openssl s_client | … | openssl dgst -sha256` one-liner for
comparing it against a live endpoint — that comparison is what ties a TLS connection to the
node just verified. The line is absent when the app has never asked for a key, which is not a
failure.

```bash
# full verification: dynamic (chain) + static (policy)
tapp-cli verify-app \
  --app-id my-app \
  --rpc-url https://evmrpc-testnet.0g.ai \
  --contract 0x<TappRegistry> \
  --policy-ids 0g-tapp-<cloud>-<boot_format>-<version>-<env>
  # --as-endpoint https://host:port  # CoCo-AS gRPC; TLS now, so give the scheme
  # --as-pubkey 0x<sha256>           # pin the AS's attested TLS key

# direct mode (single node, not yet registered): prints attested values verbatim
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

When `[kbs]` is configured, apps running inside the TEE can retrieve a hardware-independent, KMS-derived secret via the `GetSecretResource` gRPC call.

### Key material is served only on the Unix socket

Three RPCs hand over private key material — `GetAppSecretKey`, `GetSecretResource` and `GetAppTlsCert` — and from v0.4.0 they are reachable **only over the Unix socket**. Over TCP they are refused with `PermissionDenied`, including from `localhost` and from a container using `host.docker.internal:host-gateway`.

The check is the transport answering rather than a judgement about an address: tonic records connect-info per listener, and a TCP connection always carries a peer address while a Unix one never does. Before v0.4.0 this was an address check that accepted the Docker bridge ranges, which meant any host that could reach `:50051` could fetch any app's private key.

Set `unix_socket_path` in the server config. The server listens on the socket **in addition to** the TCP `bind_address` (not instead of it), so management, `teeUrl` and `verify-app` keep working over TCP while key material does not travel that way at all.

```toml
[server]
unix_socket_path = "/run/tapp/tapp.sock"
```

```yaml
# docker-compose.yml for the app container
services:
  app:
    volumes:
      - /run/tapp/tapp.sock:/run/tapp/tapp.sock
```

```bash
# From inside the container or on the host — no signature needed, the socket is the authorization:
grpcurl -unix -plaintext -d '{"app_id": "my-app"}' /run/tapp/tapp.sock tapp_service.TappService/GetSecretResource
grpcurl -unix -plaintext -d '{"app_id": "my-app"}' /run/tapp/tapp.sock tapp_service.TappService/GetAppTlsCert
```

> **⚠️ Security note:** The Unix socket grants access to all app keys and secret
> resources on the server — any process that can open the socket can request any
> app's secrets. This is safe in the standard deployment model (one tapp = one
> owner, single trust domain) but must not be bind-mounted into untrusted or
> multi-tenant containers.

> **⚠️ Upgrading a node to v0.4.0:** any app still fetching key material over
> `host.docker.internal:50051` stops working. Add the socket mount to its compose
> before upgrading the server.

The returned `secret` bytes are the HKDF-derived app key from the KMS cluster, decrypted inside the TEE. The KMS authenticates the request by verifying the TEE node's on-chain registered `signerAddress` — so an app must be registered on chain, and shortly after a fresh registration the cluster may still answer `401` until its own view of the chain catches up ([0g-kms#11](https://github.com/0gfoundation/0g-kms/issues/11)).

### Remote / TCP access

The server always listens on `bind_address` (default `0.0.0.0:50051`) for remote clients — management, the on-chain `teeUrl`, `verify-app`. The Unix socket above is additional, not a replacement. Everything except the three key-material RPCs works over either.

### Derivation material (per-caller keys)

`GetSecretResourceRequest` takes an optional `material` field — hex-encoded derivation material, opaque to tapp and forwarded verbatim to the KMS `/app-key` endpoint, which binds it into the derived key alongside `app_id`. This lets an app derive many independent keys from the KMS (e.g. AgenticID derives per-agent seal keys with `material = chainId ‖ contractAddress ‖ sealId`) instead of holding one app-wide secret and deriving locally. The KMS DPRF is one-way: per-material keys expose neither each other nor the app-wide key.

```bash
grpcurl -unix -plaintext \
  -d '{"app_id": "my-app", "material": "deadbeef01"}' \
  /run/tapp/tapp.sock tapp_service.TappService/GetSecretResource
```

Absent/empty `material` derives purely from the `app_id` namespace — byte-identical to the pre-material request, so existing callers and older KMS nodes are unaffected.
