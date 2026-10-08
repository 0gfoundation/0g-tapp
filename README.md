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
- **Encrypted app data volumes**: Every app's persistent data lives in its own LUKS volume, keyed per-app by the KMS — encrypted at rest, isolated between apps, and portable across hosts and reboots
- **Confidential GPUs**: An opt-in build stage (`ENABLE_GPU=1`) adds the NVIDIA open driver and turns on GPU confidential-computing mode, and the resulting evidence carries a per-GPU attestation report bound to the same quote as the CPU's — see [`cvm/GPU.md`](cvm/GPU.md)

## Getting Started

### Prerequisites

- Alibaba Cloud account (for confidential computing instances)
- Docker and Docker Compose
- grpcurl (for testing)
- Rust toolchain (for building from source)

### Creating a Confidential Computing Instance

To run 0G Tapp, you need to create an Alibaba Cloud ECS instance with confidential computing support.

> **GCP (Intel TDX) variant**: To build a hardened, measured, attestable confidential image for Google Cloud from a stock Ubuntu 24.04 cloud image, see [`cvm/`](cvm/) — one-command build (`build-tapp.sh`), full SOP and root-cause notes in [`cvm/cryptpilot-gcp-boot-fix.md`](cvm/cryptpilot-gcp-boot-fix.md), and a security-hardening audit (removes SSH / cloud-init / google-guest-agent / metadata startup-scripts and other backdoor vectors).
>
> Because that audit removes the agent the cloud injects keys through, `gcloud compute ssh` and GCP's browser SSH do **not** work on a hardened image. For a dev image, build with `DEV_SSH_PUBKEY` to bake your own key instead (works on GCP, Alibaba Cloud and bare metal alike, and shows up in the measurement) — see [`cvm/README.md`](cvm/README.md#dev-ssh-access-cloud-independent).

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

Attach a data disk as well: `/data` holds the app volumes, the container stores and the logs,
and `tapp-server` does not start without it (the root filesystem is a RAM overlay, so writing
there would be lost on reboot). The node provisions a single blank attached disk by itself.

Ephemeral cloud scratch disks are excluded, so a GPU machine type — where the cloud attaches
local SSDs that cannot be declined — still provisions its one attached data disk by itself.

On a host with **more than one** spare disk, which is normal on bare metal, the node cannot tell
which one is meant to be `/data` and refuses to guess rather than risk formatting the wrong disk.
**Label the intended disk before attaching it**, on any machine with a shell:

```bash
mkfs.ext4 -L tapp-data <device>
```

The label is the whole contract: a disk carrying it is used directly, on that boot and every
later one, with no guessing. A disk that already holds an ext4 filesystem is adopted by
relabelling, never reformatted, so this is safe to run against a disk holding data. If several
disks should act as one, combine them first (LVM or RAID) and label the resulting volume.

When the node has to guess and cannot, it says so on the console — naming the disks it found and
the command above — so the cloud's serial log shows why a node is idle.

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

#### Where app data lives (encrypted volumes)

Each app gets its **own encrypted volume**: a LUKS2 image on the persistent data
disk, opened with a passphrase the KMS cluster derives per app (under the `fde`
material namespace) and mounted at the app's `data/` directory before its
containers start. The key is stored nowhere — any node registered on-chain for
the app re-derives the same key on demand, which is what lets data survive
reboots (a reboot wipes the kernel's key and locks the volume) and move between
hosts (copy the image file; the destination node derives the same key).

Encryption is what keeps the host from **reading** the data or **forging** it. It does not make
the volume tamper-evident, and it does not prove the volume is the **latest** state — a disk
from last month decrypts today with the same key and passes every check. An app for which
corrupted or stale data would be harmful has to handle that itself;
[`docs/DATA_AT_REST.md`](docs/DATA_AT_REST.md) sets out exactly which guarantees hold, why the
missing ones are hard, and what to do about them.

What the compose file writes decides what protects it:

| compose writes to | where it lives | encrypted | survives reboot |
|---|---|---|---|
| named volume (plainly declared) | auto-redirected into the encrypted volume | ✅ | ✅ |
| `./data/...` bind mount | encrypted volume, explicit path | ✅ | ✅ |
| other `./...` relative paths | RAM rootfs — fine for configs, wrong for state | – (never on disk) | ❌ |
| absolute paths | host disk, plaintext (warned) | ❌ | ✅ |
| `external:` / custom-driver volumes | wherever the user configured (warned) | ❌ | depends |

The first row is the important one: the standard compose idiom
(`pgdata:/var/lib/postgresql/data` plus a top-level `volumes: pgdata:`) is
encrypted **with no changes** — the server generates a
`docker-compose.override.yml` redirecting the volume into the encrypted mount.
The user's compose runs verbatim and its measured hash is untouched. Uploading
your own override file disables the redirect (loudly).

`start-app` returns any lint findings (data placed where the volume cannot
protect it, `docker.sock` mounts, `privileged`) and the CLI prints them; the
app still starts. One kind of mount is **refused** outright: a writable bind
mount reaching tapp-server's own state in `/run/tapp` — the directory itself,
anything above it (`/run`, `/`, `/var/run`), or a file in it other than the
socket. That is where the claimed owner, the trust anchors, the apps started this
boot and the scratch key live, read back on a process restart. Mount
`/run/tapp/tapp.sock` alone, or the directory read-only. On a KMS-configured node the start **fails** when the volume
key cannot be fetched — an app never silently runs on a plaintext directory.
The usual cause is ordering: the node must be registered on-chain for the app
first, which `start-app --register-onchain` handles.

`stop-app` stops containers and leaves the volume open (the key lives in
TEE-protected kernel memory; a closed volume would protect nothing an open one
doesn't). To migrate existing plaintext data in: `stop-app`, copy the data into
the still-mounted `data/` directory, `start-app`.

##### Choosing a different data mode (`x-tapp.data`, ≥0.8.0)

The encrypted volume is the default, not the only shape. An app declares its
`data/` mode at the top level of its compose (`x-` keys are ignored by docker,
and the declaration is part of the compose content — hashed, registered
on-chain and measured like everything else):

```yaml
x-tapp:
  data: plain   # encrypted (default) | plain | ram | scratch
services: ...
```

| mode | lives on | who can read it | after a reboot |
|---|---|---|---|
| `encrypted` (default) | data disk, LUKS, KMS key | TEE only | **still there** |
| `plain` | data disk, plaintext | whoever holds the disk | still there |
| `ram` | RAM rootfs | TEE only | gone |
| `scratch` | data disk, LUKS, per-boot key | TEE only | gone (key dies with the signer; volume is wiped and recreated) |

`plain` is for data that protects itself — the KMS's own TEE-sealed share is
the canonical case (and what breaks the KMS↔FDE bootstrap circle: a KMS node
cannot fetch its volume key from a cluster that hasn't formed yet). `scratch`
is disk-sized secret cache: too big for RAM, no need to outlive the boot.
Switching modes does **not** migrate data — the old volume or directory stays
where it was, and the app starts on an empty one; move data by hand. A typo'd
mode is refused at `start-app`, never silently mapped.

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

`GetEvidence` with an `app_id` answers for an app that was started this boot (running, or stopped since) and for one that is **being started**. The last is for the KMS's attested admission: before it releases an encrypted app's volume key, the KMS has the verifier check this node's evidence for the app, and the start is waiting for that key. Such evidence proves the app's signer is held in this TEE, not that the app runs — there is no `start_app` event for it yet, and reconciliation (verify-app, the scan) reads that event. A second `start-app` of an app that is being started is refused.

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
# Default is loopback (127.0.0.1:50051) — this port is plaintext. Remote
# management goes through the TLS listener below instead. Setting 0.0.0.0 here
# exposes remote *plaintext*: start-app payloads (compose, env, mounted files)
# become readable on the network path.
bind_address = "127.0.0.1:50051"

# The same gRPC service behind TLS. The key derives from the node's COMMON
# signer (per boot), and `get-evidence` with no app_id returns node evidence
# whose runtime_data.tls_public_key is this key's SPKI sha256 — so a client can
# bootstrap a pin from attested evidence over any channel:
#   tapp-cli -s https://<host>:50052 --insecure get-evidence   # verify quote,
#   tapp-cli -s https://<host>:50052 --tls-pin 0x<tls_public_key> …
# `--insecure` alone encrypts but defeats passive observers only. "" disables.
tls_bind_address = "0.0.0.0:50052"

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
# the app, needs [kbs] and the app registered on chain). See "App TLS certificates" above.
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
# The KMS cluster this node draws persistent secrets from (stable TLS keys,
# volume passphrases, app base secrets). Access is authorized by on-chain
# registration alone — see docs/KMS.md for the model, the derivation
# namespaces, and the trust-anchor configuration that goes with this.
[kbs]
node_urls = [
    "https://kms-node-1:9443",
    "https://kms-node-2:9443",
]
```

There is no `[chain]` section (an old one is ignored). A node is not tied to one
registry: every on-chain command takes `--rpc-url`/`--contract`, so the same node can
be registered on testnet and mainnet at once.

## Claiming Ownership (runtime owner claim)

CVM images are built **ownerless**: no owner is baked into the image, so a single
image (and a single set of boot-chain reference values) serves every owner. A
freshly booted tapp is UNCLAIMED — every owner-level RPC is rejected until someone
claims it:

```bash
tapp-cli -s http://<tapp>:50051 -k 0x<your-key> claim-config

# Or claim and configure in one call — KMS cluster and TLS key source are
# optional here if already present in config.toml:
tapp-cli -s http://<tapp>:50051 -k 0x<your-key> claim-config \
  --kbs-urls "https://kms-1:9443,https://kms-2:9443" \
  --tls-key-source kms \
  --scan-url https://scan.example \
  --scan-pubkey 0x<sha256 of the verifier's TLS key>
```

The values to put in `--kbs-urls` — the deployed KMS cluster endpoints for
mainnet and testnet, and the group public key that verifies you reached the
right one (**both networks use the app_id `0g-kms`, but they are two different
clusters with two different masters**) — are listed in
[`docs/KMS.md`](docs/KMS.md), which also explains why `--scan-url`/`--scan-pubkey`
must accompany a `kms` setup.

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
- **Restart-safe**: the claimed owner and the claimed config (KMS cluster, TLS key
  source, trust anchors, including later `update-trust-anchors`) are persisted under
  `/run` (tmpfs) — a tapp-server process restart cannot reopen the claim and resumes
  the node as claimed. What it reads back is measured again as a `claim_resumed`
  event, so a state file changed between two processes shows in the evidence:
  verify-app reports a different owner as inconsistent, different trust anchors
  as ✗, and a claimed config the restart found but could not read as ⚠️; a VM reboot
  clears both the state and the RTMRs, so a rebooted node is claimable (and
  re-measured) again. The apps started this boot are kept the same way
  (`/run/tapp/apps.json`), so a restarted process still serves their evidence, stops
  them and checks their owner. They are measured on resume as `apps_resumed`, and
  verify-app fails a node whose resumed state for the app is not the last one this
  boot measured for it, or the one before (which a process stopped between measuring
  a change and recording it leaves).
- **Hijack window**: practically closed — don't expose :50051 before claiming
  (cloud firewall), and claim right after boot. Even if raced, the intruder's
  address is indelibly measured, your own claim fails immediately (instant
  detection), and the box holds no secrets yet — delete and recreate.

Legacy mode: setting `owner_address` in `config.toml` still works (the owner is
claimed automatically at startup and also measured).

### Handing an app over to a new owner

Only the app's **registry** owner is transferable (TappRegistry >= 0.2.0). Machines
are not transferred — the new owner replaces them with its own.

1. **Transfer on chain**, in two steps so a mistyped address cannot strand the app
   (with no admin override, an app owned by an address nobody controls could never
   be updated, its nodes never removed, its stake never refunded):

   ```bash
   tapp-cli -k 0x<owner-key> transfer-app-ownership -a <app_id> -r <rpc> -c <registry> --new-owner 0x<new>
   tapp-cli -k 0x<new-key>   accept-app-ownership   -a <app_id> -r <rpc> -c <registry>
   ```

   Nothing changes until the nominee accepts; nominating again replaces the nominee,
   `--cancel` withdraws. Live nodes' stake travels with the app (`removeNode` refunds
   whoever owns the app at that moment); stake already locked by earlier `removeNode`
   calls stays with the address it was locked to. Acknowledgements are not
   invalidated — no code changed, and every change the new owner can make bumps the
   ack version.

2. **Replace every node** with a machine the new owner has claimed — on each one:

   ```bash
   tapp-cli -s <new-node> -k 0x<new-key> start-app -f docker-compose.yml -a <app_id> \
     --register-onchain --rpc-url <rpc> --contract <registry> --stake-wei <wei> \
     --tee-url https://<new-node>:50052 \
     [--old-signer 0x<node being replaced>]   # needed only when the app has several nodes
   ```

   Pass `--tee-url` here. Without it the replaced node's teeUrl is kept unless something
   else answers there, and the old machine's port is normally closed to the new owner
   (#141), so it would be kept — now pointing verifiers and the KMS at the old machine.

   The new signer replaces the old one in place (`updateNode`): one transaction, the
   stake carried over, no moment where the app has no node. It also orders things so
   an `encrypted` app works: the new signer is on chain before the node asks the KMS
   for its volume key.

**Until a node is replaced, its machine's owner can still obtain the app's KMS keys**
— the KMS authorizes by the on-chain node list — so replace promptly. The keys
themselves do not change: they derive from the app id, so the new nodes get the same
ones and an encrypted volume can be copied across. By the same token, anything
encrypted before the hand-over was readable by the previous owner.

### Request signing

Every signed RPC carries `x-signature` (EIP-191 `personal_sign`, 65-byte r‖s‖v),
`x-timestamp` and `x-signature-version: 2`, and signs

```
<Method>:0x<sha256 of the encoded protobuf request>:<unix timestamp>
```

— the hash is over the exact message bytes in the gRPC frame, which the server
hashes as received, so a request altered in flight no longer recovers to the
owner. Each signature is accepted **once** (replays are refused) within **±10
minutes** of its timestamp.

tapp-server >= 0.9.0 accepts **only** this form. The older `<Method>:<timestamp>`
message authorised the method with *any* body, so an observed signature could
carry a different request; it is refused (`AUTH_LEGACY_SIGNATURE_REFUSED`).

tapp-cli >= 0.9.0 signs this form. To manage a tapp-server < 0.9.0 (which reports
a body-bound signature as "Insufficient permission"), pass `--legacy-sign`. It is
never chosen automatically, since falling back on failure would hand anyone able
to make a request fail the weaker signature. The scripts under `examples/` sign
the body-bound form too (`sign_message.py` takes the request JSON).

### Signing with a key held elsewhere (`--external-signer`)

The owner key does not have to be on the machine running tapp-cli. A hardware wallet or an
MPC/multisig custodian (Fordefi, for one) looks like an ordinary address from outside and
returns ordinary signatures, so the server and the registry need nothing different. Pass the
signer's address instead of `-k`:

```bash
tapp-cli -s https://<node>:50052 --tls-pin 0x<pin> \
  --external-signer 0x<owner address> start-app -f docker-compose.yml -a my-app
```

(or set `TAPP_EXTERNAL_SIGNER`). Every command that would sign then stops and asks:

- **a request signature**: the CLI prints the one line of text above (`<Method>:0x<hash>:<ts>`).
  Sign it as a *message* (`personal_sign`), for example in Fordefi's message signing, and
  paste the 65-byte signature back. The CLI checks that it recovers to the given address
  before sending, and asks again if it does not. It has to come back within the server's
  ±10-minute window; the prompt shows the deadline.
- **an on-chain call**: the CLI prints the transaction — chain, from, contract, value, data,
  and which registry function it is. Send it from the owner address, for example as a
  contract call in Fordefi, and paste its hash back. The CLI waits for it to be mined and
  checks that it is that transaction from that address and that it succeeded, then goes on.

So multi-step commands such as `start-app --register-onchain` run to the end, with one
prompt per signature and per transaction. The signer sees a hash, not the compose: what it
approves is "this exact request", and the request is what this CLI run built.

#### With a Ledger: `--ledger`

Add `--ledger` and tapp-cli drives a Ledger on this machine's USB instead of prompting:

```bash
tapp-cli --external-signer 0x<the Ledger address> --ledger start-app -f docker-compose.yml -a my-app ...
```

- The account is found **by the address**: the first ten accounts of each path style (Ledger
  Live, BIP44 standard as MetaMask offers it, and legacy MEW/MyCrypto) are searched, so there
  is no derivation index to get wrong.
- A message shows on the device as text; approve it if it matches what the CLI printed.
- A transaction is **signed only**. tapp-cli checks the signed transaction (signer, chain,
  contract, data, value) and broadcasts it itself, so a wrong one never reaches the chain.
  A registry call is contract data, which the Ethereum app signs only with **Blind
  signing** enabled in its settings.
- Keep the device unlocked with the Ethereum app open, and **close Ledger Live** (only one
  program can use the device at a time).

Ledger support is built in on **macOS**, through the system's own USB (IOKit) with nothing
else to install: install Rust and protobuf (`brew install protobuf`), then `cargo build
--release -p tapp-cli`. The release binaries are built for Linux without it. On Linux, build
with `--features ledger` (libusb; non-root access needs Ledger's udev rules).

## On-chain Registration

Register your app and TEE nodes on the TappRegistry contract using `tapp-cli`. These commands require `--private-key` (the deployer's Ethereum private key), or `--external-signer` for a key held elsewhere (see above), and `--server` (the tapp gRPC endpoint).

The node's on-chain `teeUrl` — where the scan and `verify-app` fetch its evidence — is `--tee-url` when given. Otherwise a node already on chain **keeps its recorded `teeUrl`**: a DNS name, front or private address was someone's choice, and a run from wherever the operator happens to be must not move it. A **replacement** asks the replaced slot's `teeUrl` for the app's signer. If *this* node answers (the restart case), the URL is kept. If another signer answers, or something answers that is not a tapp-server naming this node, the replacement gets a URL derived from `--server` instead, and says so. If nothing answers — a VPC-private URL seen from outside, a dead machine, or the old machine on a hand-over — the URL is kept with a warning, so those replacements need `--tee-url`. The one automatic move is the legacy `http://<host>:50051` → `https://<host>:50052` when the node serves the TLS listener (tapp-server ≥ 0.8.0). A **new** record is derived from `--server`: `https://` as given, `http://` → `https://<host>:50052`; a `--server` reached locally (`127.0.0.1`, a socket) cannot be derived from, so a new record then needs `--tee-url`. Every change is printed. `:50051` is meant to stay closed to everyone but the node (#141). `--tee-url` takes a DNS name, a TLS front, or a **private address** — a node in the scan's VPC can register `https://10.x.x.x:50052`, which only the scan reaches; everyone else verifies it through the scan relay. To move a node's `teeUrl`, pass `--tee-url` to `start-app --register-onchain` or `update-node-onchain` (signer unchanged, nothing else touched).

### Register during start (recommended)

`start-app --register-onchain` brings the chain in line with this deployment
BEFORE its containers start — one command for a first deploy, a restart, a
machine replacement and an upgrade. The server pulls the images and computes all
hashes first (measure-only), the CLI submits what the chain needs, and only after
it confirms are the containers started (so a node whose volume key comes from the
KMS is on the node list when it asks). Safe to re-run; it writes nothing when the
chain already matches.

**Each node's record says what that node runs.** A deployment rewrites only this
node's compose and mount files — stored as the node's own override where they
differ from the app's default — and never another node's. So every node can be
checked against its own record at any moment, including half-way through a
rolling upgrade, and nodes that legitimately differ (each KMS node has its own
`kms.toml`) need nothing special.

The app-level declaration is the default for new nodes. Its code (compose and
images) follows the deployment only in a **single-node** app, where the two are the
same thing; in a multi-node app it moves with an explicit `update-onchain` once every
node runs the new code. Mount files never move the app default — a node whose files
differ always records them as its own override.
Images are the one exception to "per node": the registry keeps them per app only,
so new images on one node of several are reported, not written — pin images by
digest in the compose file and the compose hash covers them per node.

The signer:
  - app not registered → `registerApp` (this node becomes the first node)
  - signer already a node → its record is corrected if needed, otherwise nothing
  - signer absent, exactly one other node → `updateNode`, **replacing** it (a
    restart re-derives the signer, so the address on chain is a dead instance)
  - signer absent, several other nodes → `addNode`; pass `--old-signer` to replace
    a specific one instead
  - `--add-node` → `addNode` regardless: how a one-node app scales out to two
  - **Apps whose external contracts key on the signer** (0g-sandbox's vouchers, for
    one) should restart with `--add-node`, let the old signer's obligations settle,
    then `remove-node-onchain` it. A one-step replacement skips that settling.

Rewriting a node's record goes through `updateNode`, which also resets the node's
on-chain `addedAt` to that block. Nothing in tapp reads it, but it means "when this
record was last written", not "when this machine joined".

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

# Set the app-level declaration (the default for new nodes) to what this node
# runs — e.g. after every node of a multi-node app has been upgraded
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

`tapp-cli verify-app` checks that what a node actually runs is what was published and
registered — the same checks tappscan makes, made here on your machine:

- **Quote, TCB, event-log replay** — the AS (`--as-endpoint`) verifies the quote's signature
  chain to Intel, reports TCB, and replays the event log against the signed RTMRs. This is
  what the AS is trusted for, and all it is trusted for.
- **Boot chain → published reference values**, compared locally against the AS's signed
  token: `boot chain : ✓ gcp/uki/v0.8.0/dev` names the image. The values are the published
  ones, `0gfoundation/0g-tapp@dev:verifier/reference-values` (pinned to the commit the ref
  resolves to, cached per commit; `GITHUB_TOKEN` is honoured), or a directory given with
  `--reference-values`. No match prints the measured digests in reference-value JSON
  (`{"measurement.<shim|grub|kernel|initrd|kernel_cmdline|uki>.SHA-384": [...]}`), ready to
  publish, and the closest published set. A newly published image needs nothing registered
  anywhere. `--policy-ids` additionally shows an AS policy's own verdict.
- **`--contract` + `--rpc-url` → the registry**: reconciles the runtime events against it —
  signer, compose, volumes, image, and **owner** (the `claim_config` event's owner vs the
  on-chain app owner) → `signer✓ compose✓ volumes✓ image✓ owner✓`. Without `--contract`
  (direct mode) it prints owner / compose / images as attested.

Both modes also print `tls key : <sha256>  (sha256 of the public key, attested)` when the app
has a TLS key, followed by the `openssl s_client | … | openssl dgst -sha256` one-liner for
comparing it against a live endpoint — that comparison is what ties a TLS connection to the
node just verified. The line is absent when the app has never asked for a key, which is not a
failure.

```bash
# full verification: registry + published reference values
tapp-cli verify-app \
  --app-id my-app \
  --rpc-url https://evmrpc-testnet.0g.ai \
  --contract 0x<TappRegistry>
  # --reference-values <dir>         # pinned/offline values instead of the published ones
  # --as-endpoint https://host:port  # CoCo-AS gRPC; TLS now, so give the scheme
  # --as-pubkey 0x<sha256>           # pin the AS's TLS key (or TAPP_AS_PUBKEY); current value in docs/TAPPSCAN.md

# direct mode (single node, not yet registered): prints attested values verbatim
tapp-cli -s http://<tapp>:50051 verify-app --app-id my-app
```

**Nodes whose port is closed to you** (open only to the scan and their operators) are
reached through the scan relay of their registry, automatically — `evidence : the node did
not answer here; relayed by …`. That is transport only: the evidence is checked exactly as
if fetched directly, and the quote must echo the random challenge sent for it
(`fresh : ✓`). An old quote is genuine too, so passing one off as new is the one thing a
relay could do, and the echo is what rules it out; a quote echoing a different challenge
fails whichever way it came. `docs/verify_app.py` does all of the above the same way.

The AS is trusted for the quote, so **pin it** (`--as-pubkey`, or `TAPP_AS_PUBKEY` once;
the current value is in [`docs/TAPPSCAN.md`](docs/TAPPSCAN.md)). Unpinned, anyone on the
path could forge every verdict: verify-app warns and never reports better than ⚠️. A
**dev** image's boot chain is reported ⚠️, not ✅ — dev builds can carry an SSH key into
the TD — and on **mainnet** (chain 16661) it fails, as it does in the scan's verdict and so
at the KMS. "✅" means the boot chain matches a published image's digests; firmware
(MRTD/RTMR0) is not compared yet. verify-app **exits non-zero** on a reconcile FAIL or an
unpublished image, so scripts and CI can use it: **0** everything checked and clean, **1** a
failure, **2** passed with a warning (unpinned AS, dev image off mainnet, a TCB trailing Intel's
latest, reference values unavailable).

The **platform** line reads the TD itself out of the AS token, as the AS policy used to:
a TD launched with **DEBUG** fails whatever else passes (its host can read and write its
memory — on bare metal the operator launches the TD), and so does a revoked TCB. A TCB
that merely trails Intel's latest (`OutOfDate`, `SWHardeningNeeded`, …) warns: clouds
roll firmware out behind Intel, and the outstanding advisories are listed.

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
