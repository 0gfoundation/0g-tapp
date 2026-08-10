---
name: 0g-tapp-cli
description: Use this skill when the user wants to deploy, manage, or troubleshoot applications on a 0G Tapp (Trusted Application Platform) server using tapp-cli. Covers start/stop apps, on-chain registration, registry login, check task status, view logs, and manage docker compose deployments across multiple remote TEE servers.
version: 1.8.0
author: 0G Labs
tags: [0g, tapp, tee, docker, deployment, cli, onchain]
---

# 0G Tapp CLI Skill

Deploy and manage containerized applications on 0G Tapp TEE servers using `tapp-cli`, including on-chain registration in TappRegistry.

## Environment

- **tapp-cli binary**: `/usr/local/bin/tapp-cli`
- **Server**: `-s <url>` (e.g. `http://<host>:50051`). There are MANY tapp servers; always pass `-s` explicitly.
- **Auth**: private key via `-k` flag or `TAPP_PRIVATE_KEY` env var. Read-only commands (`get-tapp-info`, `get-service-status`, `get-app-info`, `get-app-key`, `get-evidence`, `list-apps`, `verify-app` direct mode) work without `-k`; owner-only commands require it.
- **TappRegistry (testnet)**: proxy `0x2Ce80374318B1d7Fb3345724457a182E0ad165c9`, RPC `https://evmrpc-testnet.0g.ai`, chainId `16602`. See `contract/CONTRACTS.md`.
  - An older deployment `0x95a0BF4148b30F6F8D86870534c51df46Da5511c` is **superseded** — no `version()`, and `getNode` returns 3 fields instead of 5. Some long-lived apps (testnet sandbox provider / attestor) are still registered there, so you may still have to query it; just don't put anything new on it. Tell them apart with `cast call <proxy> "version()(string)"` — `"0.1.0"` = current, revert = old.
- **Short flags**: `-s` = `--server` and `-k` = `--private-key` (both global). The earlier `-s` collision is **fixed** — the formerly-clashing subcommand flags (`--stake-wei`, `--service`, `--service-name`, `--signature`, `--chain-id`) are long-only now, so `-s` always means `--server`.

## Keys & servers — read this first

Each server has an **owner** address. From tapp-server v0.3.0, canonical images boot **UNCLAIMED** — owner-level RPCs are rejected until someone calls `claim-config`.

- **Unclaimed server**: `get-tapp-info` shows empty Owner. Must run `claim-config` first before any owner-level op.
- **Server ops** (start/stop/login/get-*): key must be the **server owner** (or whitelisted). Wrong key → `PermissionDenied`.
- **On-chain** (`register-onchain` etc.): the SAME `--private-key` is used to BOTH auth the `--server` AND sign+pay the tx. So it must satisfy **three things at once**: server-authorized + the app's on-chain owner + funded (stake + gas). If they can't be the same address, do the on-chain part with raw `cast send` (see below) using the funded owner key, bypassing `--server`.
- **Find a server's owner**: `tapp-cli -s <server> get-tapp-info` (read-only; prints `Owner Address`, empty = unclaimed). Then match the key whose address equals it.
- Convert a key → address: `docker run --rm --entrypoint cast ghcr.io/foundry-rs/foundry:latest wallet address 0x<key>`, or if you have `cast` installed locally: `cast wallet address 0x<key>`.

Record which key maps to which server/owner in memory — it changes per deployment.

## Core Commands

```bash
tapp-cli -s <server> -k 0x<key> docker-login -r <registry-host> -u <user> -p <password>
tapp-cli -s <server> -k 0x<key> start-app -f docker-compose.yaml --app-id <id>   # async → task-id
tapp-cli -s <server> -k 0x<key> start-app -f <compose> --app-id <id> \
  --register-onchain --rpc-url <rpc> --contract 0x<reg> --stake-wei 1000000000000000000
  # ↑ idempotent register-BEFORE-start: pulls+measures first, tx confirms, THEN containers start.
  #   not registered→registerApp; signer already a node→skip; signer absent + exactly ONE other
  #   node→updateNode REPLACING it (a restart re-derives the signer, so the on-chain one is a
  #   dead instance); signer absent + several others→addNode, since which one died is unknowable
  #   — pass --old-signer 0x<addr> to say. A stated --old-signer that is not a node is an ERROR,
  #   never a silent fallback to addNode.
  #   Requires a server with measure_only support; older servers → CLI aborts ("Server did not return measurements").
tapp-cli -s <server> -k 0x<key> get-task-status --task-id <task-id>
tapp-cli -s <server> -k 0x<key> stop-app --app-id <id>
tapp-cli -s <server> -k 0x<key> stop-service  --app-id <id> --service-name <svc>  # flag is --service-name
tapp-cli -s <server> -k 0x<key> start-service --app-id <id> --service-name <svc>
tapp-cli -s <server> -k 0x<key> get-app-container-status --app-id <id>
tapp-cli -s <server> -k 0x<key> get-app-info --app-id <id>        # compose/volume/image hashes the server holds
tapp-cli -s <server> list-apps                                   # list all apps on this server (no key needed)
tapp-cli -s <server> -k 0x<key> get-app-logs --app-id <id> --service <name> -n 100  # app's docker compose logs
tapp-cli -s <server> get-app-key --app-id <id> [--x25519]         # TEE-derived app PUBLIC key (ethereum addr; --x25519 also prints the X25519 pubkey)
tapp-cli -s <server> get-app-csr --app-id <id> --domain api.example.com --out my.csr  # v0.6.0+, PUBLIC (TCP, no key)
tapp-cli -s <server> verify-app --app-id <id> [--policy-ids <id>]                    # direct: AS-verify this node's evidence+quote, show attested values (no chain)
tapp-cli verify-app --app-id <id> --rpc-url <rpc> --contract 0x<reg> [--policy-ids <id>]  # chain: verify all nodes + reconcile vs on-chain
tapp-cli -s <server> -k 0x<key> get-tapp-info                     # server version + Owner Address (no key needed)
tapp-cli -s <server> -k 0x<key> prune-images [--all]              # delete UNUSED images (--all removes all unused, not just dangling)
tapp-cli -s <server> -k 0x<key> get-service-logs -f <file> [-n 100] # tapp-server's own logs (-n limits lines; no -f lists files)
tapp-cli -s <server> -k 0x<key> docker-logout                    # logout from Docker registry on this server
```

### verify-app: two independent reference axes
- **`--contract`+`--rpc-url` = dynamic references** (on-chain): reconciles runtime events vs the registry → `reconcile : signer✓ compose✓ volumes✓ image✓ owner✓`. The **owner** check (v0.3.0+) compares the `claim_config` event's owner against the on-chain app owner (`✗` = hijacked/mismatched → Result ❌; `?` = no claim_config event, pre-0.3 image).
- **`--policy-ids <id>` = static references** (AS boot-chain check: shim/grub/kernel/initrd/kernel_cmdline or uki vs the image's reference values).
- **Whichever axis has NO reference, the measured values are printed verbatim**: no `--contract` → owner/compose/images as attested; no `--policy-ids` → boot-chain component digests in reference-value JSON (`{"measurement.<comp>.SHA-384": [...]}`), directly diffable against `verifier/reference-values/<cloud>/<boot_format>/<version>/<env>.json`.
- **`kms : <urls>`** (v0.6.0+) lists the KMS cluster the node draws key material from, one per line, with a warning on any plaintext `http://` entry (those nodes' identity cannot be checked). `none configured` means exactly that — not that it was checked.
- **`tls key : <sha256>  (sha256 of the public key, attested)`** (v0.4.0+) appears in both modes when the app has a TLS key, followed by the `openssl s_client | … | openssl dgst -sha256` one-liner for comparing it against a live endpoint. Line absent = no TLS key derived, which is normal, not a failure.
- Output line: `boot-chain : ✓ (executables=3, matches policy reference)` = matched; `✗ (executables=33, ...)` = did not match; `?` = policy set no executables claim. (`executables` is the AR4SI claim: **3** = approved boot chain, **33** = unrecognized.)
- **`--as-endpoint`** picks the Attestation Service (default `https://35.253.66.70:50004`). **It speaks TLS now**, and a bare `host:port` still means plaintext — so an endpoint that moved to TLS must be given with its scheme or the connection fails as an h2 protocol error.
- **`--as-pubkey 0x<sha256>`** pins the AS's TLS key. The AS is a TEE with a self-signed certificate, so this **replaces** CA validation rather than adding to it. Without it the connection is encrypted but unauthenticated — anyone on the path can hand back any verdict — and that is reported rather than refused. Current value: `0x7b13d132…`, the same key scan serves, since both are the same tapp app. Point it at a self-hosted local AS (e.g. `127.0.0.1:50004`, see the `verifier/0g-tapp-verifier` submodule) to use RVPS-backed reference values.
- **Policy ids** — two formats depending on build mode:
  - **canonical** (v0.3.0+): `0g-tapp-<cloud>-<boot_format>-<version>-<env>` (e.g. `0g-tapp-gcp-grub-v0.3.0-dev`). Reference values at `verifier/reference-values/<cloud>/<boot_format>/<version>/<env>.json`.
  - **custom** (per-owner): `0g-tapp-<cloud>-<boot_format>-<version>-<env>-<owner>`. Reference values at `.../env/<owner>.json`.
  - Must be registered on the AS first (stored as `<id>_cpu`); use `verifier/register-shared-as.sh <cloud> <boot_format> <version> <env> [owner] [as-endpoint]`.
- Note: `ear.status=affirming` also needs platform TCB `UpToDate`; `executables=3` alone (boot chain matched) is the boot-chain conclusion independent of TCB.

### Claim ownership (v0.3.0+, canonical images)
```bash
# Must run before any owner-level op on a freshly booted canonical image:
tapp-cli -s <server> -k 0x<key> claim-config                                # claim owner only
tapp-cli -s <server> -k 0x<key> claim-config \
  --chain-rpc-url https://evmrpc-testnet.0g.ai \
  --chain-contract 0x<TappRegistry> \
  --kbs-urls "http://kms-1:9091,http://kms-2:9091" \
  --tls-key-source kms                                                       # claim + set chain + KMS + TLS key source
```
- First-come-first-served, exactly once per boot. CLI verifies result end-to-end.
- `--chain-*`, `--kbs-urls` and `--tls-key-source` optional if already baked into config.toml.
- `--tls-key-source local|kms` (v0.4.0+, default `local`) — decides whether app TLS keys survive a restart, see App TLS certificates above. Must be decided at claim time; `kms` on a node with no KMS/chain config will fail when a cert is requested.
- `--scan-url https://… --scan-pubkey 0x…` (v0.5.0+) — which verifier this node believes about KMS node identity, and its pinned key. Both or neither. See Trust anchors below.

### Trust anchors — which KMS cluster, and which verifier (v0.5.0+)

```bash
tapp-cli -s <server> -k 0x<key> update-trust-anchors \
  --kbs-urls "https://kms-1:9443,https://kms-2:9443" \
  --scan-url https://scan.example --scan-pubkey 0x<sha256 of its TLS key>
```

Owner-only, and **every call is extended into the runtime measurement** carrying the resulting anchors in full — so where a node was ever pointed cannot be hidden. That is what makes these safe to change at runtime; mutable-and-unmeasured would be worse than fixed.

- **Omitted values are left alone**; there is no way to clear one. An empty request is refused rather than measured as a no-op.
- `--scan-url` must be https and must come with `--scan-pubkey`: a URL without a pin is an unauthenticated channel carrying a verdict, which is worse than no verifier at all.
- **Why it exists**: a verifier serves TLS with a `local` key, re-derived every boot, so one verifier restart invalidates the pin on *every* tapp at once. Fixed-at-claim would mean re-claiming the fleet.
- `verify-app` prints the anchors in force and how many times they were revised; `get-tapp-info` prints them even when unset, because "no verifier" means KMS node identity is **not checked** — not that it was checked and passed.

**What the node then does** (v0.5.0+): before fetching key material it pins the verifier against `--scan-pubkey`, asks it for the KMS app's attested keys, and pins the KMS node against that set. No path degrades to unverified — if the verifier is unreachable and nothing is cached, it refuses. A pin mismatch triggers one refresh (a rebooted node has legitimately re-derived its key) then rejects.
- After VM reboot the server is UNCLAIMED again and must be claimed again.

### Server health & whitelist
```bash
tapp-cli -s <server> get-service-status                           # server health + systemd journalctl (no key needed)
tapp-cli -s <server> -k 0x<key> add-to-whitelist --address 0x<evm-addr>    # authorize another address to manage this server
tapp-cli -s <server> -k 0x<key> remove-from-whitelist --address 0x<evm-addr>
tapp-cli -s <server> -k 0x<key> list-whitelist                    # list all authorized addresses
```

### Signing & verification
```bash
tapp-cli -k 0x<key> sign-message -m "hello"                      # sign a message; returns hex + base64 signature
tapp-cli verify-signature -m "hello" --signature 0x<hex> --pubkey 0x<addr>  # verify a signature
```

### Socket-only commands — key material (v0.4.0+)
```bash
tapp-cli -s /run/tapp/tapp.sock get-app-secret-key --app-id <id>                       # TEE-derived secret key
tapp-cli -s /run/tapp/tapp.sock get-secret-resource --app-id <id> [--material <hex>]    # KMS-derived secret
tapp-cli -s /run/tapp/tapp.sock get-app-tls-cert --app-id <id> \
  [--out-key key.pem --out-cert cert.pem]                                              # TLS key + cert (see below)
```
These three hand over **private key material** and from v0.4.0 are served **only on the Unix socket**. Over TCP — including `http://localhost:50051` and `host.docker.internal:50051` — they return `PermissionDenied` ("served only on the tapp Unix socket"). Before v0.4.0 any host that could reach `:50051` could pull any app's private key; that is now closed.

- `-k` is **not** needed: reaching the socket *is* the authorization. Anything that can open the socket can read every app's secrets, so never bind-mount it into an untrusted container.
- A container that needs them mounts the socket instead of using `extra_hosts`:
  ```yaml
  volumes: [ "/run/tapp/tapp.sock:/run/tapp/tapp.sock" ]
  ```
- ⚠️ **When upgrading a node to 0.4.0**, any app still fetching keys over `host.docker.internal:50051` breaks — switch its compose to the socket mount first.

### App TLS certificates (`get-app-tls-cert`, v0.4.0+)

Returns the two files a normal TLS server wants (`key_pem` + `cert_pem`), plus a `csr_pem` for reissuing elsewhere and `public_key_sha256` (sha256 of the SubjectPublicKeyInfo). P-256; self-signed unless `ca_url` is set in config.toml.

The point is the binding, not the issuer: `public_key_sha256` is committed to by the quote's `report_data`, so a client compares the key it was handed during the handshake against attested evidence. A self-signed cert is not weaker for a client that does that check — the issuer only matters to clients using a system trust store (browsers).

`key_source` in the response says where the key came from, which decides whether it is pinnable:
| | derivation | survives restart? | statement |
|---|---|---|---|
| `local` (default) | from this CVM's signer | **no** — signer is re-derived per boot | "this exact TEE instance" (strongest) |
| `kms` | from `(app_id, "tls")` at the KMS | yes, and identical on every node | "some TEE of this app" |

Pick at claim time with `claim-config --tls-key-source local|kms`, or `tls_key_source` under `[server]` in config.toml. `kms` additionally needs the app registered on chain and the cluster reachable.

**Certificate from a public CA** (v0.6.0+): `get-app-csr` returns a signing request for a domain you choose. Unlike `get-app-tls-cert` it is **public** — a CSR carries only a public key, a name, and a proof of possession, all of which the certificate publishes anyway — so it works over TCP with no socket and no key. **The app need not exist yet**: the key derives from the app id, so the certificate can be issued before anything is deployed. Feed it to any ACME client in CSR mode (`lego --csr my.csr --http`), then serve the issued cert with the key the sidecar fetches. Requires `kms` in practice — a `local` key changes every boot and each reboot means another issuance, which Let's Encrypt's rate limits refuse.

**To make an app actually serve HTTPS**, don't hand-roll it — `docs/APP_TLS.md` has a copyable compose using the `tls-init` sidecar, which fetches the cert into a shared volume and exits so an unmodified nginx/envoy just reads two PEM files. Three things bite people: `depends_on: {condition: service_completed_successfully}` is mandatory (else the app starts before the cert exists), the cert must live in a named volume (a `local` key is re-derived every boot), and the TLS port needs opening in the cloud firewall as well as in `ports:`.

### Waiting for async tasks
`start-app`/`stop-app` return a task-id and run async. Poll until done — do NOT chain `sleep`s (blocked); use an until-loop:
```bash
until tapp-cli -s <server> -k 0x<key> get-task-status --task-id <t> 2>&1 | grep -qiE 'Completed|failed'; do sleep 5; done
tapp-cli -s <server> -k 0x<key> get-task-status --task-id <t>
```
A failed task prints the docker compose `Stderr:` (the actual root cause). A completed task does NOT include pull logs.

## On-chain Commands (TappRegistry)

`--server` is also recorded on-chain as the node's `teeUrl` (the `:50051` URL). Key must be the app owner (see Keys above).

```bash
# Preferred for new deploys: start-app --register-onchain (see Core Commands) registers
# BEFORE containers start and is idempotent. The commands below register a RUNNING app.
register-onchain    --app-id <id> --rpc-url <rpc> --contract 0x<reg> --stake-wei 1000000000000000000  # 1 0G
update-onchain      --app-id <id> --rpc-url <rpc> --contract 0x<reg>                                   # re-fetch hashes after redeploy
add-node-onchain    --app-id <id> --rpc-url <rpc> --contract 0x<reg> --stake-wei <wei>                 # -s = new node
update-node-onchain --app-id <id> --rpc-url <rpc> --contract 0x<reg> [--old-signer 0x..] [--new-signer 0x..] [--tee-url ..]
update-trust-anchors --kbs-urls <urls> --scan-url https://.. --scan-pubkey 0x..   # v0.5.0+, owner-only, measured
remove-node-onchain --app-id <id> --rpc-url <rpc> --contract 0x<reg>                                   # -s = node to remove; starts 1-day stake lock
withdraw            --rpc-url <rpc> --contract 0x<reg>                                   # after lock elapses; uses -k key to identify caller
withdraw-balance    --app-id <id> --rpc-url <rpc> --contract 0x<reg>                        # withdraw app balance to owner
```
- `remove-node-onchain` accepts `--signer-address 0x<addr>` to provide the signer directly when the node is unreachable (can't connect to `--server`).
- `update-node-onchain`: new signer auto-fetched from `--server` unless `--new-signer` given; `--tee-url` defaults to the `--server` URL. Pass `--old-signer` explicitly when replacing a node on a different host.
- No app-owner transfer exists: to change owner, old owner `remove-node-onchain` (→ stake locks ~1 day, then `withdraw`) then new owner `register-onchain`.
- app-id is **global & unique** in the registry. `register-onchain` on an existing id → `app already exists`; use add-node/update-node instead.

### Native on-chain subcommands
For `authorizeInvalidator` / `revokeInvalidator`, use the built-in subcommands instead of raw `cast send`:
```bash
tapp-cli --app-id <id> --rpc-url <rpc> --contract 0x<reg> authorize-invalidator-onchain --invalidator 0x<addr>
tapp-cli --app-id <id> --rpc-url <rpc> --contract 0x<reg> revoke-invalidator-onchain --invalidator 0x<addr>
```

### Raw contract calls (fallback)
For other contract interactions or when the funded owner key isn't the server owner, call the contract directly. **Set gas explicitly** — testnet min tip is 2 gwei, cast's default (1 wei) is rejected (`gas tip cap below minimum`):
```bash
docker run --rm --entrypoint cast ghcr.io/foundry-rs/foundry:latest send 0x<reg> \
  "authorizeInvalidator(string,address)" "<appId>" 0x<SandboxServing> \
  --rpc-url <rpc> --private-key 0x<owner-key> --legacy --gas-price 3000000000
# reads: cast call 0x<reg> "getNodeList(string)(address[])" "<appId>" --rpc-url <rpc>
#        cast call 0x<reg> "getAppInfo(string)((bytes,bytes,bytes[],address,uint256))" "<appId>" --rpc-url <rpc>
```

## Restart + re-sync on-chain

Restart = `stop-app` then `start-app`. After a restart that's already registered on-chain, **re-sync** because:
- **TEE signer may change on restart** (it's ephemeral; sometimes stable, sometimes not). Compare `get-app-key` vs `getNodeList`. If different → `update-node-onchain --old-signer <onchain> --new-signer <current>`.
- If images/compose/env changed → `update-onchain` to refresh hashes.

Always verify after: container status `running` + (for crash-loopers) tail logs.

## Pulling an updated image

By default compose reuses the cached image on restart (no re-pull). To pick up a newly-pushed tag:
- **Preferred**: add `pull_policy: always` to the service in the compose, then restart.
- **Otherwise**: `stop-app` → `prune-images` → `start-app` (forces re-pull). Ensure registry login is valid first.

Confirm the new image landed: `get-app-info` → the service's `Image Hash` (sha256) should change.

## Deploying docker-compose Apps — Key Rules

### What tapp-cli uploads automatically
Scans `volumes:` and uploads sources starting with `./` (files or dirs, recursive). `../` paths are **rejected** (each app is sandboxed under `/var/lib/tapp/apps/<app_id>/`).

### Pitfalls and fixes
1. **`../` mount paths unsupported** → copy the file into the compose dir, use `./`.
2. **`.env` not uploaded** (not in `volumes:`) → mount `./.env:/...:ro` in a service so it uploads; compose then finds it for `${VAR}` substitution. Missing a `${VAR:?}` var → compose fails at interpolation (`required variable X is missing`).
3. **Private-registry images need login** on EACH server. The aliyun `cr_temp_user` tokens are **very short-lived** — `unauthorized: authentication required` on pull means re-`docker-login` with a fresh token. Token is account-wide (works on any server until it expires).
4. **App already running** → `stop-app` before re-deploy.

## Troubleshooting — common errors

| Symptom | Cause / fix |
|---|---|
| `PermissionDenied` | wrong key, or server is UNCLAIMED (v0.3.0+ canonical image) — run `claim-config` first |
| `unauthorized: authentication required` (pull) | registry token expired → `docker-login` with fresh token, retry |
| `required variable TAPP_REGISTRY is missing` (compose interpolation) | that var absent from the uploaded `.env` |
| container stuck `restarting` | `get-app-logs --service <svc>` → missing env var / mount file |
| `Bind for 0.0.0.0:<port> failed: port is already allocated` | usually transient (old container hadn't released port) → retry start-app; if persistent, another app holds the port |
| `lookup registry-1.docker.io ... connection refused` | that host's docker has no DNS → fix `/etc/docker/daemon.json` `"dns"` then restart docker |
| on-chain `imageHashes` empty `[]` / `Image Hash: {}` | tapp-server bug: old binary parses `docker compose images --format json` (a JSON array) line-by-line as NDJSON → 0 images. **Server-side**: only fixed by deploying the current tapp-server build (array parsing). prune/re-register won't help. Confirm via `get-app-info`. |
| `app already exists` (register) | app-id taken globally; use add-node/update-node |
| `gas tip cap ... below minimum` (cast send) | add `--legacy --gas-price 3000000000` |

## Remote Attestation — verify a node by `app_id`

Prove a tapp node is genuinely running the registered code in a real TEE. **Only input is `app_id`**; everything else is automatic. Full detail: `docs/EVIDENCE_AND_AS_VERIFICATION.md`.

**One-shot script** (does all 4 steps below): `python3 docs/verify_app.py <app_id>` — needs `cast` (foundry), `tapp-cli`, `grpcurl`, and `docs/attestation.proto` alongside it. The manual steps below are what it automates.

```
app_id
 ├─① chain: getAppInfo → composeHash/volumesHash/imageHashes/owner
 │         getNodeList → [signerAddress...]; getNode(app,signer) → teeUrl
 └─ per node:
     ├─② get-evidence(teeUrl, app_id)            fetch evidence
     ├─③ AS verify quote sig + TCB  (CoCo-AS gRPC 35.253.66.70:50004)
     └─④ reconcile evidence ↔ chain (signer / compose / volumes / image / boot-chain)
```
Trust = chain says "app should run C/I, node signer=S at teeUrl=U" + attestation proves "U is really running C/I and its TEE identity is S".

**① Read chain** (no tapp-cli read cmds — use `cast call`):
```bash
C=0x2Ce80374318B1d7Fb3345724457a182E0ad165c9; R=https://evmrpc-testnet.0g.ai
cast call "$C" "getAppInfo(string)((bytes,bytes,bytes[],address,uint256))" "$APP_ID" --rpc-url "$R"
cast call "$C" "getNodeList(string)(address[])" "$APP_ID" --rpc-url "$R"
cast call "$C" "getNode(string,address)((string,uint256,uint256,bytes,bytes))" "$APP_ID" "$SIGNER" --rpc-url "$R"
```

**② Get evidence** from the node's on-chain `teeUrl`:
```bash
tapp-cli -s <teeUrl> get-evidence --app-id <APP_ID> --nonce $(openssl rand -hex 16) \
  | grep -o 'Evidence (hex): [0-9a-f]*' | sed 's/.*: //' > ev.hex
```
- **`report_data` = `sha512(runtime_data)`** (v0.4.0+), where `runtime_data` is a small JSON object travelling as a third field of the evidence beside `quote` and `cc_eventlog`:
  ```json
  {"nonce":"0x…","signer":"0x…","tls_public_key":"0x…"}
  ```
  Empty fields are **omitted**, not `""`. A quote therefore no longer names its signer on its own — the structure must accompany it, and verifiers hash the bytes **exactly as received** (never re-serialise; there is no canonical form to agree on). Format definition: `tapp-common/src/report_data.rs`.
- **`--nonce <hex>`** (≤64 bytes) is a challenge echoed back inside `runtime_data`. Evidence is self-authenticating but undated, so without a nonce a cached quote is indistinguishable from a fresh one. The CLI prints `challenge : echoed` / `NOT echoed`. Pre-0.4.0 servers print `ignored — this server predates the nonce field`.
- Pre-0.4.0 evidence has **no `runtime_data` field** and `report_data` is the 20-byte signer, left-aligned and zero-padded. Both readings are supported (`tapp-common/src/verify.rs`); a missing field is reported as "server predates the challenge field", not as a signer mismatch.

**③ Verify quote sig + TCB** — submit to **CoCo-AS gRPC `35.253.66.70:50004`** `attestation.AttestationService/AttestationEvaluate`, `evidence` = `base64url(no-pad)` of the raw (hex-decoded) evidence. Returns a JWT/EAR token.
- The AS request's `runtime_data` field is separate from ours: leaving it empty means "don't check the binding yourself, just verify the quote signature chain + TCB and parse `report_data` into claims". Handing it the bytes from the evidence makes the AS check `report_data == sha512(bytes)` too — the verify step below does that recomputation locally either way.
- ⚠️ **Use AS `:50004`, NOT KBS `:8080`** — KBS `/kbs/v0/attest` is RCAR key-release and requires `report_data==hash(nonce,pubkey)`, so it 401s on signer-bound evidence.
- Pass: `submods.cpu0.ear.status == affirming` and `tdx.tcb_status == UpToDate`. `OutOfDate` TCB → `contraindicated` (quote is real but platform firmware/microcode stale — a real finding, not a verify failure).

**④ Reconcile** (read AS-parsed values from the token; do NOT hand-parse quote byte offsets):
- **signer**: read `runtime_data.signer` from the evidence and check `report_data == sha512(runtime_data bytes as received)`. That equality is what makes the field trustworthy; the signer is then compared against the on-chain `signerAddress`. On pre-0.4.0 evidence (no `runtime_data`) fall back to "first 20 bytes of `report_data` == signerAddress", searched as a substring — never treat an RTMR as the signer.
  - ⚠️ quote body offset varies by version: v4 header=48, **v5 header=54** bytes — hardcoding `quote[48:]` mis-reads report_data on v5. AS already aligns it correctly per version; just read `submods.cpu0.ear.veraison.annotated-evidence.tdx.quote.body`.
- **tls_public_key** (if present): sha256 of the SubjectPublicKeyInfo of the app's TLS key. A client compares it against the certificate it was handed during the handshake — that is what ties the TLS endpoint to this TEE. Absent = the app has no TLS key yet (keys are derived at `start_app`).
- `composeHash/volumesHash/imageHashes` == the last `result:"success"` `start_app` event in RTMR3 eventlog. Hash encoding (rebuild before compare): compose=raw 48B SHA-384; volumes=sorted `key + ':' + raw(digest) + '\n'` per entry; image=`sha256:<hex>` ascii per service.
- Boot chain MRTD/shim/grub/kernel/initrd == AS reference values (initrd may differ per host). `kernel_cmdline` matches by **OR** of two refs (new-grub `/vmlinuz...` vs old-grub `(hd0,gptN)/boot/vmlinuz...`) — both pass.
- RTMR3 `EV_EVENT_TAG` events are `<domain> <op> <value>`: `tapp.0g.com` = start_app/stop_app/... ; `cryptpilot.alibabacloud.com` = FDE (only on old aliyun images, absent on GCP).

## Reference
- RA / evidence + AS verification (full flow, encoding rules, tested walkthrough): `docs/EVIDENCE_AND_AS_VERIFICATION.md`; runnable verifier `docs/verify_app.py` (+ `docs/attestation.proto`).
- Full end-to-end app deploy flow + pitfalls (provider/broker: start → register → authorizeInvalidator → provider register): `docs/DEPLOY_RUNBOOK.md`.
- Contract addresses & on-chain query examples: `contract/CONTRACTS.md`.
