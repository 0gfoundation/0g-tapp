---
name: 0g-tapp-cli
description: Use this skill when the user wants to deploy, manage, or troubleshoot applications on a 0G Tapp (Trusted Application Platform) server using tapp-cli. Covers start/stop apps, on-chain registration, registry login, check task status, view logs, and manage docker compose deployments across multiple remote TEE servers.
version: 1.3.0
author: 0G Labs
tags: [0g, tapp, tee, docker, deployment, cli, onchain]
---

# 0G Tapp CLI Skill

Deploy and manage containerized applications on 0G Tapp TEE servers using `tapp-cli`, including on-chain registration in TappRegistry.

## Environment

- **tapp-cli binary**: `/usr/local/bin/tapp-cli`
- **Server**: `-s <url>` (e.g. `http://<host>:50051`). There are MANY tapp servers; always pass `-s` explicitly.
- **Auth**: private key via `-k` flag or `TAPP_PRIVATE_KEY` env var. Read-only commands (`get-tapp-info`, `get-service-status`, `get-app-info`, `get-app-key`, `get-evidence`) work without `-k`; owner-only commands require it.
- **TappRegistry (testnet)**: proxy `0x95a0BF4148b30F6F8D86870534c51df46Da5511c`, RPC `https://evmrpc-testnet.0g.ai`, chainId `16602`. See `contract/CONTRACTS.md`.
- **⚠️ Short flag `-s` conflict**: the global `-s` / `--server` flag is shadowed by local `-s` in `register-onchain` (`--stake-wei`), `get-app-logs` (`--service`), and `verify-signature` (`--signature`). Always use `--server` (full name) with these subcommands.

## Keys & servers — read this first

Each server has an **owner** address (set in its config). App/onchain operations require the right key:

- **Server ops** (start/stop/login/get-*): key must be the **server owner** (or whitelisted). Wrong key → `PermissionDenied`.
- **On-chain** (`register-onchain` etc.): the SAME `--private-key` is used to BOTH auth the `--server` AND sign+pay the tx. So it must satisfy **three things at once**: server-authorized + the app's on-chain owner + funded (stake + gas). If they can't be the same address, do the on-chain part with raw `cast send` (see below) using the funded owner key, bypassing `--server`.
- **Find a server's owner**: `tapp-cli -s <server> -k <anykey> get-tapp-info` (read-only; prints `Owner Address`). Then match the key whose address equals it.
- Convert a key → address: `docker run --rm --entrypoint cast ghcr.io/foundry-rs/foundry:latest wallet address 0x<key>`, or if you have `cast` installed locally: `cast wallet address 0x<key>`.

Record which key maps to which server/owner in memory — it changes per deployment.

## Core Commands

```bash
tapp-cli -s <server> -k 0x<key> docker-login -r <registry-host> -u <user> -p <password>
tapp-cli -s <server> -k 0x<key> start-app -f docker-compose.yaml --app-id <id>   # async → task-id
tapp-cli -s <server> -k 0x<key> get-task-status --task-id <task-id>
tapp-cli -s <server> -k 0x<key> stop-app --app-id <id>
tapp-cli -s <server> -k 0x<key> stop-service  --app-id <id> --service-name <svc>  # flag is --service-name
tapp-cli -s <server> -k 0x<key> start-service --app-id <id> --service-name <svc>
tapp-cli -s <server> -k 0x<key> get-app-container-status --app-id <id>
tapp-cli -s <server> -k 0x<key> get-app-info --app-id <id>        # compose/volume/image hashes the server holds
tapp-cli -s <server> -k 0x<key> get-app-logs --app-id <id> --service <name> -n 100  # note: use --server, not -s (see above)
tapp-cli -s <server> -k 0x<key> get-app-key --app-id <id>         # TEE-derived app signing key (ethereum); --key-type / --x25519 for other types
tapp-cli -s <server> -k 0x<key> get-tapp-info                     # server version + Owner Address (no key needed)
tapp-cli -s <server> -k 0x<key> prune-images [--all]              # delete UNUSED images (--all removes all unused, not just dangling)
tapp-cli -s <server> -k 0x<key> get-service-logs -f <file> [-n 100] # tapp-server's own logs (-n limits lines; no -f lists files)
tapp-cli -s <server> -k 0x<key> docker-logout                    # logout from Docker registry on this server
```

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

### Local-only commands (require localhost access)
```bash
tapp-cli -s http://localhost:50051 -k 0x<key> get-app-secret-key --app-id <id>   # TEE-derived secret key; BLOCKED remotely
tapp-cli -s http://localhost:50051 -k 0x<key> get-secret-resource --app-id <id> --resource <name>  # KMS resource; BLOCKED remotely
```
These commands error with "Private keys will NEVER be sent over the network" when called from a remote host. They only work on the server itself.

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
register-onchain    --app-id <id> --rpc-url <rpc> --contract 0x<reg> --stake-wei 1000000000000000000  # 1 0G
update-onchain      --app-id <id> --rpc-url <rpc> --contract 0x<reg>                                   # re-fetch hashes after redeploy
add-node-onchain    --app-id <id> --rpc-url <rpc> --contract 0x<reg> --stake-wei <wei>                 # -s = new node
update-node-onchain --app-id <id> --rpc-url <rpc> --contract 0x<reg> [--old-signer 0x..] [--new-signer 0x..] [--tee-url ..]
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
| `PermissionDenied` | wrong key for this server; check `get-tapp-info` Owner, use matching key |
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
     ├─③ AS verify quote sig + TCB  (CoCo-AS gRPC 47.237.201.184:50004)
     └─④ reconcile evidence ↔ chain (signer / compose / volumes / image / boot-chain)
```
Trust = chain says "app should run C/I, node signer=S at teeUrl=U" + attestation proves "U is really running C/I and its TEE identity is S".

**① Read chain** (no tapp-cli read cmds — use `cast call`):
```bash
C=0x95a0BF4148b30F6F8D86870534c51df46Da5511c; R=https://evmrpc-testnet.0g.ai
cast call "$C" "getAppInfo(string)((bytes,bytes,bytes[],address,uint256))" "$APP_ID" --rpc-url "$R"
cast call "$C" "getNodeList(string)(address[])" "$APP_ID" --rpc-url "$R"
cast call "$C" "getNode(string,address)((string,uint256,uint256))" "$APP_ID" "$SIGNER" --rpc-url "$R"
```

**② Get evidence** from the node's on-chain `teeUrl`:
```bash
tapp-cli -s <teeUrl> get-evidence --app-id <APP_ID> | grep -o 'Evidence (hex): [0-9a-f]*' | sed 's/.*: //' > ev.hex
```
`report_data` is auto-filled with the node's TEE-derived signer EVM address.

**③ Verify quote sig + TCB** — submit to **CoCo-AS gRPC `47.237.201.184:50004`** `attestation.AttestationService/AttestationEvaluate`, `evidence` = `base64url(no-pad)` of the raw (hex-decoded) evidence, leave `runtime_data` empty. Returns a JWT/EAR token.
- ⚠️ **Use AS `:50004`, NOT KBS `:8080`** — KBS `/kbs/v0/attest` is RCAR key-release and requires `report_data==hash(nonce,pubkey)`, so it 401s on signer-bound evidence.
- Pass: `submods.cpu0.ear.status == affirming` and `tdx.tcb_status == UpToDate`. `OutOfDate` TCB → `contraindicated` (quote is real but platform firmware/microcode stale — a real finding, not a verify failure).

**④ Reconcile** (read AS-parsed values from the token; do NOT hand-parse quote byte offsets):
- `report_data` first 20 bytes == on-chain `signerAddress` (search the 20-byte addr as a substring; never treat an RTMR as the signer).
  - ⚠️ quote body offset varies by version: v4 header=48, **v5 header=54** bytes — hardcoding `quote[48:]` mis-reads report_data on v5. AS already aligns it correctly per version; just read `submods.cpu0.ear.veraison.annotated-evidence.tdx.quote.body`.
- `composeHash/volumesHash/imageHashes` == the last `result:"success"` `start_app` event in RTMR3 eventlog. Hash encoding (rebuild before compare): compose=raw 48B SHA-384; volumes=sorted `key + ':' + raw(digest) + '\n'` per entry; image=`sha256:<hex>` ascii per service.
- Boot chain MRTD/shim/grub/kernel/initrd == AS reference values (initrd may differ per host). `kernel_cmdline` matches by **OR** of two refs (new-grub `/vmlinuz...` vs old-grub `(hd0,gptN)/boot/vmlinuz...`) — both pass.
- RTMR3 `EV_EVENT_TAG` events are `<domain> <op> <value>`: `tapp.0g.com` = start_app/stop_app/... ; `cryptpilot.alibabacloud.com` = FDE (only on old aliyun images, absent on GCP).

## Reference
- RA / evidence + AS verification (full flow, encoding rules, tested walkthrough): `docs/EVIDENCE_AND_AS_VERIFICATION.md`; runnable verifier `docs/verify_app.py` (+ `docs/attestation.proto`).
- Full end-to-end app deploy flow + pitfalls (provider/broker: start → register → authorizeInvalidator → provider register): `docs/DEPLOY_RUNBOOK.md`.
- Contract addresses & on-chain query examples: `contract/CONTRACTS.md`.
