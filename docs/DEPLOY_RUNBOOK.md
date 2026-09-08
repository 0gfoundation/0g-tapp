# App Deployment Runbook (tapp + TappRegistry)

The standard procedure — and the pitfall checklist — for deploying an app (using the sandbox **provider** + **broker** as the example) from zero onto tapp and making it usable on-chain in TappRegistry.

- **Contract**: TappRegistry BeaconProxy `0x2Ce80374318B1d7Fb3345724457a182E0ad165c9`
- **RPC / chainId**: `https://evmrpc-testnet.0g.ai` / `16602`
- **compose**: provider → `0g-sandbox/docker/sandbox/docker-compose.yml`, broker → `0g-sandbox/docker/broker/docker-compose.yml`

> For detailed contract usage see [`contract/CONTRACTS.md`](../contract/CONTRACTS.md); for tapp-cli usage see [`.claude/skills/0g-tapp-cli/SKILL.md`](../.claude/skills/0g-tapp-cli/SKILL.md).

---

## Standard steps

| # | Step | Command / key points | provider | broker |
|---|------|------------|:---:|:---:|
| 1 | Set the owner in the tapp-server config, start the tapp server | this owner key is used for all subsequent start/stop/register | ✅ | ✅ |
| 2 | `start-app` to bring up the services | `PROVIDER_ADDRESS` must == the app's on-chain owner; `docker-login` to the private registry first; `.env` must have both `TAPP_REGISTRY`/`SETTLEMENT_CONTRACT` | ✅ | ✅ |
| 3 | `register-onchain` to register on-chain | 1 0G stake each | ✅ | ✅ |

> Steps 2+3 can be combined into one command: `start-app --register-onchain --rpc-url … --contract … --stake-wei …`
> It registers idempotently **before** the containers start (not registered→registerApp; registered but this node's signer not in the node list→addNode; already present→skip).
> The server pulls images and computes hashes first, and only brings services up after the transaction confirms; when the signer changed after a restart, it automatically takes the addNode path (the old node still has to be removed/updated manually).
| 4 | `authorizeInvalidator(appId, <SandboxServing contract address>)` | authorizes the sibling contract SandboxServing to call `invalidateAcks`, so that a price change can invalidate user acks; **must happen before step 5** | ✅ | — |
| 5 | `cmd/provider register` to bind the service to SandboxServing | sets `services[provider].appId` + pricing | ✅ | — |

```bash
# 2. Start services (docker-login first)
tapp-cli -s http://<server>:50051 -k 0x<owner-key> docker-login -r <registry> -u <user> -p <pass>
tapp-cli -s http://<server>:50051 -k 0x<owner-key> start-app -f <compose> --app-id <appId>

# 3. Register on-chain (the key must be both the server owner and a funded app owner)
tapp-cli -s http://<server>:50051 -k 0x<owner-key> register-onchain \
  --app-id <appId> --rpc-url https://evmrpc-testnet.0g.ai \
  --contract 0x2Ce80374318B1d7Fb3345724457a182E0ad165c9 --stake-wei 1000000000000000000

# 2+3 combined: register first, then start (idempotent, safe to re-run)
tapp-cli -s http://<server>:50051 -k 0x<owner-key> start-app -f <compose> --app-id <appId> \
  --register-onchain --rpc-url https://evmrpc-testnet.0g.ai \
  --contract 0x2Ce80374318B1d7Fb3345724457a182E0ad165c9 --stake-wei 1000000000000000000

# 4. Authorize the invalidator (note: authorize the SandboxServing contract address, not the owner wallet)
#    No tapp-cli subcommand yet — use cast send directly (watch the gas)
cast send 0x2Ce80374318B1d7Fb3345724457a182E0ad165c9 \
  "authorizeInvalidator(string,address)" "<appId>" 0x<SANDBOX_SERVING_CONTRACT> \
  --rpc-url https://evmrpc-testnet.0g.ai --private-key 0x<owner-key> \
  --legacy --gas-price 3000000000

# 5. provider registers the service (in the 0g-sandbox repo)
PROVIDER_KEY=0x<owner-key> go run ./cmd/provider register --app-id <appId> --url ... --price-per-cpu ...
```

> The broker only goes through step 3; steps 4 and 5 are provider-only.

---

## Pitfall checklist (the mistakes most likely to be repeated)

- **Three keys in one**: the `--private-key` for `register-onchain` must **simultaneously** satisfy: "can connect to the server (server owner or allowlisted)" + "will be the app's owner" + "funded on-chain (1 0G stake + gas)". All three must be the same address — this is the most common blocker.
- **Authorize the invalidator to a contract, not a wallet**: `invalidateAcks` checks `msg.sender == the SandboxServing contract`. Authorizing the owner EOA makes `isAuthorizedInvalidator` return true, but the contract call still reverts with `sandbox not authorized as invalidator`.
- **`PROVIDER_ADDRESS` must == the app's on-chain owner**, otherwise the sandbox's signer_mismatch monitor reports a mismatch and every voucher gets `INVALID_SIGNATURE`.
- **Restart → TEE signer changes**: the TEE-derived signer is not persisted; after any `stop/start` the on-chain node is stale → fix with `update-node-onchain` (pass the old one via `--old-signer`; the new signer is fetched from the server automatically).
- **No owner transfer**: the owner is fixed at `registerApp`. Changing owner = the old owner deregisters via `removeNode` (the stake locks for `lockPeriod`=86400s/1 day; the old owner calls `withdraw()` itself when it expires) → the new owner does a fresh `register`.
- **app-id is globally unique**: registering with a taken name fails with `app already exists`. For an existing one you can only `add-node` / `update-node` (`update-node` replaces the original node — be careful not to accidentally remove a production node elsewhere).
- **service appId is set-once**: changing appId fails with `appId immutable; deregister to change`; you must deregister first.
- **`cast send` rejected for gas too low**: the default tip of 1 wei is below the 2 gwei minimum; add `--legacy --gas-price 3000000000` manually. tapp-cli's onchain subcommands handle gas themselves — this flag is not needed there.
- **Private-registry temporary tokens are short-lived**: they expire soon after docker-login; if an image pull hits `unauthorized`, just log in again.
- **Some cloud hosts have no docker DNS**: `docker.io` fails to resolve and public images can't be pulled; configure docker DNS on the host (`"dns"` in `/etc/docker/daemon.json`).
- **FDE (≥0.7.0): `fde_volume_key - KMS refused the volume key` refuses to start**: a node configured with KMS must obtain the volume key before starting an app. Three possible causes — the app is not yet registered on-chain to this node (use `--register-onchain`, which handles the ordering); the KMS trust anchors are not configured (`update-trust-anchors --scan-url --scan-pubkey`, or provide them together at claim-config time); or the KMS cluster is genuinely down. There is **no** silent fallback to plaintext startup — that is by design.
- **FDE: where the data lands depends on how the compose spells it**: named volumes go into the encrypted volume automatically (zero changes); `./data/` goes in explicitly; other `./` relative paths live in RAM and are lost on restart; absolute paths are plaintext (start-app prints a warning). See README "Where app data lives".

---

## Root cause of all-empty imageHashes (fixed, archived)

**Symptom**: on-chain `getAppInfo(appId).imageHashes` is an empty array `[]`, and `tapp-cli get-app-info` shows `Image Hash: {}` (compose/volume hashes are normal).

**Root cause**: tapp-server enumerates images via `docker compose images --format json`. On some hosts this command outputs a **single-line JSON array** `[{...},{...}]`, while the **old tapp-server binary parsed it as NDJSON line by line** → `invalid type: map, expected a string` → the whole line skipped → `image_count=0` → image_hash `{}`.

**Fix**: `prune`/re-pulling/re-registering do not cure it — the binary must be replaced. The current source `src/boot/manager.rs` now parses the whole array with `serde_json::from_str::<Vec<ImageInfo>>(stdout.trim())`. After installing a current build of tapp-server + restarting the app + `update-onchain`, imageHashes is non-empty.
