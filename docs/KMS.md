# The KMS: where persistent secrets come from

Everything a TEE derives locally rotates on every boot — the common signer, every
app signer, TLS keys from the `local` source, scratch volume keys. That is by
design (nothing persists that isn't measured), but apps still need secrets that
survive a reboot and follow them across hosts: a stable TLS key behind a
certificate, the passphrase of an encrypted data volume, application-level keys.
All of those come from one place: the **KMS cluster**. This document is the
consumer side — what the KMS is, why on-chain registration is the access
credential, and how a tapp node is configured to use it. Running a cluster of
your own is the [0g-kms](https://github.com/0gfoundation/0g-kms) repository's
documentation.

## Deployed clusters

Both networks run a cluster under the **same app_id `0g-kms` — but they are two
separate clusters with two different masters**. A consumer whose `--kbs-urls`
point at the wrong network derives from the wrong master and every key comes
out different; the `group_pubkey` below is the anchor to check (any member's
`/peers` endpoint reports it, and it survives node rotations and reshares
unchanged).

### Mainnet (chain 16661)

Registered on TappRegistry `0x54874F536301c993922Dd95097e3902e7FBfe612`,
app_id `0g-kms`, **2-of-5**, owner `0x73443d8C05c74F8C2F5D499Da2597a1EE49E431b`.

```
group_pubkey = 8c30fd0e713be395d8f85ca5e0a879989fa8a4bbf019f0db00c4ee38c05f463a0079ab8c2ccda195f3171b98d0522050
```

| node | zone | KBS endpoint (`--kbs-urls`) |
|---|---|---|
| 1 | us-central1-a | `https://34.66.205.90:9443` |
| 2 | us-east1-c | `https://35.229.43.139:9443` |
| 3 | us-east4-a | `https://35.245.117.228:9443` |
| 4 | us-west1-a | `https://136.66.58.34:9443` |
| 5 | us-east5-b | `https://34.162.149.158:9443` |

### Testnet (0G Galileo, chain 16602)

Registered on TappRegistry `0x2Ce80374318B1d7Fb3345724457a182E0ad165c9`,
app_id `0g-kms`, **2-of-5**.

```
group_pubkey = 8fbb1b3f6309f35e93e069f5268bcea64617a20ab8dfc5f9b79251169e62356168e2d64d8936d52dadc1c8c0eb733541
```

| node | zone | KBS endpoint (`--kbs-urls`) |
|---|---|---|
| 1 | us-central1-a | `https://104.197.68.77:9443` |
| 2 | us-east1-c | `https://34.148.132.90:9443` |
| 3 | us-east4-a | `https://34.11.104.41:9443` |
| 4 | us-west1-a | `https://136.66.159.190:9443` |
| 5 | us-east5-b | `https://136.83.14.240:9443` |

Node signers and teeUrls live on-chain (`getNodeList("0g-kms")` /
`getNode`) and rotate with reboots — the chain, not this table, is the
authority on membership. Endpoints and the group key move rarely; when they do,
this file gets the update, the same way `contract/CONTRACTS.md` tracks the
registries.

## What it is

A threshold-BLS **DPRF** (distributed pseudo-random function) cluster of `n`
TEE nodes, of which any `t` can serve a derivation (production runs 2-of-5).
The master secret is created by a distributed key generation and **never exists
in one place** — each node holds a share, sealed to its own TEE identity, and a
derivation combines `t` partial evaluations without reconstructing the master.
Every derived key is a deterministic function of:

```
app_key = DPRF(master, app_id ‖ material)
```

so the same `(app_id, material)` yields the same 32 bytes on any boot, from any
`t` live cluster nodes, forever — which is exactly the persistence anchor the
rest of the system lacks. The KMS nodes themselves run as a tapp app inside
TDX CVMs, attested and pinned like everything else.

## Why on-chain registration is the credential

The consumer endpoint (`POST /app-key`) authenticates with a plain EIP-191
signature over `GetSecretResource:{timestamp}` — no token, no allowlist file.
The KMS recovers the signer address and answers one question against the
TappRegistry: **is this address in `getNodeList(app_id)` right now?** If yes,
it derives and returns the key ECIES-encrypted to the requester's public key;
if no, it refuses.

That makes the on-chain node list the entire authorization model:

- `start-app --register-onchain` (or `add-node-onchain`) is what grants a node
  access to an app's keys; `remove-node-onchain` is what revokes it.
- A node that reboots re-derives its signer, no longer matches its
  registration, and is locked out until `update-node-onchain` syncs the chain —
  KMS refusals after a reboot are this, not a network problem.
- Nobody — including the cluster operators — can mint an app's key for an
  unregistered address without `t` colluding TEEs deviating from their measured
  code.

## Derivation namespaces

`material` is opaque hex bound into the derivation alongside the app id. The
namespaces in use:

| material | consumer | what the key becomes |
|---|---|---|
| `""` (empty) | apps, via `get-secret-resource` on the socket | the app's base secret, free-form use |
| `746c73` (`"tls"`) | tapp-server, `tls-key-source = kms` | the app's stable TLS key (same cert across boots — what lets Let's Encrypt issuance survive; see [APP_TLS.md](APP_TLS.md)) |
| `666465` (`"fde"`) | tapp-server, encrypted data volumes | the LUKS passphrase of the app's `data/` volume (see the README's data-modes section) |

Not in this table: `scratch` volume keys and everything `local` — those derive
from the node's own signer precisely because they must **not** survive a boot.
The empty app_id (the node's common signer) is refused by `get-secret-resource`;
node-scoped material is not servable to app containers.

## Configuring a node to consume the KMS

Two pieces, both usually set at claim time:

```bash
tapp-cli -s <node> -k <owner-key> claim-config \
  --kbs-urls "https://kms-1:9443,https://kms-2:9443,…" \
  --scan-url https://<verifier> --scan-pubkey 0x<sha256 of its TLS key>
```

- **`--kbs-urls`** (or a baked `[kbs] node_urls` in the image): the cluster
  members. List several — any `t` of them serve a request. CVM images usually
  bake the production list, in which case claiming without `--kbs-urls` keeps it.
- **`--scan-url` / `--scan-pubkey`** — the trust anchors. KMS nodes serve
  attested self-signed TLS; the consumer verifies their identity through a
  verifier (tappscan) whose own key is pinned here. **Omitting this is the
  classic failure**: fetching a key dies with a bare `error sending request`,
  which reads like a connectivity problem but means "I don't trust that
  certificate". `update-trust-anchors` fixes it on a running node, no restart.
  The deployed verifier's URL and pin to put here are in
  [TAPPSCAN.md](TAPPSCAN.md).
  Check with `get-tapp-info` — the `kms :` and `Verifier` lines show exactly
  what the node believes.

Bootstrap ordering matters and is the same for every KMS-derived thing: **chain
first, keys second**. Register the node on-chain, wait for the tx, then derive
(the `kms` TLS source, the FDE volume, `get-secret-resource` — all of them
refuse before registration lands, by design).

## Hosting the KMS itself on tapp: the three circularity rules

The cluster runs on tapp nodes like any app, except an app that *is* the key
source cannot consume itself:

1. **`x-tapp: {data: plain}`** in its compose — a KMS cannot fetch its own FDE
   volume key from a cluster that has not formed yet. Genesis and full-cluster
   restart would deadlock; its share is TEE-sealed and safe on plaintext disk.
   (This is why KMS must not be hosted on tapp-server 0.7.x, which has FDE but
   no opt-out.)
2. **`--tls-key-source local`** in its claim — its serving key cannot come from
   itself; consumers pin the attested key via the verifier instead.
3. Its own `[kbs]` config is irrelevant to it and a baked one should be ignored
   or removed — the KBS URLs point at the very cluster it forms.

Cluster formation, membership changes, share recovery and the reasons
`update-node-onchain` (never remove+add) is the only safe way to rotate a KMS
node's signer are operational concerns of the cluster itself — see the 0g-kms
repository's README and SECURITY notes.
