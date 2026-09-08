# Verifying a tapp node by App ID (on-chain → fetch evidence → verify signature → reconcile)

> **This is now built into the CLI**: just run `tapp-cli verify-app --app-id <X> --rpc-url <RPC> --contract <Registry>`;
> for apps not yet registered on-chain, use direct mode `tapp-cli -s <server> verify-app --app-id <X>`. This document describes what it does internally, plus
> the equivalent hand-rolled `cast`/`grpcurl` flow (`docs/verify_app.py` is a script reference with the same logic; the CLI implementation is in `src/verify.rs`).

**The verifier's only input is `app_id`.** Everything else is automatic: read the app's registration info and node list from the chain →
fetch evidence from the `teeUrl` recorded on-chain for each node → verify the quote signature/TCB → reconcile the measurements and identity in the evidence against the chain, item by item.

```
Input: app_id
  │
  ├─① on-chain getAppInfo(app_id)        → composeHash / volumesHash / imageHashes / owner
  │   on-chain getNodeList(app_id)       → [signerAddress...]  (all nodes of this app)
  │   on-chain getNode(app_id, signer)   → teeUrl              (where to fetch evidence for each node)
  │
  └─ For each node signer:
      ├─② get-evidence(teeUrl, app_id)        fetch evidence
      ├─③ verify quote signature + TCB  (CoCo-AS gRPC 35.253.66.70:50004, see §③)
      └─④ reconcile evidence ↔ chain:
            report_data == sha512(runtime_data as-is bytes), and runtime_data.signer == signerAddress
            start_app event compose_hash == on-chain composeHash
            start_app event volumes_hash == on-chain volumesHash
            start_app event image_hash  == on-chain imageHashes
            (+ MRTD/shim/grub/kernel/initrd/cmdline == AS reference values)
```

The trust semantics of the chain: **"the app should run composeHash=C with images=I; node signer=S is at teeUrl=U"**.
Attestation proves: **"the TEE at U is actually running C/I, and its TEE-derived identity is S"** → trust is established.

Contract (0G testnet): `TappRegistry` proxy `0x2Ce80374318B1d7Fb3345724457a182E0ad165c9`, RPC `https://evmrpc-testnet.0g.ai`.

---

## ① Reading registration info from the chain

Contract getters (`contract/src/TappRegistry.sol`). `tapp-cli` only has chain-write commands; for reads use `cast call` / ethers / web3 to do a direct eth_call:

| getter | returns | fields |
|---|---|---|
| `getAppInfo(string)` | `AppInfo` | `composeHash`, `volumesHash`, `imageHashes[]`, `owner`, `registeredAt` |
| `getNodeList(string)` | `address[]` | the **signerAddress** of every node of this app |
| `getNode(string,address)` | `NodeInfo` | `teeUrl` (evidence endpoint), `addedAt`, `stakeAmount`, `composeHash`, `volumesHash` |

By design: the **app level** stores the shared code identity (compose/volumes/image); the **node level**, keyed by signerAddress, stores each node's `teeUrl`
and may optionally override `composeHash`/`volumesHash` (used when node-level configuration differs). `getNode` returns the node's **effective values**:
its own overrides if present, otherwise resolved to the app-level defaults. `imageHashes` is always shared.

> ⚠️ `getNode` on the **current** registry has 5 fields. The old deployment (`0x95a0…511c`, deprecated) has only 3;
> using the wrong arity yields a decode error or silent truncation. Distinguish them with `cast call <proxy> "version()(string)"`:
> the current one returns `"0.1.0"`, the old one simply reverts. See `contract/CONTRACTS.md`.

```bash
C=0x2Ce80374318B1d7Fb3345724457a182E0ad165c9 ; R=https://evmrpc-testnet.0g.ai
cast call "$C" "getAppInfo(string)((bytes,bytes,bytes[],address,uint256))" "$APP_ID" --rpc-url "$R"
cast call "$C" "getNodeList(string)(address[])" "$APP_ID" --rpc-url "$R"
cast call "$C" "getNode(string,address)((string,uint256,uint256,bytes,bytes))" "$APP_ID" "$SIGNER" --rpc-url "$R"
```

### Encoding of on-chain hashes (must be reconstructed exactly like this when reconciling) — `src/onchain.rs:103`

| field | encoding |
|---|---|
| `composeHash` | raw 48-byte SHA-384 |
| `volumesHash` | sorted, then each entry `key + ':' + raw(digest) + '\n'` concatenated. The digest is **raw bytes** (not a hex string), and **each entry ends with `\n`** |
| `imageHashes[]` | array, one `sha256:<hex>` **ascii** byte string per service (no newline) |

> In the evidence's `start_app` event, `volumes_hash` is `{"key":"<hexdigest>"}`; when reconciling, rebuild it per the rule above as
> `key:` + `bytes.fromhex(hexdigest)` + `\n` and then compare against the on-chain `volumesHash`.

---

## ② Fetching evidence (using the on-chain teeUrl)

```bash
tapp-cli -s <teeUrl> get-evidence --app-id <APP_ID> --nonce $(openssl rand -hex 16) 2>&1 \
  | grep -o 'Evidence (hex): [0-9a-f]*' | sed 's/Evidence (hex): //' > ev.hex
```

- The signer is not persisted: when the tapp server restarts, it re-derives and the address changes; use `update-node-onchain` to sync the chain.
- **Node-level evidence (≥0.8.0)**: omitting `--app-id` (empty) returns evidence for **the node itself** — the signer is the node's
  common signer (generated at every boot; all app signers are derived from it), and `runtime_data.tls_public_key`
  is the SPKI sha256 of the :50052 management-port TLS key. Purpose: after verifying the quote, use it as `--tls-pin`
  so the management channel resists an active man-in-the-middle, without requiring any out-of-band distribution. The verification flow is identical to app evidence.
  Two boundaries: it proves "a genuine TDX node", not "the node at the address you dialed" — it prevents interception, not
  redirection to the attacker's own genuine node (anchoring the common signer on-chain is future work); and the pin rotates on every reboot
  (common signer changes → TLS key changes), so an old pin fails closed and evidence must be re-fetched after a reboot.

### Structure of `report_data` (v0.4.0+)

Previously `report_data` was simply the 20-byte signer address, left-aligned and zero-padded — the quote carried the identity, but there was no room to extend
(20 bytes + a 32-byte binding + one challenge already exceeds 64 bytes). Now:

```
report_data = sha512(runtime_data)
```

`runtime_data` is a small JSON object, returned as the **third field** of the evidence alongside `quote` / `cc_eventlog`
(base64). Definition in `tapp-common/src/report_data.rs`:

```json
{"nonce":"0x…","signer":"0x…","tls_public_key":"0x…"}
```

| field | meaning |
|---|---|
| `nonce` | the caller-supplied challenge (`--nonce`, ≤64 bytes), echoed back verbatim |
| `signer` | the app's TEE-derived signer EVM address (20 bytes), i.e. the identity registered on-chain |
| `tls_public_key` | sha256 of the app's TLS public key (SubjectPublicKeyInfo); absent if the app has never requested a TLS key |

Two rules that must be remembered:

1. **An empty field is "absent", not `""`.** This way, when a field is unused, the evidence bytes are byte-for-byte identical before and after the field was added.
2. **The verifier hashes the bytes exactly as received and never re-serializes.** There is no "canonical form" both sides must agree on, and therefore no room for drift.
   The `RuntimeData` struct is only for reading fields, not an encoder.

Why sha512: TDX's `report_data` is exactly 64 bytes and sha512 fills it exactly; it is also the algorithm CoCo-AS expects when it is handed `runtime_data`
and verifies the binding itself.

**Cost**: the quote alone can no longer state its own signer — this structure must accompany it. Evidence has always been the
`{quote, cc_eventlog}` JSON, so this is just one more field on the same object; nowhere in the system is a bare quote passed around.

**Compatibility**: evidence from before 0.4.0 has no `runtime_data` field, and `report_data` is the old 20-byte signer.
Both readings are supported (`tapp-common/src/verify.rs`); a missing field reports "server predates the challenge field"
rather than a signer mismatch.

### nonce: evidence is self-attesting, but has no notion of time

Nothing in the quote says when it was generated, so a cached quote and a fresh quote are cryptographically
indistinguishable. If the caller supplies a random value on each request, they become distinguishable:

```
$ tapp-cli -s <teeUrl> get-evidence --app-id <APP_ID> --nonce 0a1b2c3d…
  runtime_data: {"nonce":"0x0a1b2c3d…","signer":"0x…","tls_public_key":"0x…"}
  report_data : <sha512, 128 hex>
  challenge   : echoed — this quote was produced for this request
```

- It must be **random** — not a counter or a clock.
- For scenarios serving cached results to many readers (e.g. scan), don't pass a nonce — it couldn't represent any individual reader anyway.
- Older servers print `challenge : ignored — this server predates the nonce field`.

---

## ③ Verifying the quote signature + TCB (CoCo-AS gRPC `50004`)

trustee's docker-compose starts three services: **KBS `8080`**, **AS (coco-as-grpc) `50004`**, RVPS `50003`.
**The one that actually verifies evidence is the AS on `50004`, not the KBS on `8080`.** (The KBS's `/kbs/v0/attest` is RCAR key distribution;
it requires `report_data==hash(nonce,pubkey)` and returns 401 for any signer-bound evidence — **do not use it for signature verification**.)

AS service: `attestation.AttestationService/AttestationEvaluate` (proto in trustee `protos/attestation.proto`).
`evidence` = `base64url(no-pad)` of the **raw evidence bytes** (i.e. the hex-decoded `{cc_eventlog,quote,runtime_data}`).

⚠️ Be careful to distinguish two things with the same name: the `runtime_data` field **in the AS request**, and the `runtime_data` field **inside** the evidence.

- Leave the AS request's `runtime_data` **empty** → the AS does not check the binding; it only verifies the quote signature chain (PCK→Intel root) + TCB, and parses
  `report_data` into the claims. §④ recomputes `sha512` locally to verify the binding itself, so leaving it empty is sufficient.
- Alternatively, pass the bytes of the evidence's own `runtime_data` to the AS and let the AS check `report_data == sha512(bytes)` for you.
  Both paths reach the same conclusion — just don't skip it on both sides.

```python
import binascii, base64, json, subprocess
raw = binascii.unhexlify(open('ev.hex').read().strip())
req = {"verification_requests": [
        {"tee": "tdx", "evidence": base64.urlsafe_b64encode(raw).rstrip(b'=').decode()}]}
open('/tmp/as_req.json','w').write(json.dumps(req))
# requires trustee's protos/attestation.proto locally
subprocess.run(
  "grpcurl -plaintext -import-path . -proto attestation.proto -d @ "
  "35.253.66.70:50004 attestation.AttestationService/AttestationEvaluate < /tmp/as_req.json",
  shell=True)
```

Returns an `attestation_token` (JWT / EAR format). Decode the payload and look at `submods.cpu0`:

| claim | meaning |
|---|---|
| `ear.status` | overall verdict: `affirming` pass / `warning` / `contraindicated` fail |
| `ear.trustworthiness-vector` | per-dimension scores: `2`=affirming, `32–95`=warning, `≥96`=contraindicated |
| `tdx.tcb_status` | `UpToDate` / `OutOfDate` / … |
| `tdx.advisory_ids` | matched Intel security advisories (`INTEL-SA-xxxxx`) |
| `tdx.quote.report_data` / `mr_td` / `rtmr_*` | measurements parsed by the AS, directly usable for the §④ reconciliation |

> Verdict essentials: only `ear.status == affirming` means the quote is trusted. An `OutOfDate` TCB drives the `hardware` dimension
> to ≥96 → `contraindicated` (the quote is genuine, but the platform firmware/microcode is outdated and the TCB needs upgrading).

---

## ④ Parsing the evidence + reconciling

Decoded evidence(hex) = `{ cc_eventlog: <base64>, gpu_evidence: null, quote: <base64>, runtime_data: <base64> }`
(`runtime_data` only exists from v0.4.0+, see §②).

### Verify the report_data binding + read the signer (v0.4.0+)

```python
rd_bytes = base64.b64decode(j["runtime_data"])          # as-is bytes, do NOT loads then dumps
assert bytes.fromhex(report_data) == hashlib.sha512(rd_bytes).digest()   # binding holds
rd = json.loads(rd_bytes)
signer_ok  = rd["signer"].lower() == onchain_signer.lower()
nonce_ok   = rd.get("nonce","").lower() == "0x" + my_nonce.hex()          # only check if a nonce was sent
tls_pubkey = rd.get("tls_public_key")                                     # may be absent
```

Verify the binding first, then read the fields — doing it in the reverse order amounts to trusting a piece of JSON not covered by the quote.

Old evidence (no `runtime_data`) uses the legacy reading: the first 20 bytes of `report_data` == signerAddress.

### Quote measurements / report_data — taken directly from the AS parse result in §③

**Do not hand-roll quote byte offsets to extract measurements.** The field offsets inside the TD body are fixed, but **the body's starting offset within the quote varies with the quote version**:
v4 header = 48 bytes, **v5 header = 54 bytes**. Hardcoding `q[48:]` on a v5 quote shifts everything by 6 bytes, mistaking the tail of RTMR3 for the prefix of report_data — this is a pit that has actually been fallen into (see `VERIFIER_AGENT_GUIDANCE.md`).

The AS (§③) has already aligned and parsed correctly per version; just read the token's `submods.cpu0.ear.veraison.annotated-evidence.tdx.quote.body`:

```python
qb = claims["submods"]["cpu0"]["ear.veraison.annotated-evidence"]["tdx"]["quote"]["body"]
report_data = qb["report_data"]   # v0.4.0+: sha512(runtime_data); older versions: first 20 bytes = signer
mrtd        = qb["mr_td"]
rtmr3       = qb["rtmr_3"]
```

| field | meaning |
|---|---|
| MRTD (`mr_td`) | TD initial memory measurement (firmware/VM image); identical across machines with the same image |
| RTMR0/1/2 | firmware config / boot (shim·grub) / OS (grub commands·kernel·initrd) |
| RTMR3 | runtime: cryptpilot FDE (old images) + tapp operations |
| `report_data` | v0.4.0+: `sha512(runtime_data)`, signer read from `runtime_data.signer`. Older versions: signer at **offset 0** (first 20 bytes), rest zero-padded. **An RTMR (anything that isn't report_data) must never be treated as the signer** |

> The safe way to obtain the signer: first verify `report_data == sha512(runtime_data as-is bytes)` per the above, then read
> `runtime_data.signer` and compare with the on-chain `signerAddress`. Only for old evidence fall back to "take the first 20 bytes of `report_data`,
> and **search** for the on-chain `signerAddress` as a substring" — this neither hardcodes quote offsets nor loses the chain value as the anchor.
> (If you absolutely must parse offline by hand, the header length must be decided by the version in `quote[0:2]`: v4→48, v5→54, then take report_data at `body[520:584]`.)

### cc_eventlog (TCG2, SHA-384 throughout)

```python
log = base64.b64decode(j['cc_eventlog']); ALG = {4:20, 0xb:32, 0xc:48, 0xd:64}
o = 0; o += 8; o += 20; ds, = struct.unpack_from('<I', log, o); o += 4 + ds   # skip SpecID
while o + 12 <= len(log):
    pcr, et = struct.unpack_from('<II', log, o); o += 8
    cnt,    = struct.unpack_from('<I', log, o);  o += 4
    d384 = None
    for _ in range(cnt):
        alg, = struct.unpack_from('<H', log, o); o += 2
        if alg == 0xc: d384 = log[o:o+ALG[alg]].hex()
        o += ALG.get(alg, 48)
    dl, = struct.unpack_from('<I', log, o); o += 4; data = log[o:o+dl]; o += dl
    if et == 0x6 and dl >= 8:                                  # EV_EVENT_TAG: first 8 bytes are the tag header
        text = data[8:8 + struct.unpack_from('<I', data, 4)[0]].decode('utf-8','replace')
        # text = "<domain> <operation/key> <value>"
```

### Measurement matching rules (against AS reference values)

| field | match mode | notes |
|---|---|---|
| MRTD / shim / grub / kernel | exact | identical for the same image |
| initrd | exact | **may differ per machine**; each matches its own reference value |
| kernel_cmdline | **OR** | see below |
| report_data binding | = `sha512(runtime_data)` | verify the binding before reading fields |
| `runtime_data.signer` | = on-chain signerAddress | see above |
| `runtime_data.nonce` | = the challenge sent with this request | only checked if `--nonce` was passed |
| `runtime_data.tls_public_key` | = sha256 of the certificate public key obtained in the handshake | may be absent (app never requested a TLS key) |
| compose / volumes / image hash | = corresponding on-chain field | see §① encoding rules |

**kernel_cmdline has two reference values (new/old grub); matching either one passes:**

| | kernel path spelling | example digest |
|---|---|---|
| new grub | `/vmlinuz-<ver> root=… ip=dhcp` (relative to `$root`) | `7dd3d3d1…` |
| old grub | `(hd0,gptN)/boot/vmlinuz-<ver> root=… …` (full grub device path) | `bad43ebbd…` (GCP 6.17 kernel example) |

The kernel and parameters are exactly the same in both; the only difference is the textual spelling of the kernel path → different hashes.
digest = `SHA384(cmdline string)` (with the `kernel_cmdline: ` prefix from the eventlog removed, and without the trailing null).
> Observed in practice: GCP images (new grub) only produce the `/vmlinuz` form; old Aliyun images (old grub) produce the `(hd0,gpt3)/boot/vmlinuz` form.

---

## RTMR3 runtime events (the data source for reconciliation)

RTMR3's `EV_EVENT_TAG` entries are runtime measurements in the uniform format `<domain> <key/operation> <value>`, split into two classes by domain:

### cryptpilot (old Aliyun images, full-disk encryption FDE)

domain `cryptpilot.alibabacloud.com`, produced during the initrd stage, ordered before the tapp events.
**Only old images that use cryptpilot have these**; new GCP images do not.

| key | value | meaning |
|---|---|---|
| `load_config` | `<SHA-384>` | cryptpilot configuration measurement |
| `fde_rootfs_hash` | `<hash>` | full-disk-encrypted rootfs hash |
| `initrd_switch_root` | `{}` | initrd switch-root marker |

### tapp operations

domain `tapp.0g.com`, triggered by `start_app`/`stop_app`/`start_service`/`get_app_secret_key`/`docker_login`
(code: `extend_measurement()` → AA `extend_runtime_measurement`):

```
tapp.0g.com <operation> {"app_id","operation","result","error",
  "compose_hash","volumes_hash","image_hash","deployer","timestamp"}
```

- For reconciliation, take **the last `start_app` with `result:"success"` and `compose_hash` == the on-chain composeHash**.
- Both success and failure are recorded (failure: `result:"failed"` + error text + empty `image_hash:{}`).
- `docker_login` records `registry/username/signer/timestamp` (no password).
- Pattern: the first runtime event of each session lands on `pcrIndex=1`; subsequent ones land on `pcrIndex=4`.

### claim_config (runtime claiming of owner+config; mandatory check for canonical images)

Canonical images do not bake in owner/chain/kbs (one set of golden reference values network-wide, at path `<env>.json` with no owner layer),
so **the entire runtime configuration moved from static measurements into the runtime event log**:

```
tapp.0g.com claim_config {"owner":"0x<owner>","chain_rpc_url":"…",
  "chain_contract_address":"0x…","kbs_node_urls":["…"],
  "operation":"claim_config","timestamp":<ts>}
```

Reconciliation rules (add one step to §④):

1. A **`claim_config` event must exist** in the event log (none → the node is ownerless or took an unmeasured path; reject);
2. If there are multiple (e.g. config mode restarting across processes), **the `owner` of all `claim_config` events must be identical**;
3. `owner` == the owner registered on-chain for this node (mismatch → the owner was squatted or the registration does not match; reject);
4. `chain_contract_address` / `kbs_node_urls` are for audit: which contract and which KMS cluster the node claimed at the time.

The claim event is produced by the first claim after boot (dynamic mode via the ClaimConfig RPC, or automatic claiming at startup in config.toml preset mode).
On every VM reboot the RTMRs are zeroed, the claim happens again, and it is measured again — the owner and the quote always share a lifecycle.

**`tapp-cli verify-app` already performs the rules in this section automatically** (v0.3.0+): in chain mode the reconcile line prints
`owner✓/✗/?` (✓ = claim_config owner == on-chain owner; ✗ = mismatch, Result ❌; ? = no claim_config event,
images predating 0.3). Also, without `--policy-ids`, the boot-chain component measurements are printed verbatim in the reference-value JSON format,
so they can be diffed directly against `verifier/reference-values/…/<env>.json`.

---

## TLS: connecting "the verified TEE" to "the endpoint I am talking to" (v0.4.0+)

What ①②③④ above prove is "this node of this on-chain app is really running the registered code inside a genuine TEE". But what a client
actually needs is "**the peer of the TLS connection I have right now** is that node" — the rope tying these together is
`runtime_data.tls_public_key`.

```
①②③④  →  this TEE is trusted, and the sha256 of its TLS public key = H
handshake →  sha256 of the public key in the peer's certificate = H'
H == H' →  the peer of this connection is that TEE
```

The app obtains `key_pem` / `cert_pem` via `get-app-tls-cert` (socket-only) and serves HTTPS directly, without doing any
cryptographic work itself. On the client side, one command computes `H'`:

```bash
openssl s_client -connect HOST:PORT </dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der \
  | openssl dgst -sha256
```

`tapp-cli verify-app` prints `H` along with that command (`tls key : <sha256>`), so the reconciliation is a single eyeball step.

**Two trust layers; the second is optional:**

| | who binds what | what the client has to do |
|---|---|---|
| Layer 1 (evidence) | the evidence binds the TLS public key to a TEE — **no CA needed** | compare `H` and `H'` itself |
| Layer 2 (CA) | a CA binds a domain name to the same public key | nothing — the system trust store passes it automatically |

In layer 1, a self-signed certificate is **no weaker than a CA-signed one** — what is checked is the public key, not the issuer. The CA (`ca_url`) exists only so that
clients that don't perform this check (browsers, anything using the system trust store) also accept the same certificate.

**Whether the public key can be pinned depends on the key source** (`[server].tls_key_source` in `config.toml`, or
`claim-config --tls-key-source`):

| | derived from | same after a restart? | what the evidence says |
|---|---|---|---|
| `local` (default) | this CVM's signer | **no** — the signer is re-derived on every boot | "this exact TEE instance" (strongest) |
| `kms` | KMS derives from `(app_id, "tls")` | yes, and identical on every node of the app | "some TEE of this app" |

If you want pinning, CT monitoring, or ACME renewal, you must use `kms` — `local` changes the public key on every restart, breaking all of those. Conversely,
`local` depends on neither the KMS nor on-chain registration and works from first boot. `local` is the default because it always works; stability is something you
opt into when you need it.

---

## Live walkthrough: `0g-agentic-id-attestor` (run end-to-end strictly per this document)

> This walkthrough ran on a node **older than 0.4.0**, so in ④ the signer was read the legacy way (first 20 bytes of `report_data`)
> and the evidence contained no `runtime_data`. On 0.4.0+ nodes, first verify the `sha512` binding then read `runtime_data.signer`;
> all other steps are unchanged.

Input `app_id = 0g-agentic-id-attestor`, fully automatic (script in the appendix §):

```
① on-chain:
   getAppInfo  → composeHash 740e9c57…2751d8 / volumesHash .env:<digest>\n / imageHashes[sha256:b7aaa6…, sha256:4b7183ac…]
   getNodeList → [0x6C30D1E9392eaF67DAB66c4962249DE821CD335f]
   getNode     → teeUrl http://47.84.230.10:50051   stake 1 0G
② fetch evidence: get-evidence @ 47.84.230.10  (old Aliyun image: MRTD 060000…, cryptpilot FDE, old grub)   ✅
③ AS verification @ 35.253.66.70:50004 (AttestationEvaluate): token returned, quote signature✅, report_data parsed = 0x6C30…335f
        but tcb_status=OutOfDate (INTEL-SA-01036 and 7 more) → ear.status=contraindicated  ⚠️ platform TCB outdated
④ reconcile:
   node signer  0x6C30…335f      == first 20 bytes of AS report_data   ✅
   composeHash  740e9c57…2751d8   == start_app(ts 1781099341).compose ✅
   volumesHash  .env:<digest>\n   == start_app.volumes_hash (rebuilt)  ✅
   imageHashes  sha256:b7aaa6…/4b7183ac… == start_app.image_hash       ✅
```

**Node verdict**: identity + code measurement reconciliation **all passed** (①②④); AS verification: **endpoint reachable, quote genuine**, but this node's
**TCB is outdated**, causing `contraindicated` (③) — a genuine security finding (platform firmware/microcode needs upgrading), not a verification failure.
①②③④ have all been run end-to-end on real hardware.

---

## Quick checklist (input = app_id)

1. Read registration info + each node's teeUrl from the chain: `getAppInfo` / `getNodeList` / `getNode`.
2. For each node: `get-evidence --app-id <id> --nonce <random hex>` at its teeUrl.
3. Verify quote signature + TCB: submit `AttestationEvaluate` to **CoCo-AS gRPC `35.253.66.70:50004`** (leave the AS request's `runtime_data` empty); check `ear.status==affirming` and `tcb_status==UpToDate` (**do not use the KBS on 8080 — that is RCAR key distribution and will 401**).
4. Reconcile:
   - first verify `report_data == sha512(evidence.runtime_data as-is bytes)`, then read `runtime_data.signer` == on-chain signerAddress (never hand-roll quote offsets; for old evidence without this field, fall back to the first-20-bytes reading);
   - if a nonce was sent, check that `runtime_data.nonce` echoes it (distinguishes a fresh quote from a cached one);
   - `runtime_data.tls_public_key` (if present) == sha256 of the certificate public key obtained in the handshake;
   - compose/volumes/image hash == on-chain (per the §① encoding); MRTD/boot chain == AS reference values (cmdline is OR).
5. In RTMR3, recognize cryptpilot (old images) + take the last successful start_app for the compose/image/volumes reconciliation + reconcile the `claim_config` owner.
