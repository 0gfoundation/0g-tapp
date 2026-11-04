# App identity lookup through the local tapp

`ResolveAppIdentity` (tapp-server ≥0.11.1) lets an application query the Scan
already trusted by its host tapp. The application mounts `/run/tapp/tapp.sock`
as described in [KMS.md](KMS.md); it does not configure a second Scan URL or pin.

```sh
grpcurl -unix -plaintext \
  -import-path proto -proto tapp_service.proto \
  -d '{"chain_id":16602,"registry_address":"0x0000000000000000000000000000000000000001","app_id":"my-app"}' \
  /run/tapp/tapp.sock tapp_service.TappService/ResolveAppIdentity
```

Replace the example registry with the intended TappRegistry. App ids are scoped
by chain and registry. This is not a SandboxServing or other business-contract
address. The RPC is Unix-socket-only and needs no owner signature or KMS cluster.

## Result and meaning

The response echoes `chain_id`, normalized `registry_address`, and `app_id`,
plus `registered_at` (the current on-chain registration epoch),
`scanned_to_block`, `resolved_at`, and `nodes`. Each accepted node contains:

| Field | Meaning |
|---|---|
| `app_signer` | Stable secp256k1 application address, derived from an authenticated typed app-signer identity. Empty if none has been acquired. |
| `identities` | Typed, attested node/app/TLS public-key descriptions, including KMS commitment references where applicable. |
| `key_commitments` | Canonical algorithm-neutral KMS commitments, also referenced by KMS identities. |
| `node_signer` | The registered node's address, matched to its verified attestation. |
| `tee_url` | Its management/evidence endpoint. |
| `tls_spki_sha256` | The **app** TLS public key's SPKI SHA256 hash, as `0x` plus 64 hex digits. |
| `checked_at` | When Scan observed the attestation result, in Unix seconds. |
| `expires_at` | The earlier of Scan's acceptance deadline and Tapp's 300-second maximum. |
| `tcb_status`, `advisories`, `image_env` | The platform/image information accompanying Scan's accepted verdict. |
| `kms_unchecked` | Count of commitments with no successful measured event recording authenticated KMS transport; consumers can apply stricter admission policy. |

The app TLS pin must be checked during the app's TLS handshake. It does not pin
`tee_url`: the tapp management listener has a different identity. Obtain the
business URL and check service authorization through the appropriate business
contract. In particular, `node_signer` must not be substituted for a stable KMS
provider/service signer.

The response also includes the single `scan_url` / `scan_public_key` snapshot
used for the lookup. These come from `ClaimConfig` or `UpdateTrustAnchors`, not
from request fields. Replacing those anchors during a lookup aborts the RPC;
retry against the new configuration. Each call performs a lookup; there is no
additional tapp result cache. Consumers must stop using a result at its local
acceptance deadline and resolve again. A cached result cannot establish that a
node is still current after its observation time.

## Scan interaction

Tapp uses HTTPS with the configured Scan SPKI pin, disables redirects, and checks
the requested chain/registry against `/api/health`. It obtains candidate current
signers from `/api/apps/{app_id}`, then calls `POST /api/verify` for each signer.
Only affirmative structured verdicts with matching app/signer fields, a valid
app TLS pin, and a recent observation are returned. Scope is checked again after
verification. URL path prefixes such as `/mainnet/` are preserved.

The configured Scan's verification policy is the trust authority here. Tapp does
not present the returned JSON as an independently verifiable quote or proof.
Scan verifies a nonce-bound quote, and may reuse that observation within its
60-second cooldown. Tapp also imposes a 300-second maximum. The returned deadline
is the earlier limit; it is not a challenge issued by this application.

KMS admission can observe a valid node before that app has acquired its TLS or
app-signer keys. After publishing a new TLS/app-signer identity, tapp queues a
best-effort `POST /api/verify` with `refresh: true`. Scan pulls its own new
nonce-bound evidence; tapp does not upload evidence or declare verification
complete. Ordinary generic secrets and signer cache hits do not trigger this.
The queue merges pending hints per app/node, bounds both queues to 64 entries,
uses one request at a time, and retries at most three times with a 95-second
attempt timeout. Every attempt reads the current claimed Scan URL and pin.
Returning an already measured key never waits for Scan or depends on its reply.

An identity lookup that encounters a valid observation still missing app TLS
requests one refresh before reporting it pending. Ready nodes can be returned
while other current nodes remain pending; their registration epochs and all
verified app-signer/KMS declarations must still agree, including declarations
seen before the refresh. Pending observations supply no service pin or lease.
Malformed evidence or transport failures are not treated as pending.
A TLS-only app remains valid
without an app signer; services requiring that signer must wait for it explicitly.
If its publication hint fails, the 60-second Scan cache expiry allows another
observation. Consumers should bound their readiness wait and start serving only
after required identities and business authorization are ready.

Scan must support `/api/health`, `/api/apps/{app_id}`, and `POST /api/verify`
with the structured verification/status fields. Missing support, transport or
pin failures, malformed or expired verdicts, and scope mismatches fail the RPC.
There is no fallback to `/cert`, an unpinned client, or a configured default
Scan. A definite negative verdict can exclude one node; an upstream verification
outage fails the lookup rather than being disguised as a negative result.
When a batch receives an error such as HTTP 429, its already started verifications
finish before the lookup reports the first error. This lets Scan publish accepted
cold work for a later retry; no descriptor is returned and no later batch starts.
The resolver's 120-second total deadline still bounds that wait.

## Typed identities and extension boundary

The response carries `node_signer`, stable `app_signer`, and TLS public-key
metadata. The typed declarations are calculated by tapp and included in the
quote-authenticated runtime data; KMS-backed declarations refer to a measured
commitment. Scan checks public-key/address/SPKI consistency and those references.
It returns typed identities only after a nonce-bound fresh attestation and a
current registration-instance/membership check. A generic KMS commitment alone
never supplies an application address.

A missing app signer stays missing; callers requiring it must fail rather than
substitute the node signer. Multiple accepted nodes must agree about the app
signer. Their local TLS pins may legitimately differ. Stable application keys
use the dedicated `provider` material for compatibility with existing sandbox
providers; TLS continues to use its separate `tls` material.

This version relies on the verified tapp implementation's declaration of the
secret-to-public-key derivation. It does not claim an independent ZK proof.
Future proofs belong in evidence extensions and can be bound to the same
commitment and typed statement. Business-specific contracts remain outside this
infra RPC.

## Frozen KMS commitment

For a 32-byte secret `S`, UTF-8 app id `A` and decoded material bytes `M`:

```text
ctx = SHA256("tapp-kms-commit-v1" || 0x00 || U32BE(len(A)) || A || U32BE(len(M)) || M)
C = Poseidon4(ctx_hi128, ctx_lo128, S_hi128, S_lo128)
```

The four limbs are unsigned big-endian 128-bit integers, embedded without
reduction into BN254 Fr. Scheme `poseidon-bn254-4-v1` fixes circomlib's Poseidon
parameters: width 5, 8 full rounds, 60 partial rounds, exponent 5, zero initial
capacity, and the constants pinned by `light-poseidon = 0.4.0`. Encode `C` as a
canonical 32-byte big-endian field element, strictly below the Fr modulus.
The context is public and can be computed outside a future proof circuit;
the secret-dependent relation uses Poseidon.

The outer AA event log continues to hash/extend with SHA384 into RTMR3.
Successful KMS retrieval records `app_id`, normalized `material`, `key_commitment`,
the answering KMS and its attestation status. Typed app-signer/TLS retrievals
also record an `identity` computed from the actual secret. Runtime data carries
the same commitments and typed declarations; hardware `report_data` remains
`SHA512(exact runtime_data bytes)`, not a direct 32-byte commitment.

Future `evidence.extensions` data is outside report_data and is not authenticated
by the TEE quote. A proof verifier must validate it against the authenticated
commitment, app/material context and typed public-key statement. Replacing a
proof cannot replace that statement. No ZK proof is generated or accepted here.
