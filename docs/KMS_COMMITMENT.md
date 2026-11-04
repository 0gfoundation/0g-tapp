# Generic KMS material and typed identities

`GetSecretResource(app_id, material)` returns algorithm-neutral 32-byte secret bytes,
`commitment_scheme`, a canonical 32-byte big-endian `commitment`, and
`measured_in_evidence`. It does not interpret every secret as a secp256k1 key.
A successful response is released only after its SHA-384 runtime measurement was
written. TLS, the dedicated app signer, and encrypted-volume provisioning follow
this same rule. Failed measurements publish no new runtime metadata.

The node's `GetAppKey` and `GetAppSecretKey` remain fixed secp256k1 node APIs. Their
public keys retain the existing 64-byte encoding without the SEC1 `04` prefix.
The removed `key_type` and `x25519` protobuf numbers are reserved, not reused.
Use the dedicated `GetAppSigner(app_id)` for the stable application signing key:
it consumes `70726f7669646572` (hex `provider`) and uses its raw secret as a
secp256k1 scalar, preserving existing sandbox provider addresses. Application TLS
uses `746c73` (hex `tls`) as a raw P-256 scalar. Local TLS derivation remains
`SHA256("tapp-tls-v1" || node_private_key)`.

## Frozen commitment relation

The scheme is `poseidon-bn254-4-v1`. Material is decoded as hex before committing;
`AB`, `ab`, and `0xab` name the same material. App IDs use their exact UTF-8 bytes.

```text
ctx = SHA256("tapp-kms-commit-v1" || 00 ||
             U32BE(len(app_id UTF8)) || app_id UTF8 ||
             U32BE(len(decoded material)) || decoded material)
C = Poseidon4(ctx_hi, ctx_lo, S_hi, S_lo)
```

Each `hi`/`lo` is an unsigned big-endian 128-bit limb. Inputs are not reduced from
arbitrary 256-bit integers. Poseidon uses the circomlib BN254 scalar field,
width 5, exponent 5, 8 full rounds, 60 partial rounds, and initial capacity zero.
`light-poseidon` 0.4.0 supplies the frozen parameters. `C` has one canonical 32-byte
big-endian field encoding; encodings at or above the field modulus are rejected.

A protocol vector is `app_id="sandbox"`, material `70726f7669646572`, and secret
`01` repeated 32 times:

```text
C = 0x0d2e61c0c36e0879b239181b05600f6e64fec76cc972c63198b0286533460ab3
```

The shared implementation also pins the independent circomlib
`Poseidon4(1,2,3,4)` result in a known-answer test.

## Using another algorithm

The application chooses a distinct material and adapts the secret locally. For
example, an application using X25519 can depend on `x25519-dalek` itself:

```rust,ignore
let material = hex::encode(b"myapp/x25519/v1");
let resource = tapp_common::kms::get_secret(&mut trusted_local_tapp, app_id, &material).await?;
// The helper checks C against the returned bytes and requested app/material,
// and requires the acquisition to have been measured.
let private = x25519_dalek::StaticSecret::from(resource.secret);
let public = x25519_dalek::PublicKey::from(&private);
```

This follows X25519's normal scalar clamping and is separate from the node's
secp256k1 key. The generic KMS API does not invent an X25519 identity entry or
claim to prove this adapter's public-key relation. Other algorithm adapters must
likewise document their own derivation and encoding, rather than reintroducing a
server-side generic `key_type` switch.

## Evidence boundary

Current runtime data explicitly names `app_id`, `identities`, and
`key_commitments`. Typed identities describe actual tapp-computed purpose keys,
with their role, algorithm, encoding, source, derivation, and optional KMS
commitment reference. Legacy signer/TLS fields remain, and old `kms_keys`
evidence remains readable. Metadata is restored from this boot's measured log;
unauthenticated `GetEvidence` does not contact the KMS.

The quote still commits to **SHA-512 of the exact transmitted runtime-data
bytes**. The event log remains SHA-384. The outer evidence envelope reserves an
empty `extensions` object, represented by
`tapp_common::report_data::EvidenceExtensions`. No ZK proof is produced or
validated by this release. A future proof must be checked against its own
cryptographic relation and public inputs; a TEE statement or the mere presence
of a field in `extensions` cannot substitute for that verification.
