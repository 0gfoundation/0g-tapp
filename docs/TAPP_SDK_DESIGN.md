# Tapp Verification SDK — Design Draft

**Status:** draft for review · **Author:** (TBD) · **Date:** 2026-06-23 · tracking: #9

> Draft for review — scope/shape before committing to the full SDK.
>
> **Already implemented:** the core verify flow now ships in `src/verify.rs` (behind
> `tapp-cli verify-app`): chain reads (`src/onchain.rs`: getNodeList/getNode/getAppInfo),
> evidence parsing (version-aware quote, cc_eventlog), CoCo-AS gRPC client + EAR parsing,
> and reconciliation. So the SDK work is largely **extract `verify` + `onchain` into a
> shared crate (no TEE deps → macOS-buildable) + add TS/Python bindings**, rather than
> writing it from scratch. This also resolves the duplication in the "standalone CLI"
> approach (copying modules) by sharing one crate instead.

## 1. Why

Every place that hand-rolled tapp's low-level chain/attestation logic this cycle got
something wrong. The SDK exists to encode these once, correctly, with tests, so no
consumer (CLI, verifier, frontend, indexer, AI agent) re-implements them:

| Real bug we hit | Root cause | What the SDK removes |
|---|---|---|
| Agent read **RTMR3 as the signer** | report_data has no self-describing layout | one `signer_of(evidence)` that's correct |
| Decoded quote with **v4 offset on a v5 quote** (phantom "layout") | TD body start varies by quote version | version-aware quote parser |
| compose/volumes **override vs inherit** fallback | effective = node override ?? app default | `effective_code(appId, signer)` |
| Submitted to **KBS :8080** instead of **AS :50004** | two different services, RCAR ≠ verify | one `verify_quote()` to the right endpoint |
| Hash **`key:raw\n` / `sha256:` encoding** mistakes | bespoke on-chain encoding | typed hash codec |

Design principle (from `VERIFIER_AGENT_GUIDANCE.md`): **constrain the environment,
don't rely on each consumer's discipline.**

## 2. Scope

**In (v1):**
- Read-only chain access to TappRegistry (app info, node list, node, ack state) with
  override/inherit resolution.
- Evidence parsing (TDX quote, report_data→signer, cc_eventlog incl. cryptpilot + tapp
  runtime events).
- Attestation-Service client (CoCo-AS gRPC :50004) + EAR token parsing.
- Hash codec (compose/volumes/image ↔ on-chain bytes).
- One high-level **`verify_app(appId)`** that runs chain → fetch evidence → AS → reconcile.

**Out (v1):**
- Write/transaction helpers (register/add-node/update — stays in tapp-cli for now; can
  be a later `tapp-sdk-tx` feature).
- Key management / signing for authenticated tapp-server RPCs.
- Deployment/upgrade tooling (stays in `contract/cmd/`).

**Non-goals:** replacing tapp-cli; being a general EVM SDK.

## 3. Shape

```
tapp-sdk (Rust core crate)            ← single source of truth, reuses tapp_service
  ├─ chain      : TappRegistry reads + override/inherit resolution
  ├─ evidence   : quote / report_data / cc_eventlog parsing
  ├─ as_client  : CoCo-AS submit + EAR token parse
  ├─ codec      : hash encode/decode (combine_map_hashes etc.)
  └─ verify     : verify_app(appId) end-to-end
        │
        ├── tapp-sdk-ffi  → uniffi/napi → TypeScript pkg (frontends, indexers)
        └── pyo3          → Python pkg  (scripts; replaces verify_app.py)
```

Reuse existing modules rather than rewrite: `tapp_service::onchain` (calldata/reads),
`tapp_service::app_key`, `tapp_service::measurement`, and the proven logic in
`docs/verify_app.py`. The Rust core is the only implementation; TS/Python are thin
bindings so all consumers share the same (tested) code.

## 4. Public API sketch (Rust core)

```rust
// ── chain ──────────────────────────────────────────────────────────────────
pub struct Registry { /* rpc + contract addr */ }
impl Registry {
    pub async fn app_info(&self, app_id: &str) -> Result<AppInfo>;          // app-level defaults + images + owner
    pub async fn node_list(&self, app_id: &str) -> Result<Vec<Address>>;    // signer addresses
    pub async fn node(&self, app_id: &str, signer: Address) -> Result<NodeInfo>;
    /// effective code for a node. NOTE: the contract's getNode already resolves the
    /// per-node override → app-level default on read, so this just wraps node()+app_info().
    pub async fn effective_code(&self, app_id: &str, signer: Address)
        -> Result<CodeIdentity>;                                            // { compose, volumes, images }
    pub async fn is_acknowledged(&self, user: Address, app_id: &str) -> Result<bool>;
}

// ── evidence ───────────────────────────────────────────────────────────────
pub struct Evidence { /* raw bytes */ }
impl Evidence {
    pub fn parse(raw: &[u8]) -> Result<ParsedEvidence>;   // { quote, cc_eventlog, gpu }
}
pub struct Quote { /* ... */ }
impl Quote {
    pub fn parse(b64_or_bytes: &[u8]) -> Result<Quote>;   // version-aware header offset
    pub fn signer(&self) -> Address;                      // report_data → 20-byte addr, layout-safe
    pub fn mrtd(&self) -> [u8;48];
    pub fn rtmr(&self, i: u8) -> [u8;48];
}
pub struct EventLog { /* ... */ }
impl EventLog {
    pub fn events(&self) -> &[CcEvent];                   // TCG2 + cryptpilot + tapp.0g.com runtime
    pub fn runtime_ops(&self) -> Vec<TappOp>;             // start_app/stop_app/... parsed JSON
    pub fn latest_successful_start(&self, app_id: &str) -> Option<TappOp>;
}

// ── as_client ──────────────────────────────────────────────────────────────
pub struct AsClient { /* grpc :50004 */ }
impl AsClient {
    pub async fn verify(&self, ev: &Evidence) -> Result<EarToken>;  // runtime_data omitted
}
pub struct EarToken { /* ... */ }
impl EarToken {
    pub fn status(&self) -> EarStatus;        // Affirming | Warning | Contraindicated
    pub fn tcb_status(&self) -> TcbStatus;    // UpToDate | OutOfDate | ...
    pub fn advisories(&self) -> &[String];
    pub fn report_data(&self) -> &[u8];       // AS-parsed (version-correct)
}

// ── codec ──────────────────────────────────────────────────────────────────
pub fn combine_volume_hashes(map: &BTreeMap<String,String>) -> Vec<u8>;  // "key:raw\n"
pub fn image_hashes(map: &BTreeMap<String,String>) -> Vec<Vec<u8>>;      // "sha256:..."

// ── verify (high level) ──────────────────────────────────────────────────────
pub async fn verify_app(reg: &Registry, app_id: &str) -> Result<AppVerdict>;
// AppVerdict { per-node: { signer, ear_status, tcb_status, signer_matches_chain,
//              compose_matches(effective), volumes_matches, image_matches }, overall }
```

## 5. Footgun-proofing baked in
- **Quote version**: header length resolved from `quote[0..2]` (v4=48, v5=54); never hardcoded.
- **Signer**: taken from AS-parsed report_data, or `report_data[..20]` with the on-chain
  signer used as an anchor (substring search) — never from RTMR.
- **Override/inherit**: `effective_code` is the only sanctioned way to get a node's code
  identity; raw `node.compose` is clearly documented as "override; empty = inherit".
- **Endpoints**: AS = `:50004` (verify); KBS `:8080` RCAR is not exposed by the SDK.

## 6. Phasing
- **v0 (extract & prove):** Rust core = chain reads + evidence parse + AS client +
  `verify_app`; port `verify_app.py` onto it; wire tapp-cli's read/verify paths to it.
- **v1 (bindings):** Python (replace the script) + TypeScript (frontend/indexer).
- **v2 (writes):** optional tx helpers (register/add-node/update with inherit logic).

## 7. Open questions
- Crate boundary: new `tapp-sdk` crate vs. a public surface on `tapp_service`?
- Binding tech: uniffi vs napi-rs (TS), pyo3 vs grpc-gateway?
- ~~Does the contract want a `getEffectiveCode(appId,signer)` view?~~ **Decided:** `getNode`
  itself resolves the inherited override → app-level default on read, so non-SDK consumers
  (cast/explorers) already get the effective value. The SDK just wraps `getNode`.
- AS endpoint discovery: hardcode per-env, or read a node's evidence URL + a registry of
  AS endpoints?
