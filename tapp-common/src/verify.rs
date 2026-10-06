//! End-to-end app verification: on-chain registry → fetch evidence per node →
//! CoCo-AS quote verification → reconcile evidence against on-chain values.
//!
//! This is the Rust core of the verification flow (port of docs/verify_app.py);
//! `tapp-cli verify-app` is a thin wrapper. Intended to be extracted into the SDK.

use anyhow::{anyhow, Result};
use base64::Engine;
use std::collections::{HashMap, HashSet};

use crate::onchain;
use crate::proto::{tapp_service_client::TappServiceClient, GetEvidenceRequest};

use crate::as_proto::attestation_service_client::AttestationServiceClient;
use crate::as_proto::{AttestationRequest, IndividualAttestationRequest};

const B64: base64::engine::general_purpose::GeneralPurpose = base64::engine::general_purpose::STANDARD;
const B64URL: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Per-node verification result.
pub struct NodeVerdict {
    pub signer: String, // on-chain signer (0x…)
    pub tee_url: String,
    pub reachable: bool,
    pub ear_status: String, // affirming | warning | contraindicated | -
    pub tcb_status: String,
    pub advisories: usize,
    pub signer_ok: bool,  // report_data binds the on-chain signer
    /// sha256 of the TLS public key the quote vouches for, `0x…`. Empty when the app has
    /// no TLS key. A client that compares this against the certificate it was served
    /// during a handshake learns the peer holds a key attested inside this TEE — which is
    /// the whole of layer-1 verification, and needs no CA.
    pub tls_public_key: String,
    pub compose_ok: bool, // start_app compose == node effective compose
    pub volumes_ok: bool,
    pub image_ok: bool,
    pub boot_executables: Option<i64>, // AR4SI executables claim (3 = boot chain matched policy)
    /// Boot-chain component digests from the eventlog (printed when no policy selected).
    pub boot_measurements: Vec<(String, String)>,
    /// claim_config owner from event log:
    ///   Some(Ok(addr))  = found and matches on-chain app owner
    ///   Some(Err(addr)) = found but mismatches (addr is what the event says)
    ///   None            = no claim_config event found in event log
    pub owner_claim: Option<Result<String, String>>,
    /// Trust anchors in force per the event log. Reported rather than judged: which verifier
    /// a node believes is the operator's decision, but it is measured, so it is auditable —
    /// and a node with none configured cannot check KMS node identity at all.
    pub trust_anchors: Option<TrustAnchors>,
    /// Whether the quote echoed the challenge sent for it: `Some(false)` means it was
    /// produced for some other request, `None` that the server predates the field.
    pub fresh: Option<bool>,
    /// The relay the evidence came through, when the node did not answer directly.
    pub relayed_by: Option<String>,
    /// The AS replayed the event log and every entry hashes to what was extended — the
    /// condition for believing anything read from it (start_app, claim_config).
    pub replay_ok: bool,
    /// The boot chain against the published reference values.
    pub boot_chain: crate::refvalues::BootChain,
    pub note: String,
}

impl NodeVerdict {
    /// A quote that echoes some other challenge is never accepted. Through a relay,
    /// freshness must also be PROVEN: replaying an old, genuine quote is the one thing
    /// a relay can do, and the echoed challenge is the only thing that rules it out.
    pub fn reconciled(&self) -> bool {
        self.signer_ok
            && self.compose_ok
            && self.volumes_ok
            && self.image_ok
            && self.replay_ok
            && self.fresh != Some(false)
            && (self.relayed_by.is_none() || self.fresh == Some(true))
    }
}

pub struct AppVerdict {
    pub app_id: String,
    pub nodes: Vec<NodeVerdict>,
}

struct StartAppMeasure {
    compose_hash: String,                  // hex
    volumes_hash: HashMap<String, String>, // file -> hex (empty for legacy string format)
    image_hash: HashMap<String, String>,   // service -> "sha256:…"
}

/// What a quote's `report_data` commits to, read in whichever era applies.
struct Attested {
    /// The signer the quote names, `0x…`. Empty if it could not be read.
    signer: String,
    /// sha256 of the app's TLS public key, `0x…`, empty when the app has no TLS key yet.
    /// A client compares this against the key it was handed during a handshake.
    tls_public_key: String,
    /// `None` when no challenge was sent or the server predates the field, so a caller
    /// that does not care about freshness is never reported as failing.
    fresh: Option<bool>,
    /// False means the old signer-only `report_data`, which carries no challenge at all.
    structured: bool,
    note: String,
}

impl Attested {
    /// True when `signer` is the address the caller expected.
    fn is(&self, expected: &[u8]) -> bool {
        crate::report_data::strip_hex(&self.signer).eq_ignore_ascii_case(&hex::encode(expected))
    }
}

/// Read the signer, and the challenge if there is one, out of a quote.
///
/// Which era applies is decided by whether the evidence carries a `runtime_data` field —
/// never guessed from the bytes:
///
/// - **With it**, `report_data` is `sha512(runtime_data)`. Recompute from the bytes as
///   received (never re-serialise) and read the fields out of the structure. Confirming
///   the challenge came back is the only way to tell a fresh quote from a replayed one.
/// - **Without it**, `report_data` is the bare 20-byte address. Take the leading 20
///   bytes — that is where every server that produced this format put it.
fn read_report_data(evidence: &serde_json::Value, quote_b64: &str, nonce: &[u8]) -> Attested {
    let mut a = Attested {
        signer: String::new(),
        tls_public_key: String::new(),
        fresh: None,
        structured: false,
        note: String::new(),
    };

    let rd = match quote_report_data(quote_b64) {
        Ok(rd) => rd,
        Err(e) => {
            a.note = format!("quote parse failed: {}; ", e);
            return a;
        }
    };

    let Some(rdata_b64) = evidence[crate::report_data::EVIDENCE_FIELD].as_str() else {
        a.signer = format!("0x{}", hex::encode(&rd[..20]));
        if !nonce.is_empty() {
            a.note = "server predates the challenge field, freshness unproven; ".to_string();
        }
        return a;
    };
    a.structured = true;

    let bytes = match B64.decode(rdata_b64) {
        Ok(b) => b,
        Err(e) => {
            a.note = format!("runtime_data b64: {}; ", e);
            return a;
        }
    };
    if crate::report_data::report_data_of(&bytes) != rd {
        a.note = "runtime_data does not hash to the quote's report_data; ".to_string();
        return a;
    }
    let parsed: crate::report_data::RuntimeData = match serde_json::from_slice(&bytes) {
        Ok(p) => p,
        Err(e) => {
            a.note = format!("runtime_data parse: {}; ", e);
            return a;
        }
    };

    a.signer = parsed.signer;
    a.tls_public_key = parsed.tls_public_key;
    if !nonce.is_empty() {
        let echoed = crate::report_data::strip_hex(&parsed.nonce)
            .eq_ignore_ascii_case(&hex::encode(nonce));
        a.fresh = Some(echoed);
        if !echoed {
            a.note =
                "challenge not echoed — this evidence was not produced for this request; "
                    .to_string();
        }
    }
    a
}

/// report_data (64 bytes) from a TDX quote, header offset resolved by version (v4=48, v5=54).
fn quote_report_data(quote_b64: &str) -> Result<Vec<u8>> {
    let q = B64.decode(quote_b64).map_err(|e| anyhow!("quote b64: {}", e))?;
    if q.len() < 2 {
        return Err(anyhow!("quote too short"));
    }
    let ver = u16::from_le_bytes([q[0], q[1]]);
    let hdr = match ver {
        4 => 48,
        5 => 54,
        v => return Err(anyhow!("unsupported quote version {}", v)),
    };
    let body = q
        .get(hdr..hdr + 584)
        .ok_or_else(|| anyhow!("quote body out of range"))?;
    Ok(body[520..584].to_vec())
}

fn alg_size(alg: u16) -> usize {
    match alg {
        4 => 20,
        0xb => 32,
        0xc => 48,
        0xd => 64,
        _ => 48,
    }
}

/// Parse the cc_eventlog (TCG2) and return the latest successful `start_app` measurement
/// for `app_id` (from the `tapp.0g.com start_app {…}` EV_EVENT_TAG runtime events).
fn latest_successful_start(cc_eventlog_b64: &str, app_id: &str) -> Result<Option<StartAppMeasure>> {
    let log = B64.decode(cc_eventlog_b64).map_err(|e| anyhow!("eventlog b64: {}", e))?;
    let u32le = |b: &[u8]| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize;

    // skip SpecID event: pcr(4)+type(4)+sha1(20)+size(4)+data
    let mut o = 8 + 20;
    if o + 4 > log.len() {
        return Ok(None);
    }
    let ds = u32le(&log[o..o + 4]);
    o += 4 + ds;

    let mut last: Option<StartAppMeasure> = None;
    while o + 12 <= log.len() {
        o += 4; // pcrIndex
        let et = u32le(&log[o..o + 4]);
        o += 4;
        let cnt = u32le(&log[o..o + 4]);
        o += 4;
        for _ in 0..cnt {
            if o + 2 > log.len() {
                return Ok(last);
            }
            let alg = u16::from_le_bytes([log[o], log[o + 1]]);
            o += 2 + alg_size(alg);
        }
        if o + 4 > log.len() {
            break;
        }
        let dl = u32le(&log[o..o + 4]);
        o += 4;
        if o + dl > log.len() {
            break;
        }
        let data = &log[o..o + dl];
        o += dl;

        if et == 0x6 && dl >= 8 {
            let tsz = u32le(&data[4..8]);
            if 8 + tsz <= data.len() {
                if let Ok(text) = std::str::from_utf8(&data[8..8 + tsz]) {
                    if let Some(payload) = text.strip_prefix("tapp.0g.com start_app ") {
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(payload) {
                            if v["app_id"].as_str() == Some(app_id)
                                && v["result"].as_str() == Some("success")
                            {
                                last = Some(StartAppMeasure {
                                    compose_hash: v["compose_hash"]
                                        .as_str()
                                        .unwrap_or("")
                                        .to_string(),
                                    volumes_hash: json_str_map(&v["volumes_hash"]),
                                    image_hash: json_str_map(&v["image_hash"]),
                                });
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(last)
}

/// Parse the cc_eventlog and extract the claimed owner from `claim_config` events.
/// Returns:
///   Ok(Some(owner)) — all claim_config events agree, returns the (normalized) owner
///   Ok(None)        — no claim_config events found
///   Err(msg)        — events found but inconsistent owners
fn eventlog_claim_config_owner(cc_eventlog_b64: &str) -> Result<Option<String>> {
    let log = B64.decode(cc_eventlog_b64).map_err(|e| anyhow!("eventlog b64: {}", e))?;
    let u32le = |b: &[u8]| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize;

    let mut o = 8 + 20;
    if o + 4 > log.len() { return Ok(None); }
    let ds = u32le(&log[o..o + 4]);
    o += 4 + ds;

    let mut owners: Vec<String> = Vec::new();
    while o + 12 <= log.len() {
        o += 4;
        let et = u32le(&log[o..o + 4]); o += 4;
        let cnt = u32le(&log[o..o + 4]); o += 4;
        for _ in 0..cnt {
            if o + 2 > log.len() { return Ok(owners.into_iter().next()); }
            let alg = u16::from_le_bytes([log[o], log[o + 1]]);
            o += 2 + alg_size(alg);
        }
        if o + 4 > log.len() { break; }
        let dl = u32le(&log[o..o + 4]); o += 4;
        if o + dl > log.len() { break; }
        let data = &log[o..o + dl]; o += dl;

        if et == 0x6 && dl >= 8 {
            let tsz = u32le(&data[4..8]);
            if 8 + tsz <= data.len() {
                if let Ok(text) = std::str::from_utf8(&data[8..8 + tsz]) {
                    if let Some(payload) = text.strip_prefix("tapp.0g.com claim_config ") {
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(payload) {
                            if let Some(owner) = v["owner"].as_str() {
                                owners.push(owner.to_lowercase());
                            }
                        }
                    }
                }
            }
        }
    }

    if owners.is_empty() { return Ok(None); }
    let first = owners[0].clone();
    if owners.iter().all(|o| o == &first) {
        Ok(Some(first))
    } else {
        Err(anyhow!("inconsistent claim_config owners: {:?}", owners))
    }
}

/// Every `tapp.0g.com <operation> <json>` event with the given operation, in log order.
///
/// (The TCG walk here is a fourth copy of the same loop. Left duplicated rather than
/// refactoring three working parsers as a side effect of adding a feature.)
fn eventlog_tapp_events(cc_eventlog_b64: &str, operation: &str) -> Result<Vec<serde_json::Value>> {
    let log = B64.decode(cc_eventlog_b64).map_err(|e| anyhow!("eventlog b64: {}", e))?;
    let u32le = |b: &[u8]| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize;
    let prefix = format!("tapp.0g.com {} ", operation);

    let mut out = Vec::new();
    let mut o = 8 + 20;
    if o + 4 > log.len() {
        return Ok(out);
    }
    let ds = u32le(&log[o..o + 4]);
    o += 4 + ds;

    while o + 12 <= log.len() {
        o += 4;
        let et = u32le(&log[o..o + 4]);
        o += 4;
        let cnt = u32le(&log[o..o + 4]);
        o += 4;
        for _ in 0..cnt {
            if o + 2 > log.len() {
                return Ok(out);
            }
            let alg = u16::from_le_bytes([log[o], log[o + 1]]);
            o += 2 + alg_size(alg);
        }
        if o + 4 > log.len() {
            break;
        }
        let dl = u32le(&log[o..o + 4]);
        o += 4;
        if o + dl > log.len() {
            break;
        }
        let data = &log[o..o + dl];
        o += dl;

        if et == 0x6 && dl >= 8 {
            let tsz = u32le(&data[4..8]);
            if 8 + tsz <= data.len() {
                if let Ok(text) = std::str::from_utf8(&data[8..8 + tsz]) {
                    if let Some(payload) = text.strip_prefix(prefix.as_str()) {
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(payload) {
                            out.push(v);
                        }
                    }
                }
            }
        }
    }
    Ok(out)
}

/// Which KMS cluster the node fetches key material from, and which verifier it believes
/// about that cluster's identity — as the event log currently stands.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct TrustAnchors {
    pub kbs_node_urls: Vec<String>,
    pub scan_url: String,
    pub scan_public_key: String,
    /// How many times the anchors were revised after the claim. Not a fault on its own —
    /// a verifier restart legitimately forces one — but it is history a reader is entitled
    /// to see, and the reason these events carry the resulting state rather than a delta.
    pub revisions: usize,
}

/// The anchors in force, read from the newest event that sets them.
///
/// `update_trust_anchors` events carry the resulting state in full, so the newest one is
/// the answer outright with no replay. Falling back to `claim_config` covers a node whose
/// anchors were never revised. Both are taken newest-first because these are deliberately
/// mutable: earlier events are history, not conflicts — unlike the owner, which cannot
/// change and where disagreement is a finding.
fn eventlog_trust_anchors(cc_eventlog_b64: &str) -> Result<Option<TrustAnchors>> {
    let updates = eventlog_tapp_events(cc_eventlog_b64, "update_trust_anchors")?;
    let revisions = updates.len();
    let source = match updates.last() {
        Some(v) => v.clone(),
        None => match eventlog_tapp_events(cc_eventlog_b64, "claim_config")?.last() {
            Some(v) => v.clone(),
            None => return Ok(None),
        },
    };
    Ok(Some(TrustAnchors {
        kbs_node_urls: source["kbs_node_urls"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|u| u.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default(),
        scan_url: source["scan_url"].as_str().unwrap_or("").to_string(),
        scan_public_key: source["scan_public_key"].as_str().unwrap_or("").to_string(),
        revisions,
    }))
}

fn json_str_map(v: &serde_json::Value) -> HashMap<String, String> {
    let mut m = HashMap::new();
    if let Some(obj) = v.as_object() {
        for (k, val) in obj {
            if let Some(s) = val.as_str() {
                m.insert(k.clone(), s.to_string());
            }
        }
    }
    m
}

/// CoCo-AS AR4SI `executables` trust-claim value meaning the boot chain matched the
/// policy's reference values ("only a recognized set of approved executables was loaded").
pub const EXECUTABLES_MATCHED: i64 = 3;

/// Result of submitting evidence to the AS.
pub struct AsVerdict {
    pub ear_status: String,
    pub tcb_status: String,
    pub advisories: usize,
    /// AR4SI executables trust claim (== EXECUTABLES_MATCHED when the boot chain matched
    /// the policy reference values); None if the policy set no executables / no policy applied.
    pub executables: Option<i64>,
    /// Boot-chain digests from the token's parsed event log — signed by the AS, unlike the
    /// raw event log in the evidence.
    pub measured: crate::refvalues::Measured,
    /// Event-log entries the AS found not to hash to their extended digest.
    pub replay_mismatches: usize,
}

/// A bare `host:port` means plaintext, which is what the shared AS speaks today. An endpoint
/// that names its own scheme is passed through, so `https://as.example:50004` works the day
/// the AS terminates TLS without anything here changing.
///
/// Plaintext is a real exposure and not one this side can close: the verdict is an assertion
/// with no internal proof — unlike the evidence it is about, which authenticates itself — so
/// anyone on the path can rewrite it and report any node as affirming. See 0g-tapp#99.
fn as_grpc_url(as_endpoint: &str) -> String {
    if as_endpoint.contains("://") {
        as_endpoint.to_string()
    } else {
        format!("http://{}", as_endpoint)
    }
}

/// Connect to the AS, using TLS when the endpoint asks for it.
///
/// A TLS AS is a TEE serving a self-signed certificate, so certificate-authority validation
/// is replaced by pinning its attested key — the same decision, and the same code, as for a
/// KMS node. Passing `as_pubkey` is what makes the verdict worth anything: without it the
/// connection is encrypted but unauthenticated, and whoever is on the path can return any
/// verdict they like. Callers that supply nothing are told so rather than being refused,
/// since a tool that reports "unverified" is more useful than one that will not run.
async fn connect_as(
    as_endpoint: &str,
    as_pubkey: Option<&str>,
) -> Result<AttestationServiceClient<tonic::transport::Channel>> {
    let url = as_grpc_url(as_endpoint);
    if !url.starts_with("https://") {
        return AttestationServiceClient::connect(url)
            .await
            .map_err(|e| anyhow!("connect AS {}: {}", as_endpoint, e));
    }

    // Empty means encrypted-but-unauthenticated, which the caller is told about rather
    // than refused for — a diagnostic tool that reports "unverified" beats one that will
    // not run. Nothing that fetches key material may take this branch.
    let expected: Vec<String> = as_pubkey
        .filter(|k| !k.is_empty())
        .map(|k| vec![k.to_string()])
        .unwrap_or_default();
    let channel = crate::pinned_tls::grpc_channel(&url, expected)
        .await
        .map_err(|e| anyhow!("{}", e))?;
    Ok(AttestationServiceClient::new(channel))
}

/// Submit evidence to CoCo-AS (gRPC). `policy_ids` selects the policy to enforce; pass an
/// empty slice to use the AS default policy (which does NOT check our boot chain).
async fn verify_with_as(
    as_endpoint: &str,
    as_pubkey: Option<&str>,
    raw_evidence: &[u8],
    policy_ids: &[String],
) -> Result<AsVerdict> {
    let mut client = connect_as(as_endpoint, as_pubkey).await?;
    let req = AttestationRequest {
        verification_requests: vec![IndividualAttestationRequest {
            tee: "tdx".to_string(),
            evidence: B64URL.encode(raw_evidence),
            // Left unset deliberately. report_data is now sha512 of the runtime_data we
            // could hand over here, which would make the AS check the binding for us — but
            // only if its hash choice matches ours, and that is unconfirmed. Until then we
            // check it ourselves in read_report_data, which loses nothing.
            runtime_data: None,
            init_data: None,
            runtime_data_hash_algorithm: String::new(),
        }],
        policy_ids: policy_ids.to_vec(),
    };
    let token = client
        .attestation_evaluate(req)
        .await
        .map_err(|e| anyhow!("AttestationEvaluate: {}", e))?
        .into_inner()
        .attestation_token;

    // EAR token is a JWT; decode the payload (middle segment) — the AS already verified.
    let seg = token
        .split('.')
        .nth(1)
        .ok_or_else(|| anyhow!("malformed attestation token"))?;
    let payload = B64URL
        .decode(seg)
        .map_err(|e| anyhow!("token payload b64: {}", e))?;
    let claims: serde_json::Value = serde_json::from_slice(&payload)?;
    let cpu0 = &claims["submods"]["cpu0"];
    let ear_status = cpu0["ear.status"].as_str().unwrap_or("unknown").to_string();
    let executables = cpu0["ear.trustworthiness-vector"]["executables"].as_i64();
    let tdx = &cpu0["ear.veraison.annotated-evidence"]["tdx"];
    let tcb = tdx["tcb_status"].as_str().unwrap_or("unknown").to_string();
    let adv = tdx["advisory_ids"].as_array().map(|a| a.len()).unwrap_or(0);
    let logs = tdx["uefi_event_logs"].as_array().cloned().unwrap_or_default();

    Ok(AsVerdict {
        ear_status,
        tcb_status: tcb,
        advisories: adv,
        executables,
        measured: crate::refvalues::boot_digests(&logs),
        replay_mismatches: crate::refvalues::replay_mismatches(&logs),
    })
}

/// A fresh challenge. Random per call, never a counter or a timestamp: the point is that
/// the node cannot have produced this quote before we asked.
fn fresh_nonce() -> Vec<u8> {
    use rand::RngCore;
    let mut n = vec![0u8; 16];
    rand::thread_rng().fill_bytes(&mut n);
    n
}

/// How long a node gets to accept a connection before it counts as unreachable. A port
/// closed by a firewall usually drops rather than refuses, which would otherwise hang
/// for minutes.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);

/// Where a fetch failed: before the node answered (worth trying the relay) or after
/// (the node itself said no, and a relay would only repeat it).
enum FetchError {
    Unreachable(anyhow::Error),
    Failed(anyhow::Error),
}

impl From<FetchError> for anyhow::Error {
    fn from(e: FetchError) -> Self {
        match e {
            FetchError::Unreachable(e) | FetchError::Failed(e) => e,
        }
    }
}

async fn fetch_evidence(tee_url: &str, app_id: &str, nonce: &[u8]) -> Result<Vec<u8>, FetchError> {
    // An https teeUrl (the node's :50052 TLS listener serves a per-boot
    // self-signed cert) gets encryption without authentication: evidence is
    // Intel-signed and carries our nonce, so the channel needs no identity of
    // its own — the same reasoning as the pinless AS connection above.
    let connect = async {
        if tee_url.starts_with("https://") {
            crate::pinned_tls::grpc_channel(tee_url, Vec::new())
                .await
                .map(TappServiceClient::new)
                .map_err(|e| anyhow!("connect {}: {}", tee_url, e))
        } else {
            TappServiceClient::connect(tee_url.to_string())
                .await
                .map_err(|e| anyhow!("connect {}: {}", tee_url, e))
        }
    };
    let mut client = match tokio::time::timeout(CONNECT_TIMEOUT, connect).await {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => return Err(FetchError::Unreachable(e)),
        Err(_) => {
            return Err(FetchError::Unreachable(anyhow!(
                "connect {}: no answer within {}s",
                tee_url,
                CONNECT_TIMEOUT.as_secs()
            )))
        }
    };
    let resp = client
        .get_evidence(tonic::Request::new(GetEvidenceRequest {
            app_id: app_id.to_owned(),
            nonce: nonce.to_vec(),
        }))
        .await
        .map_err(|e| FetchError::Failed(anyhow!("{}", e)))?
        .into_inner();
    Ok(resp.evidence)
}

/// The scan that relays evidence for nodes of a known registry. A node whose port is
/// closed to the caller is reached through it — transport only: what comes back is
/// checked here exactly as if fetched directly, challenge included.
pub fn known_relay(contract: &str) -> Option<&'static str> {
    match contract.to_ascii_lowercase().as_str() {
        "0x2ce80374318b1d7fb3345724457a182e0ad165c9" => Some("https://tappscan.0g.ai"),
        "0x54874f536301c993922dd95097e3902e7fbfe612" => Some("https://tappscan.0g.ai/mainnet"),
        _ => None,
    }
}

/// Path segments are escaped, so an app id cannot reach any other endpoint of the scan.
fn relay_url(scan: &str, app_id: &str, signer: &str, nonce: &[u8]) -> Result<reqwest::Url> {
    let mut url = reqwest::Url::parse(scan).map_err(|e| anyhow!("scan url {}: {}", scan, e))?;
    url.path_segments_mut()
        .map_err(|_| anyhow!("scan url {} cannot take a path", scan))?
        .pop_if_empty()
        .extend(["api", "apps", app_id, "nodes", signer, "evidence"]);
    url.query_pairs_mut()
        .append_pair("nonce", &format!("0x{}", hex::encode(nonce)));
    Ok(url)
}

/// Fetch a node's evidence through a scan's relay
/// (`GET {scan}/api/apps/{app}/nodes/{signer}/evidence?nonce=…`), for nodes whose port
/// is open only to the scan and their operators. Nothing in the answer is trusted but
/// the evidence bytes, and those are checked exactly as if fetched directly — the
/// challenge included, which is what keeps the relay from passing off an old quote.
async fn fetch_evidence_via_scan(
    scan: &str,
    app_id: &str,
    signer: &str,
    nonce: &[u8],
) -> Result<Vec<u8>> {
    let url = relay_url(scan, app_id, signer, nonce)?;
    let resp = reqwest::get(url.clone())
        .await
        .map_err(|e| anyhow!("scan {}: {}", url, e))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow!("scan answered {}: {}", status, body.trim()));
    }
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| anyhow!("scan response: {}", e))?;
    let evidence = body["evidence"]
        .as_str()
        .ok_or_else(|| anyhow!("scan response has no evidence"))?;
    B64.decode(evidence)
        .map_err(|e| anyhow!("scan evidence b64: {}", e))
}

/// Direct (no-chain) verification of a single server: fetch evidence, verify the quote
/// via CoCo-AS, and report what the node attests. No on-chain reconciliation — used when
/// the app is not (yet) registered on-chain, or to check one node directly.
pub struct DirectVerdict {
    pub server: String,
    pub signer: String, // from quote report_data (0x…), as attested (not reconciled)
    /// sha256 of the attested TLS public key, `0x…`. Empty when the app has no TLS key.
    pub tls_public_key: String,
    pub ear_status: String,
    pub tcb_status: String,
    pub advisories: usize,
    pub boot_executables: Option<i64>, // AR4SI executables claim (3 = boot chain matched policy)
    /// Boot-chain measurements from AS (printed when no policy selected).
    pub boot_measurements: Vec<(String, String)>,
    pub compose_hash: String, // from latest successful start_app, if any
    pub images: Vec<String>,
    /// Owner address from claim_config event (if present). No chain comparison in direct mode.
    pub claimed_owner: Option<String>,
    /// Trust anchors in force per the event log — see NodeVerdict.
    pub trust_anchors: Option<TrustAnchors>,
    pub replay_ok: bool,
    pub boot_chain: crate::refvalues::BootChain,
    pub note: String,
}

pub async fn verify_node_direct(
    server: &str,
    app_id: &str,
    as_endpoint: &str,
    as_pubkey: Option<&str>,
    policy_ids: &[String],
    refs: Option<&[crate::refvalues::RefSet]>,
) -> Result<DirectVerdict> {
    let mut v = DirectVerdict {
        server: server.to_string(),
        signer: String::new(),
        tls_public_key: String::new(),
        ear_status: "-".to_string(),
        tcb_status: "-".to_string(),
        advisories: 0,
        boot_executables: None,
        boot_measurements: Vec::new(),
        compose_hash: String::new(),
        images: Vec::new(),
        claimed_owner: None,
        trust_anchors: None,
        replay_ok: false,
        boot_chain: crate::refvalues::BootChain::NotChecked,
        note: String::new(),
    };

    let nonce = fresh_nonce();
    let raw = fetch_evidence(server, app_id, &nonce).await?;
    let j: serde_json::Value = serde_json::from_slice(&raw)?;
    let quote_b64 = j["quote"].as_str().unwrap_or("");
    let cc_b64 = j["cc_eventlog"].as_str().unwrap_or("");

    // There is no on-chain signer to compare against here — the whole point of this path
    // is that the app may not be registered — so report what the node attested.
    let attested = read_report_data(&j, quote_b64, &nonce);
    v.signer = attested.signer.clone();
    v.tls_public_key = attested.tls_public_key.clone();
    v.note = attested.note.clone();

    match verify_with_as(as_endpoint, as_pubkey, &raw, policy_ids).await {
        Ok(av) => {
            v.ear_status = av.ear_status;
            v.tcb_status = av.tcb_status;
            v.advisories = av.advisories;
            v.boot_executables = av.executables;
            v.boot_measurements = av.measured.as_reference_pairs();
            v.boot_chain = crate::refvalues::identify(&av.measured, refs);
            v.replay_ok = av.replay_mismatches == 0;
        }
        Err(e) => v.note = format!("{}AS: {}", v.note, e),
    }

    if let Ok(Some(m)) = latest_successful_start(cc_b64, app_id) {
        v.compose_hash = m.compose_hash;
        v.images = m.image_hash.into_values().collect();
    }

    // claim_config owner — direct mode: print without chain comparison
    match eventlog_claim_config_owner(cc_b64) {
        Ok(owner) => v.claimed_owner = owner,
        Err(e) => v.note = format!("{}claim_config: {}", v.note, e),
    }

    if let Ok(anchors) = eventlog_trust_anchors(cc_b64) {
        v.trust_anchors = anchors;
    }

    Ok(v)
}

/// Verify every node of `app_id`: read chain, fetch evidence from each node's teeUrl,
/// verify the quote via CoCo-AS, and reconcile evidence against on-chain values.
/// Chain-mode verification of every node of `app_id`. A node that does not answer on its
/// teeUrl is reached through `relay` (default: the scan for this registry, see
/// [`known_relay`]). `refs` are the published reference values; `None` leaves the boot
/// chain unchecked rather than failed.
pub async fn verify_app(
    rpc_url: &str,
    contract: &str,
    app_id: &str,
    as_endpoint: &str,
    as_pubkey: Option<&str>,
    policy_ids: &[String],
    relay: Option<&str>,
    refs: Option<&[crate::refvalues::RefSet]>,
) -> Result<AppVerdict> {
    let relay = relay.or_else(|| known_relay(contract));
    let signers = onchain::get_node_list(rpc_url, contract, app_id).await?;
    if signers.is_empty() {
        return Err(anyhow!("app '{}' has no registered nodes on-chain", app_id));
    }
    let app_image_set: HashSet<Vec<u8>> = onchain::get_app_image_hashes(rpc_url, contract, app_id)
        .await?
        .into_iter()
        .collect();
    // On-chain app owner (who registered the app via registerApp)
    let onchain_owner = onchain::get_app_owner(rpc_url, contract, app_id)
        .await
        .ok()
        .map(|a| format!("0x{:x}", a))
        .unwrap_or_default();

    let mut nodes = Vec::new();
    for signer in signers {
        let mut v = NodeVerdict {
            signer: format!("0x{}", hex::encode(signer.as_bytes())),
            tee_url: String::new(),
            reachable: false,
            ear_status: "-".to_string(),
            tcb_status: "-".to_string(),
            advisories: 0,
            signer_ok: false,
            tls_public_key: String::new(),
            compose_ok: false,
            volumes_ok: false,
            image_ok: false,
            boot_executables: None,
            boot_measurements: Vec::new(),
            owner_claim: None,
            trust_anchors: None,
            fresh: None,
            relayed_by: None,
            replay_ok: false,
            boot_chain: crate::refvalues::BootChain::NotChecked,
            note: String::new(),
        };

        // ① chain: node teeUrl + effective compose/volumes
        let (tee_url, eff_compose, eff_volumes) =
            match onchain::get_node(rpc_url, contract, app_id, signer).await {
                Ok(x) => x,
                Err(e) => {
                    v.note = format!("getNode failed: {}", e);
                    nodes.push(v);
                    continue;
                }
            };
        v.tee_url = tee_url.clone();

        // ② fetch evidence, with a challenge so a cached blob is distinguishable
        let nonce = fresh_nonce();
        let fetched = match fetch_evidence(&tee_url, app_id, &nonce).await {
            Ok(b) => Ok(b),
            Err(FetchError::Unreachable(e)) => match relay {
                // The node never saw this challenge, so it is still fresh to use.
                Some(r) => {
                    v.relayed_by = Some(r.to_string());
                    fetch_evidence_via_scan(r, app_id, &v.signer, &nonce)
                        .await
                        .map_err(|re| anyhow!("{}; relayed by {}: {}", e, r, re))
                }
                None => Err(e),
            },
            Err(FetchError::Failed(e)) => Err(e),
        };
        let raw = match fetched {
            Ok(b) => b,
            Err(e) => {
                v.note = format!("get-evidence failed: {}", e);
                nodes.push(v);
                continue;
            }
        };
        v.reachable = true;
        let j: serde_json::Value = match serde_json::from_slice(&raw) {
            Ok(x) => x,
            Err(e) => {
                v.note = format!("evidence not JSON: {}", e);
                nodes.push(v);
                continue;
            }
        };
        let quote_b64 = j["quote"].as_str().unwrap_or("");
        let cc_b64 = j["cc_eventlog"].as_str().unwrap_or("");

        // ④a signer binding: the quote names the signer the chain registered
        let attested = read_report_data(&j, quote_b64, &nonce);
        v.signer_ok = attested.is(signer.as_bytes());
        v.tls_public_key = attested.tls_public_key.clone();
        v.fresh = attested.fresh;
        v.note = attested.note.clone();

        // ③ AS quote verification
        match verify_with_as(as_endpoint, as_pubkey, &raw, policy_ids).await {
            Ok(av) => {
                v.ear_status = av.ear_status;
                v.tcb_status = av.tcb_status;
                v.advisories = av.advisories;
                v.boot_executables = av.executables;
                v.boot_measurements = av.measured.as_reference_pairs();
                v.boot_chain = crate::refvalues::identify(&av.measured, refs);
                v.replay_ok = av.replay_mismatches == 0;
                if !v.replay_ok {
                    v.note = format!(
                        "{}{} measured tapp events do not hash to what was extended; ",
                        v.note, av.replay_mismatches
                    );
                }
            }
            Err(e) => v.note = format!("{}AS: {}", v.note, e),
        }

        // ④b reconcile compose/volumes/image vs chain
        match latest_successful_start(cc_b64, app_id) {
            Ok(Some(m)) => {
                if let Ok(c) = hex::decode(&m.compose_hash) {
                    v.compose_ok = c == eff_compose;
                }
                v.volumes_ok = onchain::combine_map_hashes(&m.volumes_hash) == eff_volumes;
                let ev_imgs: HashSet<Vec<u8>> =
                    m.image_hash.values().map(|s| s.as_bytes().to_vec()).collect();
                v.image_ok = ev_imgs == app_image_set;
            }
            Ok(None) => v.note = format!("{}no successful start_app in eventlog", v.note),
            Err(e) => v.note = format!("{}eventlog parse: {}", v.note, e),
        }

        // ④c reconcile claim_config owner vs on-chain app owner
        match eventlog_claim_config_owner(cc_b64) {
            Ok(Some(claimed)) => {
                if onchain_owner.is_empty() || claimed == onchain_owner.to_lowercase() {
                    v.owner_claim = Some(Ok(claimed));
                } else {
                    v.owner_claim = Some(Err(claimed));
                }
            }
            Ok(None) => {} // no claim_config event — leave owner_claim as None
            Err(e) => v.note = format!("{}claim_config: {}", v.note, e),
        }

        if let Ok(anchors) = eventlog_trust_anchors(cc_b64) {
            v.trust_anchors = anchors;
        }

        nodes.push(v);
    }

    Ok(AppVerdict {
        app_id: app_id.to_string(),
        nodes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIGNER: [u8; 20] = [0x11; 20];

    #[test]
    fn a_bare_host_port_as_endpoint_stays_plaintext() {
        assert_eq!(as_grpc_url("1.2.3.4:50004"), "http://1.2.3.4:50004");
    }

    #[test]
    fn an_as_endpoint_that_names_its_scheme_is_not_downgraded() {
        // The bug this guards: prefixing unconditionally produced
        // "http://https://as.example:50004", so an operator who supplied a TLS
        // endpoint silently got plaintext or a connect error rather than TLS.
        assert_eq!(
            as_grpc_url("https://as.example:50004"),
            "https://as.example:50004"
        );
        assert_eq!(
            as_grpc_url("http://as.example:50004"),
            "http://as.example:50004"
        );
    }

    /// A TCG2 event log carrying the given `tapp.0g.com <op> <json>` events, in order.
    fn tcg_log(events: &[(&str, &str)]) -> String {
        let mut log = Vec::new();
        // SpecID header: the parser skips 8 + 20 bytes then a length-prefixed blob.
        log.extend_from_slice(&0u32.to_le_bytes()); // pcrIndex
        log.extend_from_slice(&3u32.to_le_bytes()); // EV_NO_ACTION
        log.extend_from_slice(&[0u8; 20]); // SHA1 digest
        let spec = b"Spec ID Event03\0";
        log.extend_from_slice(&(spec.len() as u32).to_le_bytes());
        log.extend_from_slice(spec);

        for (op, json) in events {
            let text = format!("tapp.0g.com {} {}", op, json);
            let mut data = Vec::new();
            data.extend_from_slice(&0u32.to_le_bytes()); // tagId
            data.extend_from_slice(&(text.len() as u32).to_le_bytes());
            data.extend_from_slice(text.as_bytes());

            log.extend_from_slice(&4u32.to_le_bytes()); // pcrIndex
            log.extend_from_slice(&6u32.to_le_bytes()); // EV_EVENT_TAG
            log.extend_from_slice(&1u32.to_le_bytes()); // one digest
            log.extend_from_slice(&0xcu16.to_le_bytes()); // SHA-384
            log.extend_from_slice(&[0u8; 48]);
            log.extend_from_slice(&(data.len() as u32).to_le_bytes());
            log.extend_from_slice(&data);
        }
        B64.encode(log)
    }

    fn anchors_event(scan: &str, kbs: &[&str]) -> String {
        serde_json::json!({
            "kbs_node_urls": kbs,
            "scan_url": scan,
            "scan_public_key": format!("0x{}", "ab".repeat(32)),
        })
        .to_string()
    }

    #[test]
    fn a_node_with_no_config_events_reports_no_anchors() {
        assert_eq!(eventlog_trust_anchors(&tcg_log(&[])).unwrap(), None);
    }

    #[test]
    fn anchors_come_from_the_claim_when_never_revised() {
        let log = tcg_log(&[(
            "claim_config",
            &anchors_event("https://scan.a", &["http://kms-1:9090"]),
        )]);
        let a = eventlog_trust_anchors(&log).unwrap().unwrap();
        assert_eq!(a.scan_url, "https://scan.a");
        assert_eq!(a.kbs_node_urls, vec!["http://kms-1:9090"]);
        assert_eq!(a.revisions, 0);
    }

    #[test]
    fn the_newest_revision_wins_and_the_older_ones_are_counted_not_lost() {
        // The property under test: these are deliberately mutable, so an earlier value is
        // history rather than a conflict — but the count must still surface, because "this
        // node was re-pointed three times" is exactly what an auditor needs to notice.
        let log = tcg_log(&[
            ("claim_config", &anchors_event("https://scan.a", &["http://kms-1:9090"])),
            ("update_trust_anchors", &anchors_event("https://scan.b", &["http://kms-2:9090"])),
            ("update_trust_anchors", &anchors_event("https://scan.c", &["http://kms-3:9090"])),
        ]);
        let a = eventlog_trust_anchors(&log).unwrap().unwrap();
        assert_eq!(a.scan_url, "https://scan.c");
        assert_eq!(a.kbs_node_urls, vec!["http://kms-3:9090"]);
        assert_eq!(a.revisions, 2);
    }

    #[test]
    fn a_second_claim_config_does_not_look_like_a_revision() {
        // Pre-baked mode re-claims on a process restart, so two claim_config events are
        // normal. Counting those as revisions would cry wolf on every restart.
        let log = tcg_log(&[
            ("claim_config", &anchors_event("https://scan.a", &["http://kms-1:9090"])),
            ("claim_config", &anchors_event("https://scan.a", &["http://kms-1:9090"])),
        ]);
        let a = eventlog_trust_anchors(&log).unwrap().unwrap();
        assert_eq!(a.revisions, 0);
        assert_eq!(a.scan_url, "https://scan.a");
    }

    #[test]
    fn other_tapp_events_are_not_mistaken_for_config() {
        let log = tcg_log(&[
            ("start_app", r#"{"app_id":"x","result":"success"}"#),
            ("get_app_secret_key", r#"{"app_id":"x"}"#),
        ]);
        assert_eq!(eventlog_trust_anchors(&log).unwrap(), None);
    }

    #[test]
    fn a_claim_that_configured_no_verifier_reports_empty_rather_than_absent() {
        // "No verifier configured" and "no config event at all" are different states and a
        // caller must not read one as the other: the first means identity cannot be checked.
        let log = tcg_log(&[("claim_config", r#"{"owner":"0xabc","kbs_node_urls":[]}"#)]);
        let a = eventlog_trust_anchors(&log).unwrap().unwrap();
        assert!(a.scan_url.is_empty());
        assert!(a.kbs_node_urls.is_empty());
    }

    /// Smallest thing `quote_report_data` will parse: v4 header (48 bytes) followed by a
    /// 584-byte body whose last 64 bytes are report_data.
    fn quote_with(report_data: &[u8]) -> String {
        let mut q = vec![0u8; 48 + 584];
        q[0..2].copy_from_slice(&4u16.to_le_bytes());
        q[48 + 520..48 + 584].copy_from_slice(report_data);
        B64.encode(q)
    }

    fn legacy_report_data(signer: &[u8]) -> Vec<u8> {
        let mut rd = vec![0u8; 64];
        rd[..signer.len()].copy_from_slice(signer);
        rd
    }

    #[test]
    fn a_server_that_predates_runtime_data_still_has_its_signer_read() {
        let quote = quote_with(&legacy_report_data(&SIGNER));
        let a = read_report_data(&serde_json::json!({}), &quote, &[]);
        assert!(a.is(&SIGNER));
        assert!(!a.structured);
        assert_eq!(a.fresh, None);
        assert!(a.note.is_empty());
    }

    #[test]
    fn sending_a_challenge_to_an_old_server_says_so_instead_of_failing_the_signer() {
        let quote = quote_with(&legacy_report_data(&SIGNER));
        let a = read_report_data(&serde_json::json!({}), &quote, b"chal");
        assert!(a.is(&SIGNER), "the signer binding still holds");
        assert_eq!(a.fresh, None, "not a failure — the server cannot answer it");
        assert!(a.note.contains("predates"), "got {}", a.note);
    }

    #[test]
    fn an_echoed_challenge_proves_the_quote_was_made_for_this_request() {
        let rdata = crate::report_data::RuntimeData::new(&SIGNER, b"chal").unwrap();
        let (bytes, rd) = rdata.seal().unwrap();
        let ev = serde_json::json!({ crate::report_data::EVIDENCE_FIELD: B64.encode(&bytes) });
        let a = read_report_data(&ev, &quote_with(&rd), b"chal");
        assert!(a.is(&SIGNER));
        assert!(a.structured);
        assert_eq!(a.fresh, Some(true));
        assert!(a.note.is_empty());
    }

    #[test]
    fn a_replayed_quote_is_caught_by_the_challenge_not_by_the_signer() {
        // Evidence produced for someone else's challenge: signer still binds, freshness does not.
        let rdata = crate::report_data::RuntimeData::new(&SIGNER, b"theirs").unwrap();
        let (bytes, rd) = rdata.seal().unwrap();
        let ev = serde_json::json!({ crate::report_data::EVIDENCE_FIELD: B64.encode(&bytes) });
        let a = read_report_data(&ev, &quote_with(&rd), b"mine");
        assert!(a.is(&SIGNER));
        assert_eq!(a.fresh, Some(false));
        assert!(a.note.contains("not echoed"), "got {}", a.note);
    }

    #[test]
    fn runtime_data_that_does_not_hash_to_the_quote_names_nobody() {
        // A structure swapped for one naming a different signer: it no longer reproduces
        // report_data, so nothing in it may be believed — including the signer.
        let (_, rd) = crate::report_data::RuntimeData::new(&SIGNER, b"chal")
            .unwrap()
            .seal()
            .unwrap();
        let (other, _) = crate::report_data::RuntimeData::new(&[0x22; 20], b"chal")
            .unwrap()
            .seal()
            .unwrap();
        let ev = serde_json::json!({ crate::report_data::EVIDENCE_FIELD: B64.encode(&other) });
        let a = read_report_data(&ev, &quote_with(&rd), b"chal");
        assert!(!a.is(&SIGNER));
        assert!(!a.is(&[0x22; 20]), "the swapped signer must not be believed either");
        assert!(a.note.contains("does not hash"), "got {}", a.note);
    }
}

#[cfg(test)]
mod relay_tests {
    use super::*;

    fn node(fresh: Option<bool>, relayed: bool) -> NodeVerdict {
        NodeVerdict {
            signer: "0x11".into(),
            tee_url: String::new(),
            reachable: true,
            ear_status: "affirming".into(),
            tcb_status: "UpToDate".into(),
            advisories: 0,
            signer_ok: true,
            tls_public_key: String::new(),
            compose_ok: true,
            volumes_ok: true,
            image_ok: true,
            boot_executables: None,
            boot_measurements: Vec::new(),
            owner_claim: None,
            trust_anchors: None,
            fresh,
            relayed_by: relayed.then(|| "https://tappscan.0g.ai".to_string()),
            replay_ok: true,
            boot_chain: crate::refvalues::BootChain::NotChecked,
            note: String::new(),
        }
    }

    #[test]
    fn a_quote_made_for_another_request_never_passes() {
        assert!(!node(Some(false), false).reconciled());
        assert!(!node(Some(false), true).reconciled());
    }

    #[test]
    fn through_a_relay_freshness_must_be_proven() {
        assert!(node(Some(true), true).reconciled());
        // An old server cannot echo a challenge, so a relay could be replaying its quote.
        assert!(!node(None, true).reconciled());
    }

    #[test]
    fn fetched_directly_an_old_server_still_passes() {
        assert!(node(None, false).reconciled());
        assert!(node(Some(true), false).reconciled());
    }

    #[test]
    fn an_event_log_that_does_not_replay_proves_nothing_read_from_it() {
        let mut n = node(Some(true), false);
        n.replay_ok = false;
        assert!(!n.reconciled());
    }

    #[test]
    fn each_known_registry_has_its_own_relay() {
        assert_eq!(
            known_relay("0x2Ce80374318B1d7Fb3345724457a182E0ad165c9"),
            Some("https://tappscan.0g.ai")
        );
        assert_eq!(
            known_relay("0x54874F536301c993922Dd95097e3902e7FBfe612"),
            Some("https://tappscan.0g.ai/mainnet")
        );
        // The relay only serves nodes of the registry it scans; a different one gets none.
        assert_eq!(known_relay("0x5f0d9c243048F5a55468472c6F090184E2E333c7"), None);
    }

    #[test]
    fn the_relay_url_names_the_node_and_carries_the_challenge() {
        let u = relay_url("https://tappscan.0g.ai", "0g-kms", "0xabc", &[0x01, 0xff]).unwrap();
        assert_eq!(
            u.as_str(),
            "https://tappscan.0g.ai/api/apps/0g-kms/nodes/0xabc/evidence?nonce=0x01ff"
        );
        // A base with a path (the mainnet instance) keeps it; a trailing slash adds nothing.
        let u = relay_url("https://tappscan.0g.ai/mainnet/", "a", "0x1", &[0x02]).unwrap();
        assert_eq!(
            u.as_str(),
            "https://tappscan.0g.ai/mainnet/api/apps/a/nodes/0x1/evidence?nonce=0x02"
        );
    }

    #[test]
    fn an_app_id_cannot_steer_the_request_elsewhere() {
        let u = relay_url("https://scan", "../../keys", "0x1", &[0x00]).unwrap();
        assert!(u.path().starts_with("/api/apps/"), "{}", u);
        assert!(!u.path().contains("/keys/") && u.path().contains("%2F"), "{}", u);
    }
}
