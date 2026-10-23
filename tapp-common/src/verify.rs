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
    /// The AS verified the quote: its signature chain leads to Intel. Until then nothing
    /// in the evidence is anything more than a claim.
    pub quote_ok: bool,
    /// sha256 of the TLS public key the quote vouches for, `0x…`. Empty when the app has
    /// no TLS key. A client that compares this against the certificate it was served
    /// during a handshake learns the peer holds a key attested inside this TEE — which is
    /// the whole of layer-1 verification, and needs no CA.
    pub tls_public_key: String,
    pub identity: crate::identity_verify::IdentityVerification,
    /// The KMS keys the app took on this node, as runtime_data lists them. Believe them
    /// only when [`NodeVerdict::kms_keys_attested`] holds; see
    /// [`AppVerdict::kms_key_conflicts`] for the check across nodes.
    pub kms_keys: Vec<crate::report_data::KmsKey>,
    /// Keys the event log says the app took this boot that runtime_data does not list: a
    /// tapp-server that could not read the log back when it started. Compared like the
    /// listed ones. Empty unless the event log replays.
    pub kms_keys_logged_only: Vec<crate::report_data::KmsKey>,
    /// How many of the keys (listed or logged only) have no `get_secret_resource` event
    /// saying the KMS answered over a connection checked against attestation: taken with
    /// no verifier, or from a node reached over plain http. Their address could have been
    /// substituted.
    pub kms_keys_unchecked: usize,
    /// Listed keys that no event of this app names: another app's keys, which fails the
    /// node. See `KeysInLog::unrecorded`.
    pub kms_keys_unrecorded: usize,
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
    /// The TD's DEBUG attribute, from the AS token.
    pub td_debug: Option<bool>,
    /// A restarted tapp-server took over state for this app (`apps_resumed`) that is neither
    /// the latest state this boot measured for it nor the one before: its state file was
    /// written by something else. See `eventlog_app_resumed_differently`.
    pub app_resumed_differently: bool,
    pub note: String,
}

impl NodeVerdict {
    pub fn platform(&self) -> Platform {
        platform(&self.tcb_status, self.td_debug)
    }

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
            && !self.app_resumed_differently
    }

    /// Why this node's KMS keys cannot be believed, or `None` when they can: the AS
    /// verified the quote, the quote names the registered signer and was made for this
    /// request with a matching challenge, the event log replays, the platform passes,
    /// and the image is a published production one (or could not be checked). Everything
    /// but a dev image fails the node on its own; what such a node lists is neither shown
    /// as attested nor compared with the other nodes'.
    ///
    /// Believable is not the same as trustworthy: the keys are what the KMS cluster this
    /// node trusted gave it, and that is the owner's setting (`kms_keys_unchecked`).
    pub fn kms_keys_unattested(&self) -> Option<&'static str> {
        if !self.quote_ok {
            return Some("the AS did not verify the quote");
        }
        if !self.signer_ok {
            return Some("the quote does not name this node's signer");
        }
        if self.fresh != Some(true) {
            return Some("the quote is not proven to be made for this request");
        }
        unattested_by(self.replay_ok, &self.platform(), &self.boot_chain)
    }

    pub fn kms_keys_attested(&self) -> bool {
        self.kms_keys_unattested().is_none()
    }

    pub fn identity_unattested(&self) -> Option<&'static str> {
        if !self.identity.present { return Some("no typed identity metadata"); }
        if self.identity.error.is_some() { return Some("typed identity metadata is invalid"); }
        if self.fresh != Some(true) { return Some("typed identities require a matching quote challenge"); }
        if let Some(reason) = self.kms_keys_unattested() { return Some(reason); }
        if matches!(self.boot_chain, crate::refvalues::BootChain::NotChecked) {
            return Some("boot reference values were not checked");
        }
        if !self.reconciled() { return Some("app workload measurements do not reconcile with the registry"); }
        None
    }

    pub fn identity_attested(&self) -> bool { self.identity_unattested().is_none() }
}

/// The checks [`NodeVerdict::kms_keys_unattested`] and the direct-mode one share.
fn unattested_by(
    replay_ok: bool,
    platform: &Platform,
    boot_chain: &crate::refvalues::BootChain,
) -> Option<&'static str> {
    if !replay_ok {
        return Some("the event log does not replay");
    }
    if matches!(platform, Platform::Fail(_)) {
        return Some("the platform fails (DEBUG on, or a revoked TCB)");
    }
    match boot_chain {
        crate::refvalues::BootChain::Unknown { .. } => Some("the image is not a published one"),
        // Its operator has a shell in the TD, so the quote vouches for anything.
        crate::refvalues::BootChain::Matched(label) if crate::refvalues::is_dev_image(label) => {
            Some("a dev image, whose operator has a shell in the TD")
        }
        _ => None,
    }
}

/// The materials for which more than one key is attested among `holders`: each node's
/// signer and the keys it can be believed about.
///
/// The KMS derives one key per (app_id, material), so every node that took a material
/// must name the same address for it, and a node names at most one. Two addresses mean a
/// node got a key from somewhere else: another KMS cluster, or an answer substituted on
/// the way. Which one is the odd one out the evidence cannot say.
pub fn kms_key_conflicts<'a>(
    holders: impl IntoIterator<Item = (&'a str, Vec<&'a crate::report_data::KmsKey>)>,
) -> Vec<KmsKeyConflict> {
    let mut by_material: std::collections::BTreeMap<&str, std::collections::BTreeMap<&str, Vec<String>>> =
        Default::default();
    for (signer, keys) in holders {
        // Entries are in the one form tapp-server writes (read_kms_keys and
        // eventlog_kms_keys drop the rest), so plain string comparison is exact.
        for k in keys {
            let signers = by_material
                .entry(k.material.as_str())
                .or_default()
                .entry(k.address.as_str())
                .or_default();
            if !signers.iter().any(|s| s == signer) {
                signers.push(signer.to_string());
            }
        }
    }
    by_material
        .into_iter()
        .filter(|(_, addresses)| addresses.len() > 1)
        .map(|(material, addresses)| KmsKeyConflict {
            material: material.to_string(),
            addresses: addresses
                .into_iter()
                .map(|(address, signers)| (address.to_string(), signers))
                .collect(),
        })
        .collect()
}

/// What a node's event log says about the keys its runtime_data lists, for `app_id`.
struct KeysInLog {
    /// Keys only the log names.
    logged_only: Vec<crate::report_data::KmsKey>,
    /// Of all the keys, those whose events never say the KMS was checked against
    /// attestation.
    unchecked: usize,
    /// Listed keys that no event of this app names. tapp-server lists a key only once its
    /// event is written, so in evidence whose log replays this cannot happen honestly:
    /// runtime_data carries no app_id, and such a key is another app's.
    unrecorded: usize,
}

/// `None` when the log cannot be read.
fn kms_keys_from_log(
    cc_eventlog_b64: &str,
    app_id: &str,
    listed: &[crate::report_data::KmsKey],
) -> Option<KeysInLog> {
    let logged: HashMap<(String, String), LoggedKmsKey> = eventlog_kms_keys(cc_eventlog_b64)
        .ok()?
        .into_iter()
        .filter(|l| l.app_id == app_id)
        .map(|l| ((l.key.material.clone(), l.key.address.clone()), l))
        .collect();
    let checked = |k: &crate::report_data::KmsKey| {
        logged
            .get(&(k.material.clone(), k.address.clone()))
            .is_some_and(|l| l.checked)
    };
    let listed_set: HashSet<(&str, &str)> =
        listed.iter().map(|k| (k.material.as_str(), k.address.as_str())).collect();
    let mut logged_only: Vec<_> = logged
        .values()
        .filter(|l| !listed_set.contains(&(l.key.material.as_str(), l.key.address.as_str())))
        .map(|l| l.key.clone())
        .collect();
    logged_only.sort_by(|a, b| (&a.material, &a.address).cmp(&(&b.material, &b.address)));
    let in_log = |k: &crate::report_data::KmsKey| {
        logged.contains_key(&(k.material.clone(), k.address.clone()))
    };
    let unrecorded = listed.iter().filter(|k| !in_log(k)).count();
    let unchecked = listed
        .iter()
        .chain(logged_only.iter())
        .filter(|k| in_log(k) && !checked(k))
        .count();
    Some(KeysInLog {
        logged_only,
        unchecked,
        unrecorded,
    })
}

pub struct AppVerdict {
    pub app_id: String,
    pub nodes: Vec<NodeVerdict>,
}

/// A material for which the nodes of an app attest more than one key.
#[derive(Debug, PartialEq, Eq)]
pub struct KmsKeyConflict {
    pub material: String,
    /// Each address attested for the material, with the signers of the nodes attesting it.
    pub addresses: Vec<(String, Vec<String>)>,
}

impl AppVerdict {
    /// The materials for which more than one key is attested across this app's nodes (see
    /// [`kms_key_conflicts`]): a finding about the app rather than about a node.
    ///
    /// Only nodes whose keys are attested count ([`NodeVerdict::kms_keys_attested`]), with
    /// what runtime_data lists and what only the event log names. The others fail on their
    /// own (or run a dev image), and nothing they say about their keys can be believed.
    pub fn kms_key_conflicts(&self) -> Vec<KmsKeyConflict> {
        kms_key_conflicts(self.nodes.iter().filter(|n| n.kms_keys_attested()).map(|n| {
            (
                n.signer.as_str(),
                n.kms_keys.iter().chain(&n.kms_keys_logged_only).collect(),
            )
        }))
    }
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
    identity: crate::identity_verify::IdentityVerification,
    /// The KMS keys listed, those in the form tapp-server writes (`read_kms_keys`).
    kms_keys: Vec<crate::report_data::KmsKey>,
    /// `None` when no challenge was sent or the server predates the field, so a caller
    /// that does not care about freshness is never reported as failing.
    fresh: Option<bool>,
    /// False means the old signer-only `report_data`, which carries no challenge at all.
    structured: bool,
    note: String,
}

// Keep new metadata errors independent from the legacy signer parser.
#[derive(serde::Deserialize)]
struct LegacyRuntimeIdentity {
    signer: String,
    #[serde(default)]
    tls_public_key: String,
    #[serde(default)]
    nonce: String,
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
fn read_report_data(evidence: &serde_json::Value, quote_b64: &str, nonce: &[u8], app_id: &str) -> Attested {
    let mut a = Attested {
        signer: String::new(),
        tls_public_key: String::new(),
        identity: Default::default(),
        kms_keys: Vec::new(),
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

    let Some(runtime_data) = evidence.get(crate::report_data::EVIDENCE_FIELD) else {
        a.signer = format!("0x{}", hex::encode(&rd[..20]));
        if !nonce.is_empty() {
            a.note = "server predates the challenge field, freshness unproven; ".to_string();
        }
        return a;
    };
    a.structured = true;
    let Some(rdata_b64) = runtime_data.as_str() else {
        a.note = "runtime_data is present but is not a base64 string; ".into();
        return a;
    };

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
    let parsed: LegacyRuntimeIdentity = match serde_json::from_slice(&bytes) {
        Ok(p) => p,
        Err(e) => {
            a.note = format!("runtime_data parse: {}; ", e);
            return a;
        }
    };

    a.signer = parsed.signer;
    a.tls_public_key = parsed.tls_public_key;
    a.identity = crate::identity_verify::IdentityVerification::read(&bytes, app_id, &a.signer, &a.tls_public_key);
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
    let read = crate::report_data::read_kms_keys(&bytes);
    a.kms_keys = read.keys;
    if read.dropped > 0 {
        a.note.push_str(&format!(
            "{} kms_keys entr{} ignored ({}); ",
            read.dropped,
            if read.dropped == 1 { "y" } else { "ies" },
            read.reasons.join("; ")
        ));
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
                    // A resumed claim states the owner a restarted process took over: it
                    // must be the one claimed, or the state file was changed in between.
                    let payload = text
                        .strip_prefix("tapp.0g.com claim_config ")
                        .or_else(|| text.strip_prefix("tapp.0g.com claim_resumed "));
                    if let Some(payload) = payload {
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
pub(crate) fn eventlog_tapp_events(cc_eventlog_b64: &str, operation: &str) -> Result<Vec<serde_json::Value>> {
    Ok(eventlog_tapp_events_of(cc_eventlog_b64, &[operation])?
        .into_iter()
        .map(|(_, v)| v)
        .collect())
}

/// Events of any of `operations`, in log order, with the operation each one is.
fn eventlog_tapp_events_of(
    cc_eventlog_b64: &str,
    operations: &[&str],
) -> Result<Vec<(String, serde_json::Value)>> {
    let log = B64.decode(cc_eventlog_b64).map_err(|e| anyhow!("eventlog b64: {}", e))?;
    let u32le = |b: &[u8]| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize;

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
                    for op in operations {
                        let prefix = format!("tapp.0g.com {} ", op);
                        if let Some(payload) = text.strip_prefix(prefix.as_str()) {
                            if let Ok(v) = serde_json::from_str::<serde_json::Value>(payload) {
                                out.push((op.to_string(), v));
                            }
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
    /// A restarted process took over anchors that differ from what the claim or the last
    /// update before it set: the state file was changed between the two processes. Cleared
    /// by a later update, which measures the anchors in force again.
    pub resumed_differently: bool,
    /// The above happened at some point this boot, even if an update has re-set the
    /// anchors since — history a reader should still see.
    pub ever_resumed_differently: bool,
    /// A restart had no claimed config to take over (the tapp-server before it persisted
    /// only the owner), so it ran on config.toml's values: not carried over, not changed.
    /// Cleared by a later update, as above.
    pub not_carried_over: bool,
    /// A restart found the claimed config but could not read it — damaged, or written by
    /// something other than tapp-server — and ran on config.toml's values. Those are what
    /// this reports, so nothing is hidden, but the file was not what tapp-server left.
    /// Cleared by a later update, as above.
    pub config_unreadable: bool,
}

/// Whether a restarted tapp-server took over state for `app_id` that differs from what
/// this boot's events left for it.
///
/// tapp-server keeps its apps on tmpfs so that a process restart within a boot still knows
/// them, and measures what it read back (`apps_resumed`) because that file sits outside the
/// measurement. Replaying start_app / start_service / stop_app gives what the file may hold:
/// the state after the latest of them, or the one before it — tapp-server records a change
/// only after measuring it, so a process stopped in between leaves the previous state. An
/// `apps_resumed` entry that is anything else — another owner, a compose or image never
/// started, an app this boot never started, or an older state rolled back to — means the
/// file was written by something other than tapp-server.
fn eventlog_app_resumed_differently(cc_eventlog_b64: &str, app_id: &str) -> Result<bool> {
    let fields = |v: &serde_json::Value| {
        ["deployer", "compose_hash", "volumes_hash", "image_hash"].map(|k| v[k].clone())
    };
    let mut states = Vec::new();
    let mut differs = false;
    let events = eventlog_tapp_events_of(
        cc_eventlog_b64,
        &["start_app", "start_service", "stop_app", "apps_resumed"],
    )?;
    for (op, v) in &events {
        if op == "apps_resumed" {
            let resumed = v["apps"].as_array().into_iter().flatten();
            let possible = &states[states.len().saturating_sub(2)..];
            for a in resumed.filter(|a| a["app_id"].as_str() == Some(app_id)) {
                differs |= !possible.contains(&fields(a));
            }
        } else if v["app_id"].as_str() == Some(app_id) && v["result"].as_str() == Some("success") {
            states.push(match op.as_str() {
                // A stop keeps the owner and clears the rest (BootService::stop_app).
                "stop_app" => [
                    v["deployer"].clone(),
                    serde_json::json!(""),
                    serde_json::json!({}),
                    serde_json::json!({}),
                ],
                _ => fields(v),
            });
        }
    }
    Ok(differs)
}

/// A KMS key the event log says was taken this boot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoggedKmsKey {
    pub app_id: String,
    pub key: crate::report_data::KmsKey,
    /// At least one of its `get_secret_resource` events says the KMS answered over a
    /// connection checked against attestation (`kms_attested`): TLS to a node holding a key
    /// the verifier attests. Recorded by the client that made the request, so a change of
    /// settings while it was under way cannot make an unchecked answer look checked.
    pub checked: bool,
}

/// Every KMS key the `get_secret_resource` events of this boot name, once per app and key,
/// in app, material and address order. Events from before tapp-server 0.11.0 name no key
/// and are skipped, as is anything not in the form tapp-server writes.
///
/// tapp-server reads this back when it starts, so that `runtime_data.kms_keys` covers the
/// whole boot. A verifier reads it to tell, for each key, whether the KMS that gave it was
/// checked against attestation.
pub fn eventlog_kms_keys(cc_eventlog_b64: &str) -> Result<Vec<LoggedKmsKey>> {
    let events = eventlog_tapp_events(cc_eventlog_b64, "get_secret_resource")?;
    let mut out: std::collections::BTreeMap<(String, String, String), LoggedKmsKey> =
        Default::default();
    for v in &events {
        let (Some(app_id), Some(address), Some(material), Some(public_key)) = (
            v["app_id"].as_str(),
            v["address"].as_str(),
            v["material"].as_str(),
            v["public_key"].as_str(),
        ) else {
            continue;
        };
        let key = crate::report_data::KmsKey {
            address: address.to_string(),
            material: crate::report_data::normalize_material(material),
            public_key: public_key.to_string(),
        };
        if key.problem().is_some() {
            continue;
        }
        out.entry((app_id.to_string(), key.material.clone(), key.address.clone()))
            .or_insert_with(|| LoggedKmsKey {
                app_id: app_id.to_string(),
                key,
                checked: false,
            })
            .checked |= v["kms_attested"].as_bool() == Some(true);
    }
    Ok(out.into_values().collect())
}

/// The anchors in force, read from the newest event that sets them.
///
/// `update_trust_anchors` events carry the resulting state in full, so the newest one is
/// the answer outright with no replay. Falling back to `claim_config` covers a node whose
/// anchors were never revised. Both are taken newest-first because these are deliberately
/// mutable: earlier events are history, not conflicts — unlike the owner, which cannot
/// change and where disagreement is a finding.
fn eventlog_trust_anchors(cc_eventlog_b64: &str) -> Result<Option<TrustAnchors>> {
    // All three state the anchors in full. In log order, the newest is in force; a resumed
    // claim that does not repeat the state before it is a finding, not a revision.
    let events = eventlog_tapp_events_of(
        cc_eventlog_b64,
        &["claim_config", "update_trust_anchors", "claim_resumed"],
    )?;
    let anchors_of = |v: &serde_json::Value| {
        (v["kbs_node_urls"].clone(), v["scan_url"].clone(), v["scan_public_key"].clone())
    };
    let mut revisions = 0;
    let mut resumed_differently = false;
    let mut ever_resumed_differently = false;
    let mut not_carried_over = false;
    let mut config_unreadable = false;
    let mut source: Option<&serde_json::Value> = None;
    for (op, v) in &events {
        match op.as_str() {
            "update_trust_anchors" => {
                revisions += 1;
                resumed_differently = false;
                not_carried_over = false;
                config_unreadable = false;
            }
            "claim_resumed" => {
                // Absent in events from before the field existed: those always carried it.
                // `false` is what the first version of the field wrote for "absent".
                let resumed = &v["config_resumed"];
                if resumed == "unreadable" {
                    config_unreadable = true;
                } else if resumed == "absent" || resumed.as_bool() == Some(false) {
                    not_carried_over = true;
                } else if source.is_some_and(|prev| anchors_of(prev) != anchors_of(v)) {
                    resumed_differently = true;
                    ever_resumed_differently = true;
                }
            }
            _ => {}
        }
        source = Some(v);
    }
    let Some(source) = source else { return Ok(None) };
    Ok(Some(TrustAnchors {
        resumed_differently,
        ever_resumed_differently,
        not_carried_over,
        config_unreadable,
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
    /// The TD's DEBUG attribute; `None` when the token does not carry it.
    pub td_debug: Option<bool>,
}

/// What the platform itself allows, from the AS token: a policy used to check this, and
/// the local verdict must not lose it.
#[derive(Debug, Clone, PartialEq)]
pub enum Platform {
    /// Debug off, TCB up to date.
    Ok,
    /// Usable, but with an Intel advisory outstanding (a TCB other than UpToDate):
    /// common on clouds, whose firmware trails Intel's releases.
    Warn(String),
    /// The TD's memory is open to its host (DEBUG), the platform key is revoked, or the
    /// debug attribute could not be read at all.
    Fail(String),
}

/// DEBUG lets the host read and write the TD's memory: whoever launches the TD — the
/// operator on bare metal — can, so nothing attested inside it means anything. A TCB
/// that trails Intel's latest is a warning, not a failure: clouds lag, and failing every
/// node over it would teach people to ignore the check. Revoked is a failure.
pub fn platform(tcb_status: &str, td_debug: Option<bool>) -> Platform {
    match td_debug {
        Some(true) => return Platform::Fail("TD runs with DEBUG: its host can read and write its memory".into()),
        None => return Platform::Fail("TD attributes not in the AS token: DEBUG cannot be ruled out".into()),
        Some(false) => {}
    }
    match tcb_status {
        "UpToDate" => Platform::Ok,
        "Revoked" => Platform::Fail("platform TCB is revoked".into()),
        other => Platform::Warn(format!("TCB {}", other)),
    }
}

/// The DEBUG bit, parsed by the AS or read from the raw TDATTRIBUTES (bit 0 of the first,
/// little-endian byte) when only that is present.
fn td_debug_of(tdx: &serde_json::Value) -> Option<bool> {
    if let Some(d) = tdx["td_attributes"]["debug"].as_bool() {
        return Some(d);
    }
    let hex_attrs = tdx["quote"]["body"]["td_attributes"].as_str()?;
    let first = u8::from_str_radix(hex_attrs.get(0..2)?, 16).ok()?;
    Some(first & 1 == 1)
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
    // The request carries the whole evidence and the token the whole parsed event log, so
    // both directions get the evidence limit (the scan sets the same). The AS's own server
    // limit is its own: on default settings it refuses a request past 4 MiB.
    let mut client = connect_as(as_endpoint, as_pubkey)
        .await?
        .max_decoding_message_size(MAX_EVIDENCE_LEN)
        .max_encoding_message_size(MAX_EVIDENCE_LEN);
    let req = AttestationRequest {
        verification_requests: vec![IndividualAttestationRequest {
            tee: "tdx".to_string(),
            evidence: B64URL.encode(raw_evidence),
            // Left unset deliberately: read_report_data checks the binding itself, which
            // loses nothing. Handing the AS our runtime_data as structured runtime data with
            // "sha512" named would have it check too (its default is sha384, and raw runtime
            // data it compares unhashed); the bytes are the canonical JSON it hashes.
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
        td_debug: td_debug_of(tdx),
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

/// Largest evidence accepted from a node, the scan's own limit. Shared with `get-evidence`.
pub const MAX_EVIDENCE_LEN: usize = 64 * 1024 * 1024;

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
        // Evidence grows with the event log and with every KMS key an app takes; tonic's
        // default 4 MiB would refuse a busy node's. The scan allows the same 64 MiB.
        Ok(Ok(c)) => c.max_decoding_message_size(MAX_EVIDENCE_LEN),
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
    pub identity: crate::identity_verify::IdentityVerification,
    /// The KMS keys the app took on this node, as runtime_data lists them. Believe them
    /// only when [`DirectVerdict::kms_keys_attested`] holds.
    pub kms_keys: Vec<crate::report_data::KmsKey>,
    /// See NodeVerdict.
    pub kms_keys_logged_only: Vec<crate::report_data::KmsKey>,
    /// See NodeVerdict.
    pub kms_keys_unchecked: usize,
    /// See NodeVerdict.
    pub kms_keys_unrecorded: usize,
    /// The AS verified the quote. See NodeVerdict.
    pub quote_ok: bool,
    /// Whether the quote echoed the challenge sent for it. See NodeVerdict.
    pub fresh: Option<bool>,
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
    pub td_debug: Option<bool>,
    pub note: String,
}

impl DirectVerdict {
    pub fn platform(&self) -> Platform {
        platform(&self.tcb_status, self.td_debug)
    }

    /// [`NodeVerdict::kms_keys_unattested`] without the signer, which direct mode has no
    /// registration to compare against, and without a relay.
    pub fn kms_keys_unattested(&self) -> Option<&'static str> {
        if !self.quote_ok {
            return Some("the AS did not verify the quote");
        }
        if self.fresh != Some(true) {
            return Some("the quote is not proven to be made for this request");
        }
        unattested_by(self.replay_ok, &self.platform(), &self.boot_chain)
    }

    pub fn kms_keys_attested(&self) -> bool {
        self.kms_keys_unattested().is_none()
    }

    pub fn identity_unattested(&self) -> Option<&'static str> {
        if !self.identity.present { return Some("no typed identity metadata"); }
        if self.identity.error.is_some() { return Some("typed identity metadata is invalid"); }
        if self.fresh != Some(true) { return Some("typed identities require a matching quote challenge"); }
        if let Some(reason) = self.kms_keys_unattested() { return Some(reason); }
        if matches!(self.boot_chain, crate::refvalues::BootChain::NotChecked) {
            return Some("boot reference values were not checked");
        }
        None
    }

    pub fn identity_attested(&self) -> bool { self.identity_unattested().is_none() }

    /// One node can disagree with itself too: two keys for one material.
    pub fn kms_key_conflicts(&self) -> Vec<KmsKeyConflict> {
        if !self.kms_keys_attested() {
            return Vec::new();
        }
        kms_key_conflicts([(
            self.signer.as_str(),
            self.kms_keys.iter().chain(&self.kms_keys_logged_only).collect(),
        )])
    }
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
        identity: Default::default(),
        kms_keys: Vec::new(),
        kms_keys_logged_only: Vec::new(),
        kms_keys_unchecked: 0,
        kms_keys_unrecorded: 0,
        quote_ok: false,
        fresh: None,
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
        td_debug: None,
        note: String::new(),
    };

    let nonce = fresh_nonce();
    let raw = fetch_evidence(server, app_id, &nonce).await?;
    let j: serde_json::Value = serde_json::from_slice(&raw)?;
    let quote_b64 = j["quote"].as_str().unwrap_or("");
    let cc_b64 = j["cc_eventlog"].as_str().unwrap_or("");

    // There is no on-chain signer to compare against here — the whole point of this path
    // is that the app may not be registered — so report what the node attested.
    let attested = read_report_data(&j, quote_b64, &nonce, app_id);
    v.signer = attested.signer.clone();
    v.tls_public_key = attested.tls_public_key.clone();
    v.kms_keys = attested.kms_keys.clone();
    v.identity = attested.identity.clone();
    v.fresh = attested.fresh;
    v.note = attested.note.clone();

    match verify_with_as(as_endpoint, as_pubkey, &raw, policy_ids).await {
        Ok(av) => {
            v.quote_ok = true;
            v.ear_status = av.ear_status;
            v.tcb_status = av.tcb_status;
            v.advisories = av.advisories;
            v.boot_executables = av.executables;
            v.boot_measurements = av.measured.as_reference_pairs();
            v.boot_chain = crate::refvalues::identify(&av.measured, refs);
            v.replay_ok = av.replay_mismatches == 0;
            v.td_debug = av.td_debug;
        }
        Err(e) => v.note = format!("{}AS: {}", v.note, e),
    }

    // What the event log says about each key, once the log is known to replay. Until then
    // no key's provenance is known.
    v.kms_keys_unchecked = v.kms_keys.len();
    if v.replay_ok {
        v.identity.reconcile_log(cc_b64, app_id);
        if let Some(log) = kms_keys_from_log(cc_b64, app_id, &v.kms_keys) {
            v.kms_keys_logged_only = log.logged_only;
            v.kms_keys_unchecked = log.unchecked;
            v.kms_keys_unrecorded = log.unrecorded;
        }
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
            quote_ok: false,
            tls_public_key: String::new(),
            identity: Default::default(),
            kms_keys: Vec::new(),
            kms_keys_logged_only: Vec::new(),
            kms_keys_unchecked: 0,
            kms_keys_unrecorded: 0,
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
            td_debug: None,
            app_resumed_differently: false,
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
        let attested = read_report_data(&j, quote_b64, &nonce, app_id);
        v.signer_ok = attested.is(signer.as_bytes());
        v.tls_public_key = attested.tls_public_key.clone();
        v.kms_keys = attested.kms_keys.clone();
        v.identity = attested.identity.clone();
        v.fresh = attested.fresh;
        v.note = attested.note.clone();

        // ③ AS quote verification
        match verify_with_as(as_endpoint, as_pubkey, &raw, policy_ids).await {
            Ok(av) => {
                v.quote_ok = true;
                v.ear_status = av.ear_status;
                v.tcb_status = av.tcb_status;
                v.advisories = av.advisories;
                v.boot_executables = av.executables;
                v.boot_measurements = av.measured.as_reference_pairs();
                v.boot_chain = crate::refvalues::identify(&av.measured, refs);
                v.replay_ok = av.replay_mismatches == 0;
                v.td_debug = av.td_debug;
                if !v.replay_ok {
                    v.note = format!(
                        "{}{} measured tapp events do not hash to what was extended; ",
                        v.note, av.replay_mismatches
                    );
                }
            }
            Err(e) => v.note = format!("{}AS: {}", v.note, e),
        }

        // What the event log says about each key, once the log is known to replay. Until
        // then no key's provenance is known.
        v.kms_keys_unchecked = v.kms_keys.len();
        if v.replay_ok {
            v.identity.reconcile_log(cc_b64, app_id);
            if let Some(log) = kms_keys_from_log(cc_b64, app_id, &v.kms_keys) {
                v.kms_keys_logged_only = log.logged_only;
                v.kms_keys_unchecked = log.unchecked;
                v.kms_keys_unrecorded = log.unrecorded;
            }
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

        match eventlog_app_resumed_differently(cc_b64, app_id) {
            Ok(differs) => v.app_resumed_differently = differs,
            Err(e) => v.note = format!("{}apps_resumed: {}", v.note, e),
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

    /// A `get_secret_resource` event as tapp-server ≥ 0.11.0 measures it, built with the
    /// same field builder the server uses. `attested` is what the KMS client reported.
    fn taken(app_id: &str, material: &str, last: u8, attested: bool) -> String {
        let mut event = serde_json::json!({
            "app_id": app_id, "operation": "get_secret_resource", "result": "success",
            "material": material,
        });
        let fields = crate::report_data::kms_event_fields(
            Some(&key(material, last)),
            Some(("https://kms-1:9443", attested)),
        );
        event.as_object_mut().unwrap().extend(fields);
        event.to_string()
    }

    fn key(material: &str, last: u8) -> crate::report_data::KmsKey {
        let mut secret = [0u8; 32];
        secret[31] = last;
        crate::report_data::KmsKey::of_secret(material, &secret).unwrap()
    }

    #[test]
    fn each_logged_key_is_judged_by_what_its_own_events_say() {
        let log = tcg_log(&[
            // Settings events say nothing about a key: the event of the key itself does.
            ("update_trust_anchors", &anchors_event("https://scan.a", &["https://kms-1:9443"])),
            ("get_secret_resource", &taken("a", "01", 1, false)),
            ("get_secret_resource", &taken("a", "0x02", 2, true)),
            // Unchecked, then checked: the same key, now known to be the cluster's.
            ("get_secret_resource", &taken("a", "03", 3, false)),
            ("get_secret_resource", &taken("a", "03", 3, true)),
            // And the reverse.
            ("get_secret_resource", &taken("a", "04", 4, true)),
            ("get_secret_resource", &taken("a", "04", 4, false)),
            ("get_secret_resource", &taken("b", "05", 5, true)),
            // Before 0.11.0 an event names no key; the TLS key never does.
            ("get_secret_resource", r#"{"app_id":"a","material":"746c73","kms_attested":true}"#),
        ]);
        let logged = eventlog_kms_keys(&log).unwrap();
        let checked_of = |app: &str, m: &str| {
            logged.iter().find(|l| l.app_id == app && l.key.material == m).map(|l| l.checked)
        };
        assert_eq!(checked_of("a", "01"), Some(false));
        assert_eq!(checked_of("a", "02"), Some(true), "0x02 is read as the KMS reads it");
        assert_eq!(checked_of("a", "03"), Some(true));
        assert_eq!(checked_of("a", "04"), Some(true));
        assert_eq!(checked_of("b", "05"), Some(true));
        assert_eq!(logged.len(), 5);
    }

    #[test]
    fn the_log_adds_what_runtime_data_does_not_list_and_counts_the_rest() {
        let log = tcg_log(&[
            ("get_secret_resource", &taken("a", "01", 1, true)),
            ("get_secret_resource", &taken("a", "02", 2, false)),
            ("get_secret_resource", &taken("b", "03", 3, true)),
        ]);
        // 02 is not listed (a restart that could not read the log back); 03 is app b's key,
        // listed under a; 09 no event names at all.
        let listed = vec![key("01", 1), key("03", 3), key("09", 9)];
        let log = kms_keys_from_log(&log, "a", &listed).unwrap();
        assert_eq!(log.logged_only, vec![key("02", 2)]);
        assert_eq!(log.unchecked, 1, "02, taken from an unchecked KMS");
        assert_eq!(log.unrecorded, 2, "03 and 09, which no event of app a names");
    }

    #[test]
    fn a_dev_image_proves_no_keys() {
        let dev = crate::refvalues::BootChain::Matched("gcp/uki/v0.8.0/dev.json".into());
        let prod = crate::refvalues::BootChain::Matched("gcp/uki/v0.8.0/prod.json".into());
        assert!(unattested_by(true, &Platform::Ok, &dev).is_some());
        assert_eq!(unattested_by(true, &Platform::Ok, &prod), None);
        // Reference values unavailable: nothing to tell, so not held against the node.
        assert_eq!(unattested_by(true, &Platform::Ok, &crate::refvalues::BootChain::NotChecked), None);
        assert!(unattested_by(false, &Platform::Ok, &prod).is_some(), "a log that does not replay");
    }

    #[test]
    fn one_key_listed_and_logged_is_not_counted_twice() {
        let conflicts = kms_key_conflicts([("0x01", vec![&key("ab", 1), &key("ab", 1)])]);
        assert!(conflicts.is_empty());
        let conflicts = kms_key_conflicts([("0x01", vec![&key("ab", 1), &key("ab", 2)])]);
        assert_eq!(conflicts.len(), 1);
        assert!(conflicts[0].addresses.iter().all(|(_, s)| s == &vec!["0x01".to_string()]));
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
    fn new_metadata_is_parsed_only_after_hash_binding_and_does_not_block_legacy_signer() {
        let bytes = serde_json::to_vec(&serde_json::json!({
            "signer":format!("0x{}",hex::encode(SIGNER)),"app_id":42,
            "identities":"invalid","key_commitments":[]
        })).unwrap();
        let evidence = serde_json::json!({"runtime_data":B64.encode(&bytes)});
        let bound = quote_with(&crate::report_data::report_data_of(&bytes));
        let read = read_report_data(&evidence,&bound,&[],"sandbox");
        assert!(read.is(&SIGNER));
        assert!(read.identity.present && read.identity.error.is_some());
        let other = quote_with(&crate::report_data::report_data_of(b"other"));
        let read = read_report_data(&evidence,&other,&[],"sandbox");
        assert!(!read.identity.present && read.identity.identities.is_empty());
        assert!(read.signer.is_empty());
    }

    #[test]
    fn a_malformed_runtime_field_does_not_downgrade_to_legacy_report_data() {
        for runtime in [serde_json::json!(null),serde_json::json!({}),serde_json::json!(42)] {
            let quote=quote_with(&legacy_report_data(&SIGNER));
            let read=read_report_data(&serde_json::json!({"runtime_data":runtime}),&quote,&[],"sandbox");
            assert!(read.signer.is_empty() && !read.identity.present);
            assert!(read.structured);
        }
    }

    #[test]
    fn a_server_that_predates_runtime_data_still_has_its_signer_read() {
        let quote = quote_with(&legacy_report_data(&SIGNER));
        let a = read_report_data(&serde_json::json!({}), &quote, &[], "");
        assert!(a.is(&SIGNER));
        assert!(!a.structured);
        assert_eq!(a.fresh, None);
        assert!(a.note.is_empty());
    }

    #[test]
    fn sending_a_challenge_to_an_old_server_says_so_instead_of_failing_the_signer() {
        let quote = quote_with(&legacy_report_data(&SIGNER));
        let a = read_report_data(&serde_json::json!({}), &quote, b"chal", "");
        assert!(a.is(&SIGNER), "the signer binding still holds");
        assert_eq!(a.fresh, None, "not a failure — the server cannot answer it");
        assert!(a.note.contains("predates"), "got {}", a.note);
    }

    #[test]
    fn an_echoed_challenge_proves_the_quote_was_made_for_this_request() {
        let rdata = crate::report_data::RuntimeData::new(&SIGNER, b"chal").unwrap();
        let (bytes, rd) = rdata.seal().unwrap();
        let ev = serde_json::json!({ crate::report_data::EVIDENCE_FIELD: B64.encode(&bytes) });
        let a = read_report_data(&ev, &quote_with(&rd), b"chal", "");
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
        let a = read_report_data(&ev, &quote_with(&rd), b"mine", "");
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
        let a = read_report_data(&ev, &quote_with(&rd), b"chal", "");
        assert!(!a.is(&SIGNER));
        assert!(!a.is(&[0x22; 20]), "the swapped signer must not be believed either");
        assert!(a.note.contains("does not hash"), "got {}", a.note);
    }

    fn kms_key(material: &str, last: u8) -> crate::report_data::KmsKey {
        let mut secret = [0u8; 32];
        secret[31] = last;
        crate::report_data::KmsKey::of_secret(material, &secret).unwrap()
    }

    #[test]
    fn the_kms_keys_a_quote_vouches_for_are_read_back() {
        let mut rdata = crate::report_data::RuntimeData::new(&SIGNER, b"chal").unwrap();
        rdata.kms_keys = vec![kms_key("", 1), kms_key("7369676e6572", 2)];
        let (bytes, rd) = rdata.seal().unwrap();
        let ev = serde_json::json!({ crate::report_data::EVIDENCE_FIELD: B64.encode(&bytes) });
        let a = read_report_data(&ev, &quote_with(&rd), b"chal", "");
        assert!(a.is(&SIGNER));
        assert_eq!(a.kms_keys, rdata.kms_keys);
        assert!(a.note.is_empty(), "got {}", a.note);
    }

    #[test]
    fn a_kms_key_whose_address_is_not_its_public_keys_is_dropped_and_said() {
        let mut bad = kms_key("ab", 1);
        bad.address = kms_key("ab", 2).address;
        let mut rdata = crate::report_data::RuntimeData::new(&SIGNER, b"theirs").unwrap();
        rdata.kms_keys = vec![kms_key("", 1), bad];
        let (bytes, rd) = rdata.seal().unwrap();
        let ev = serde_json::json!({ crate::report_data::EVIDENCE_FIELD: B64.encode(&bytes) });
        let a = read_report_data(&ev, &quote_with(&rd), b"mine", "");
        assert_eq!(a.kms_keys, vec![kms_key("", 1)]);
        // Said alongside the challenge finding, not instead of it.
        assert!(a.note.contains("not echoed"), "got {}", a.note);
        assert!(a.note.contains("\"ab\""), "got {}", a.note);
    }

    #[test]
    fn kms_keys_in_runtime_data_that_does_not_hash_are_not_believed() {
        let (_, rd) = crate::report_data::RuntimeData::new(&SIGNER, b"chal").unwrap().seal().unwrap();
        let mut forged = crate::report_data::RuntimeData::new(&SIGNER, b"chal").unwrap();
        forged.kms_keys = vec![kms_key("", 1)];
        let (bytes, _) = forged.seal().unwrap();
        let ev = serde_json::json!({ crate::report_data::EVIDENCE_FIELD: B64.encode(&bytes) });
        let a = read_report_data(&ev, &quote_with(&rd), b"chal", "");
        assert!(a.kms_keys.is_empty());
    }

    #[test]
    fn recovering_legacy_kms_keys_from_the_log_cannot_bypass_the_quote_challenge() {
        let material = "70726f7669646572";
        let mut runtime = crate::report_data::RuntimeData::new(&SIGNER, b"old").unwrap();
        runtime.kms_keys = vec![key(material, 1)];
        let (bytes, rd) = runtime.seal().unwrap();
        let quote = quote_with(&rd);
        let log = tcg_log(&[("get_secret_resource", &taken("a", material, 1, true))]);
        for (evidence, challenge, accepted) in [
            (serde_json::json!({}), b"new".as_slice(), false),
            (serde_json::json!({"runtime_data":B64.encode(b"swapped")}), b"new".as_slice(), false),
            (serde_json::json!({"runtime_data":B64.encode(&bytes)}), b"new".as_slice(), false),
            (serde_json::json!({"runtime_data":B64.encode(&bytes)}), b"old".as_slice(), true),
        ] {
            let parsed = read_report_data(&evidence, &quote, challenge, "a");
            let logged = kms_keys_from_log(&log, "a", &parsed.kms_keys).unwrap();
            assert_eq!(parsed.kms_keys.len() + logged.logged_only.len(), 1);
            // This isolates the freshness policy after successful AS/replay checks;
            // quote_with is a parsing fixture, not a hardware-signed quote.
            let verdict = DirectVerdict {
                server: "https://node.example".into(), signer: parsed.signer,
                tls_public_key: parsed.tls_public_key, identity: parsed.identity,
                kms_keys: parsed.kms_keys, kms_keys_logged_only: logged.logged_only,
                kms_keys_unchecked: logged.unchecked, kms_keys_unrecorded: logged.unrecorded,
                quote_ok: true, fresh: parsed.fresh, ear_status: "affirming".into(),
                tcb_status: "UpToDate".into(), advisories: 0, boot_executables: None,
                boot_measurements: vec![], compose_hash: String::new(), images: vec![],
                claimed_owner: None, trust_anchors: None, replay_ok: true,
                boot_chain: crate::refvalues::BootChain::Matched("gcp/prod.json".into()),
                td_debug: Some(false), note: parsed.note,
            };
            assert_eq!(verdict.kms_keys_attested(), accepted);
        }
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
            quote_ok: true,
            tls_public_key: String::new(),
            identity: Default::default(),
            kms_keys: Vec::new(),
            kms_keys_logged_only: Vec::new(),
            kms_keys_unchecked: 0,
            kms_keys_unrecorded: 0,
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
            td_debug: Some(false),
            app_resumed_differently: false,
            note: String::new(),
        }
    }

    #[test]
    fn a_debug_td_fails_whatever_else_passes() {
        assert!(matches!(platform("UpToDate", Some(true)), Platform::Fail(_)));
        // Unknown is not "probably fine": the attribute must be read to be ruled out.
        assert!(matches!(platform("UpToDate", None), Platform::Fail(_)));
    }

    #[test]
    fn a_trailing_tcb_warns_and_a_revoked_one_fails() {
        assert_eq!(platform("UpToDate", Some(false)), Platform::Ok);
        for lagging in ["OutOfDate", "SWHardeningNeeded", "ConfigurationNeeded", "OutOfDateConfigurationNeeded"] {
            assert!(matches!(platform(lagging, Some(false)), Platform::Warn(_)), "{lagging}");
        }
        assert!(matches!(platform("Revoked", Some(false)), Platform::Fail(_)));
    }

    #[test]
    fn the_debug_bit_is_read_parsed_or_raw() {
        let parsed = serde_json::json!({"td_attributes": {"debug": true}});
        assert_eq!(td_debug_of(&parsed), Some(true));
        // TDATTRIBUTES as seen on test-tapp (SEPT_VE_DISABLE only), then with DEBUG set.
        let raw = |h: &str| serde_json::json!({"quote": {"body": {"td_attributes": h}}});
        assert_eq!(td_debug_of(&raw("0000001000000000")), Some(false));
        assert_eq!(td_debug_of(&raw("0100001000000000")), Some(true));
        assert_eq!(td_debug_of(&serde_json::json!({})), None);
    }

    #[test]
    fn a_quote_made_for_another_request_never_passes() {
        assert!(!node(Some(false), false).reconciled());
        assert!(!node(Some(false), true).reconciled());
    }

    #[test]
    fn legacy_node_diagnostics_do_not_authenticate_kms_keys_without_a_challenge() {
        let legacy = node(None, false);
        assert!(legacy.reconciled());
        assert!(!legacy.kms_keys_attested());
        assert!(node(Some(true), false).kms_keys_attested());
        assert!(!node(Some(false), false).kms_keys_attested());
    }

    #[test]
    fn typed_identity_authentication_requires_the_full_trust_gate() {
        let mut n=node(Some(true),false);
        n.identity.present=true;
        n.boot_chain=crate::refvalues::BootChain::Matched("prod/gcp/v1.json".into());
        assert!(n.identity_attested());
        n.quote_ok=false; assert!(!n.identity_attested()); n.quote_ok=true;
        n.signer_ok=false; assert!(!n.identity_attested()); n.signer_ok=true;
        n.fresh=None; assert!(!n.identity_attested()); n.fresh=Some(true);
        n.replay_ok=false; assert!(!n.identity_attested()); n.replay_ok=true;
        n.compose_ok=false; assert!(!n.identity_attested()); n.compose_ok=true;
        n.image_ok=false; assert!(!n.identity_attested()); n.image_ok=true;
        n.td_debug=Some(true); assert!(!n.identity_attested()); n.td_debug=Some(false);
        n.boot_chain=crate::refvalues::BootChain::NotChecked; assert!(!n.identity_attested());
        n.boot_chain=crate::refvalues::BootChain::Matched("gcp/dev.json".into()); assert!(!n.identity_attested());
        n.boot_chain=crate::refvalues::BootChain::Matched("gcp/prod.json".into());
        n.identity.unchecked=1; assert!(n.identity_attested()); // provenance is a visible warning
        n.identity.error=Some("bad commitment".into()); assert!(!n.identity_attested());
    }

    fn holding(signer: &str, keys: &[(&str, u8)]) -> NodeVerdict {
        let mut n = node(Some(true), false);
        n.signer = signer.into();
        n.kms_keys = keys
            .iter()
            .map(|(material, last)| {
                let mut secret = [0u8; 32];
                secret[31] = *last;
                crate::report_data::KmsKey::of_secret(material, &secret).unwrap()
            })
            .collect();
        n
    }

    #[test]
    fn nodes_that_took_the_same_keys_agree() {
        let app = AppVerdict {
            app_id: "a".into(),
            nodes: vec![
                holding("0x01", &[("", 1), ("ab", 2)]),
                // A node that has not taken a material yet is not a disagreement.
                holding("0x02", &[("", 1)]),
            ],
        };
        assert!(app.kms_key_conflicts().is_empty());
    }

    #[test]
    fn two_keys_for_one_material_are_a_conflict_naming_both() {
        let app = AppVerdict {
            app_id: "a".into(),
            nodes: vec![
                holding("0x01", &[("", 1), ("ab", 2)]),
                holding("0x02", &[("", 1), ("ab", 3)]),
                holding("0x03", &[("ab", 2)]),
            ],
        };
        let conflicts = app.kms_key_conflicts();
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].material, "ab");
        let signers: Vec<_> = conflicts[0].addresses.iter().map(|(_, s)| s.clone()).collect();
        assert!(signers.contains(&vec!["0x01".to_string(), "0x03".to_string()]), "{signers:?}");
        assert!(signers.contains(&vec!["0x02".to_string()]), "{signers:?}");
    }

    #[test]
    fn a_node_whose_runtime_data_names_another_signer_does_not_count() {
        let mut stranger = holding("0x02", &[("ab", 3)]);
        stranger.signer_ok = false;
        let app = AppVerdict {
            app_id: "a".into(),
            nodes: vec![holding("0x01", &[("ab", 2)]), stranger],
        };
        assert!(app.kms_key_conflicts().is_empty());
    }

    #[test]
    fn keys_from_evidence_that_did_not_verify_are_not_compared() {
        // Each of these nodes fails on its own; none may make the healthy one look like
        // it disagrees. A fabricated quote can name the registered signer and any key, so
        // signer_ok alone is not enough.
        let unverified: [fn(&mut NodeVerdict); 5] = [
            |n| n.quote_ok = false,
            |n| n.fresh = Some(false),
            |n| {
                n.fresh = None;
                n.relayed_by = Some("https://tappscan.0g.ai".into());
            },
            |n| n.td_debug = Some(true),
            |n| n.boot_chain = crate::refvalues::BootChain::Unknown { closest: None },
        ];
        for break_it in unverified {
            let mut odd = holding("0x02", &[("ab", 3)]);
            break_it(&mut odd);
            assert!(!odd.kms_keys_attested());
            let app = AppVerdict {
                app_id: "a".into(),
                nodes: vec![holding("0x01", &[("ab", 2)]), odd],
            };
            assert!(app.kms_key_conflicts().is_empty());
        }
        assert!(holding("0x01", &[]).kms_keys_attested());
    }

    #[test]
    fn one_node_with_two_keys_for_a_material_is_a_conflict() {
        // What a node lists after its KMS cluster was changed while it ran.
        let app = AppVerdict {
            app_id: "a".into(),
            nodes: vec![holding("0x01", &[("ab", 2), ("ab", 3)])],
        };
        let conflicts = app.kms_key_conflicts();
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].addresses.len(), 2);
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
    fn a_resumed_app_state_the_boot_did_not_measure_fails_the_node() {
        let mut n = node(Some(true), false);
        assert!(n.reconciled());
        n.app_resumed_differently = true;
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

#[cfg(test)]
mod resumed_apps_tests {
    use super::resumed_claim_tests::log_of;
    use super::*;

    fn op(op: &str, app: &str, deployer: &str, compose: &str, image: &str) -> String {
        format!(
            r#"tapp.0g.com {op} {{"app_id":"{app}","operation":"{op}","result":"success","compose_hash":"{compose}","volumes_hash":{{"a.conf":"01"}},"image_hash":{{"web":"{image}"}},"deployer":"{deployer}"}}"#
        )
    }

    fn resumed(apps: &[(&str, &str, &str, &str)]) -> String {
        let list: Vec<_> = apps
            .iter()
            .map(|(app, deployer, compose, image)| {
                let (volumes, images) = if compose.is_empty() {
                    (serde_json::json!({}), serde_json::json!({}))
                } else {
                    (serde_json::json!({"a.conf": "01"}), serde_json::json!({"web": image}))
                };
                serde_json::json!({"app_id": app, "deployer": deployer, "compose_hash": compose,
                                   "volumes_hash": volumes, "image_hash": images})
            })
            .collect();
        format!(
            "tapp.0g.com apps_resumed {}",
            serde_json::json!({"operation": "apps_resumed", "apps": list, "timestamp": 1})
        )
    }

    fn differs(events: &[String]) -> bool {
        eventlog_app_resumed_differently(&log_of(events), "app").unwrap()
    }

    #[test]
    fn a_resume_of_what_was_started_is_not_a_finding() {
        assert!(!differs(&[op("start_app", "app", "0xa", "c1", "sha256:1"), resumed(&[("app", "0xa", "c1", "sha256:1")])]));
        // A pulled image, then a stop: the resume follows both.
        assert!(!differs(&[
            op("start_app", "app", "0xa", "c1", "sha256:1"),
            op("start_service", "app", "0xa", "c1", "sha256:2"),
            resumed(&[("app", "0xa", "c1", "sha256:2")]),
        ]));
        assert!(!differs(&[
            op("start_app", "app", "0xa", "c1", "sha256:1"),
            op("stop_app", "app", "0xa", "c1", "sha256:1"),
            resumed(&[("app", "0xa", "", "")]),
        ]));
        // A process that stopped between measuring a stop and recording it: an earlier,
        // genuine state.
        assert!(!differs(&[
            op("start_app", "app", "0xa", "c1", "sha256:1"),
            op("stop_app", "app", "0xa", "c1", "sha256:1"),
            resumed(&[("app", "0xa", "c1", "sha256:1")]),
        ]));
        // Other apps in the list are theirs to answer for.
        assert!(!differs(&[op("start_app", "app", "0xa", "c1", "sha256:1"), resumed(&[("app", "0xa", "c1", "sha256:1"), ("other", "0xb", "c9", "sha256:9")])]));
        // No resume at all: nothing to judge.
        assert!(!differs(&[op("start_app", "app", "0xa", "c1", "sha256:1")]));
    }

    #[test]
    fn a_changed_state_file_shows() {
        // Another owner, another compose, an image never pulled, an app never started.
        assert!(differs(&[op("start_app", "app", "0xa", "c1", "sha256:1"), resumed(&[("app", "0xb", "c1", "sha256:1")])]));
        assert!(differs(&[op("start_app", "app", "0xa", "c1", "sha256:1"), resumed(&[("app", "0xa", "c2", "sha256:1")])]));
        assert!(differs(&[op("start_app", "app", "0xa", "c1", "sha256:1"), resumed(&[("app", "0xa", "c1", "sha256:2")])]));
        assert!(differs(&[resumed(&[("app", "0xa", "c1", "sha256:1")])]));
        // Rolled back two changes: a genuine state, but not one a crash can leave.
        assert!(differs(&[
            op("start_app", "app", "0xa", "c1", "sha256:1"),
            op("start_service", "app", "0xa", "c1", "sha256:2"),
            op("stop_app", "app", "0xa", "c1", "sha256:2"),
            resumed(&[("app", "0xa", "c1", "sha256:1")]),
        ]));
        // And it stays a finding: a later start does not erase what the file held.
        assert!(differs(&[
            op("start_app", "app", "0xa", "c1", "sha256:1"),
            resumed(&[("app", "0xb", "c1", "sha256:1")]),
            op("start_app", "app", "0xa", "c1", "sha256:1"),
        ]));
    }
}

#[cfg(test)]
mod resumed_claim_tests {
    use super::*;

    /// A minimal CCEL: the header the walkers skip, then one tapp event per entry.
    pub(super) fn log_of(events: &[String]) -> String {
        let mut b = vec![0u8; 28];
        b.extend_from_slice(&0u32.to_le_bytes());
        for text in events {
            b.extend_from_slice(&3u32.to_le_bytes()); // pcr
            b.extend_from_slice(&6u32.to_le_bytes()); // EV_EVENT_TAG
            b.extend_from_slice(&1u32.to_le_bytes()); // one digest
            b.extend_from_slice(&0x0cu16.to_le_bytes());
            b.extend_from_slice(&[0u8; 48]);
            let mut data = vec![0u8; 4];
            data.extend_from_slice(&(text.len() as u32).to_le_bytes());
            data.extend_from_slice(text.as_bytes());
            b.extend_from_slice(&(data.len() as u32).to_le_bytes());
            b.extend_from_slice(&data);
        }
        B64.encode(b)
    }

    fn ev(op: &str, owner: &str, scan: &str) -> String {
        format!(
            r#"tapp.0g.com {op} {{"owner":"{owner}","kbs_node_urls":["https://kms:9443"],"scan_url":"{scan}","scan_public_key":"0x01"}}"#
        )
    }

    #[test]
    fn a_resume_that_repeats_the_state_is_not_a_finding() {
        let log = log_of(&[ev("claim_config", "0xa", "https://s1"), ev("claim_resumed", "0xa", "https://s1")]);
        let a = eventlog_trust_anchors(&log).unwrap().unwrap();
        assert!(!a.resumed_differently);
        assert_eq!(a.scan_url, "https://s1");
        assert_eq!(eventlog_claim_config_owner(&log).unwrap().as_deref(), Some("0xa"));
    }

    #[test]
    fn a_resume_after_an_update_compares_with_the_update() {
        let log = log_of(&[
            ev("claim_config", "0xa", "https://s1"),
            ev("update_trust_anchors", "0xa", "https://s2"),
            ev("claim_resumed", "0xa", "https://s2"),
        ]);
        let a = eventlog_trust_anchors(&log).unwrap().unwrap();
        assert!(!a.resumed_differently);
        assert_eq!((a.scan_url.as_str(), a.revisions), ("https://s2", 1));
    }

    #[test]
    fn anchors_changed_between_processes_are_reported() {
        let log = log_of(&[ev("claim_config", "0xa", "https://s1"), ev("claim_resumed", "0xa", "https://evil")]);
        let a = eventlog_trust_anchors(&log).unwrap().unwrap();
        assert!(a.resumed_differently);
        assert_eq!(a.scan_url, "https://evil");
    }

    #[test]
    fn a_config_that_was_not_carried_over_is_not_called_changed() {
        let mut resumed = ev("claim_resumed", "0xa", "");
        resumed = resumed.replace(r#""scan_public_key""#, r#""config_resumed":false,"scan_public_key""#);
        let log = log_of(&[ev("claim_config", "0xa", "https://s1"), resumed]);
        let a = eventlog_trust_anchors(&log).unwrap().unwrap();
        assert!(a.not_carried_over);
        assert!(!a.resumed_differently);
    }

    #[test]
    fn an_unreadable_config_is_told_apart_from_an_absent_one() {
        let with = |state: &str| {
            ev("claim_resumed", "0xa", "").replace(
                r#""scan_public_key""#,
                &format!(r#""config_resumed":{state},"scan_public_key""#),
            )
        };
        let a = eventlog_trust_anchors(&log_of(&[ev("claim_config", "0xa", "https://s1"), with(r#""absent""#)]))
            .unwrap()
            .unwrap();
        assert!(a.not_carried_over && !a.config_unreadable && !a.resumed_differently);
        let a = eventlog_trust_anchors(&log_of(&[ev("claim_config", "0xa", "https://s1"), with(r#""unreadable""#)]))
            .unwrap()
            .unwrap();
        assert!(a.config_unreadable && !a.not_carried_over && !a.resumed_differently);
        // A later update measures the anchors in force again.
        let a = eventlog_trust_anchors(&log_of(&[
            ev("claim_config", "0xa", "https://s1"),
            with(r#""unreadable""#),
            ev("update_trust_anchors", "0xa", "https://s1"),
        ]))
        .unwrap()
        .unwrap();
        assert!(!a.config_unreadable);
    }

    #[test]
    fn a_later_update_clears_the_finding_but_not_its_history() {
        let log = log_of(&[
            ev("claim_config", "0xa", "https://s1"),
            ev("claim_resumed", "0xa", "https://evil"),
            ev("update_trust_anchors", "0xa", "https://s1"),
        ]);
        let a = eventlog_trust_anchors(&log).unwrap().unwrap();
        assert!(!a.resumed_differently);
        assert!(a.ever_resumed_differently);
        assert_eq!(a.scan_url, "https://s1");
    }

    #[test]
    fn an_owner_changed_between_processes_is_inconsistent() {
        let log = log_of(&[ev("claim_config", "0xa", "https://s1"), ev("claim_resumed", "0xb", "https://s1")]);
        assert!(eventlog_claim_config_owner(&log).is_err());
    }
}
