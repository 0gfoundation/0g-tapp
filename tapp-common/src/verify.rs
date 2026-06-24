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
    pub compose_ok: bool, // start_app compose == node effective compose
    pub volumes_ok: bool,
    pub image_ok: bool,
    pub boot_executables: Option<i64>, // AR4SI executables claim (3 = boot chain matched policy)
    pub note: String,
}

impl NodeVerdict {
    pub fn reconciled(&self) -> bool {
        self.signer_ok && self.compose_ok && self.volumes_ok && self.image_ok
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

/// AS verification result: (ear_status, tcb_status, advisory_count, executables_claim).
/// `executables` is the AR4SI executables trust claim (3 = boot chain matched the policy
/// reference values); None if the policy didn't set it / no policy was applied.
type AsVerdict = (String, String, usize, Option<i64>);

/// Submit evidence to CoCo-AS (gRPC). `policy_ids` selects the policy to enforce; pass an
/// empty slice to use the AS default policy (which does NOT check our boot chain).
async fn verify_with_as(
    as_endpoint: &str,
    raw_evidence: &[u8],
    policy_ids: &[String],
) -> Result<AsVerdict> {
    let mut client = AttestationServiceClient::connect(format!("http://{}", as_endpoint))
        .await
        .map_err(|e| anyhow!("connect AS {}: {}", as_endpoint, e))?;
    let req = AttestationRequest {
        verification_requests: vec![IndividualAttestationRequest {
            tee: "tdx".to_string(),
            evidence: B64URL.encode(raw_evidence),
            runtime_data: None, // no nonce binding for pre-generated, signer-bound evidence
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
    Ok((ear_status, tcb, adv, executables))
}

async fn fetch_evidence(tee_url: &str, app_id: &str) -> Result<Vec<u8>> {
    let mut client = TappServiceClient::connect(tee_url.to_string())
        .await
        .map_err(|e| anyhow!("connect {}: {}", tee_url, e))?;
    let resp = client
        .get_evidence(tonic::Request::new(GetEvidenceRequest {
            app_id: app_id.to_owned(),
        }))
        .await
        .map_err(|e| anyhow!("{}", e))?
        .into_inner();
    Ok(resp.evidence)
}

/// Direct (no-chain) verification of a single server: fetch evidence, verify the quote
/// via CoCo-AS, and report what the node attests. No on-chain reconciliation — used when
/// the app is not (yet) registered on-chain, or to check one node directly.
pub struct DirectVerdict {
    pub server: String,
    pub signer: String, // from quote report_data (0x…), as attested (not reconciled)
    pub ear_status: String,
    pub tcb_status: String,
    pub advisories: usize,
    pub boot_executables: Option<i64>, // AR4SI executables claim (3 = boot chain matched policy)
    pub compose_hash: String, // from latest successful start_app, if any
    pub images: Vec<String>,
    pub note: String,
}

pub async fn verify_node_direct(
    server: &str,
    app_id: &str,
    as_endpoint: &str,
    policy_ids: &[String],
) -> Result<DirectVerdict> {
    let mut v = DirectVerdict {
        server: server.to_string(),
        signer: String::new(),
        ear_status: "-".to_string(),
        tcb_status: "-".to_string(),
        advisories: 0,
        boot_executables: None,
        compose_hash: String::new(),
        images: Vec::new(),
        note: String::new(),
    };

    let raw = fetch_evidence(server, app_id).await?;
    let j: serde_json::Value = serde_json::from_slice(&raw)?;
    let quote_b64 = j["quote"].as_str().unwrap_or("");
    let cc_b64 = j["cc_eventlog"].as_str().unwrap_or("");

    if let Ok(rd) = quote_report_data(quote_b64) {
        v.signer = format!("0x{}", hex::encode(&rd[..20]));
    } else {
        v.note = "quote parse failed; ".to_string();
    }

    match verify_with_as(as_endpoint, &raw, policy_ids).await {
        Ok((s, t, a, ex)) => {
            v.ear_status = s;
            v.tcb_status = t;
            v.advisories = a;
            v.boot_executables = ex;
        }
        Err(e) => v.note = format!("{}AS: {}", v.note, e),
    }

    if let Ok(Some(m)) = latest_successful_start(cc_b64, app_id) {
        v.compose_hash = m.compose_hash;
        v.images = m.image_hash.into_values().collect();
    }
    Ok(v)
}

/// Verify every node of `app_id`: read chain, fetch evidence from each node's teeUrl,
/// verify the quote via CoCo-AS, and reconcile evidence against on-chain values.
pub async fn verify_app(
    rpc_url: &str,
    contract: &str,
    app_id: &str,
    as_endpoint: &str,
    policy_ids: &[String],
) -> Result<AppVerdict> {
    let signers = onchain::get_node_list(rpc_url, contract, app_id).await?;
    if signers.is_empty() {
        return Err(anyhow!("app '{}' has no registered nodes on-chain", app_id));
    }
    let app_image_set: HashSet<Vec<u8>> = onchain::get_app_image_hashes(rpc_url, contract, app_id)
        .await?
        .into_iter()
        .collect();

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
            compose_ok: false,
            volumes_ok: false,
            image_ok: false,
            boot_executables: None,
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

        // ② fetch evidence
        let raw = match fetch_evidence(&tee_url, app_id).await {
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

        // ④a signer binding: on-chain signer (20 bytes) present in report_data
        if let Ok(rd) = quote_report_data(quote_b64) {
            let needle = signer.as_bytes();
            v.signer_ok = rd.windows(needle.len()).any(|w| w == needle);
        } else {
            v.note = "quote parse failed; ".to_string();
        }

        // ③ AS quote verification
        match verify_with_as(as_endpoint, &raw, policy_ids).await {
            Ok((s, t, a, ex)) => {
                v.ear_status = s;
                v.tcb_status = t;
                v.advisories = a;
                v.boot_executables = ex;
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

        nodes.push(v);
    }

    Ok(AppVerdict {
        app_id: app_id.to_string(),
        nodes,
    })
}
