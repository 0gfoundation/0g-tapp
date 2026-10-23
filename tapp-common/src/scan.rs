//! App identities resolved through a configured, TLS-pinned tappscan.
//!
//! The scan's pin and chain/registry scope are trust anchors supplied by the caller.
//! Only current registered signers are candidates; each requires a complete positive
//! `POST /api/verify` verdict. The 300-second acceptance window is local policy over
//! the scan's check time, not a claim that a quote was challenged by this caller.
//! No service-signing identity is inferred from a node signer or an app's TLS key.

use crate::{pinned_tls, identity::{KeyIdentity, KeyCommitment}};
use reqwest::{Client, Method, Url};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::task::JoinSet;

pub const ACCEPTANCE_TTL_SECS: i64 = 300;
const CLOCK_SKEW_SECS: i64 = 30;
const MAX_NODES: usize = 64;
const CONCURRENT_VERIFICATIONS: usize = 8;
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedAppIdentity {
    pub chain_id: u64,
    /// Canonical lowercase 0x-prefixed registry address.
    pub registry: String,
    /// App names are case sensitive; surrounding whitespace is removed.
    pub app_id: String,
    pub scanned_to_block: u64,
    pub resolved_at: i64,
    pub nodes: Vec<ResolvedNodeIdentity>,
    pub registered_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedNodeIdentity {
    pub node_signer: String,
    /// The registered evidence/management URL. The app TLS pin below does NOT
    /// authenticate this URL: an app's own service can use a different endpoint.
    pub tee_url: String,
    /// SHA-256 of the attested app TLS SPKI, lowercase hex without 0x.
    pub tls_spki_sha256: String,
    pub checked_at: i64,
    pub expires_at: i64,
    pub tcb_status: String,
    pub advisories: Vec<String>,
    /// The scan's reference-value policy result (prod or dev), preserved for callers.
    pub image_env: String,
    pub app_signer: String,
    pub identities: Vec<KeyIdentity>,
    pub key_commitments: Vec<KeyCommitment>,
    pub kms_unchecked: u64,
}

/// Errors name the failed boundary without echoing upstream bodies or credentials.
#[derive(Debug, Error)]
pub enum ResolveError {
    #[error("invalid identity resolver configuration: {0}")]
    InvalidConfig(&'static str),
    #[error("scan transport failed during {0}")]
    Transport(&'static str),
    #[error("scan returned HTTP {status} during {operation}")]
    HttpStatus { operation: &'static str, status: u16 },
    #[error("scan response exceeded the size limit")]
    ResponseTooLarge,
    #[error("invalid scan response: {0}")]
    InvalidResponse(&'static str),
    #[error("scan chain or registry does not match the configured scope")]
    ScopeMismatch,
    #[error("scan scope changed or its block cursor regressed during resolution")]
    ScopeChanged,
    #[error("scan result is stale or has an invalid timestamp: {0}")]
    Stale(&'static str),
    #[error("scan could not complete verification")]
    UpstreamFault,
    #[error("app exceeds the maximum of 64 current signers")]
    TooManyNodes,
    #[error("app has no verified current nodes")]
    NoVerifiedNodes,
    #[error("app identity is not ready: {0}")]
    IdentityPending(&'static str),
    #[error("app identity resolution timed out")]
    Timeout,
}

struct Scope {
    chain_id: u64,
    registry: String,
    app_id: String,
}

struct Health {
    scanned_to_block: u64,
}

struct VerifiedReply {
    node: Option<ResolvedNodeIdentity>,
    registered_at: u64,
    pending: bool,
}

/// Resolve current app nodes through HTTPS authenticated by the configured scan
/// SPKI pin. Redirects and environment proxies are disabled. Definitive negative
/// or incomplete node verdicts can be omitted when another node is ready;
/// transport, malformed responses and verifier faults
/// abort the whole resolution, even if another node verified successfully.
pub async fn resolve_app_identity(
    scan_url: &str,
    scan_pin: &str,
    chain_id: u64,
    registry: &str,
    app_id: &str,
) -> Result<ResolvedAppIdentity, ResolveError> {
    let base = scan_base(scan_url)?;
    let registry = address(registry)
        .ok_or(ResolveError::InvalidConfig("registry must be a nonzero 20-byte address"))?;
    let app_id = app_id.trim();
    if app_id.is_empty() || app_id.len() > 1024 || matches!(app_id, "." | "..") {
        return Err(ResolveError::InvalidConfig("invalid app id"));
    }
    if chain_id == 0 {
        return Err(ResolveError::InvalidConfig("chain id must be nonzero"));
    }
    let client = scan_client(scan_pin)?;
    let scope = Scope { chain_id, registry, app_id: app_id.to_string() };
    tokio::time::timeout(Duration::from_secs(120), resolve(&client, &base, &scope))
        .await
        .map_err(|_| ResolveError::Timeout)?
}

fn scan_client(scan_pin: &str) -> Result<Client, ResolveError> {
    let pin = normalize_hex(scan_pin, 32)
        .ok_or(ResolveError::InvalidConfig("scan pin must be a 32-byte SPKI hash"))?;
    Client::builder()
        .use_preconfigured_tls(pinned_tls::client_config([pin]))
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|_| ResolveError::InvalidConfig("cannot initialize scan TLS client"))
}

/// Ask the claimed Scan to verify a newly published identity. Scan obtains its
/// own nonce-bound evidence; this request supplies no evidence or trusted claim.
/// Call only after local measurement and metadata publication have completed.
pub async fn refresh_node(
    scan_url: &str,
    scan_pin: &str,
    app_id: &str,
    node_signer: &str,
) -> Result<(), ResolveError> {
    let base = scan_base(scan_url)?;
    let client = scan_client(scan_pin)?;
    let signer = address(node_signer)
        .ok_or(ResolveError::InvalidConfig("invalid node signer"))?;
    if app_id.trim().is_empty() || app_id.len() > 1024 {
        return Err(ResolveError::InvalidConfig("invalid app id"));
    }
    let body = serde_json::json!({"app_id":app_id,"signer":signer,"refresh":true});
    let value = tokio::time::timeout(
        Duration::from_secs(120),
        request(&client, Method::POST, endpoint(&base, &["verify"]), Some(body), "identity refresh"),
    )
        .await
        .map_err(|_| ResolveError::Timeout)??;
    let scope = value.get("scope").ok_or(ResolveError::InvalidResponse("identity scope missing"))?;
    let status = value.get("status").ok_or(ResolveError::InvalidResponse("verification status missing"))?;
    if string(scope, "app_id")? != app_id || string(status, "app_id")? != app_id
        || address(string(status, "signer")?).as_deref() != Some(signer.as_str()) {
        return Err(ResolveError::InvalidResponse("refresh target mismatch"));
    }
    if !boolean(&value, "verified")? {
        return Err(ResolveError::IdentityPending("Scan has not verified this node"));
    }
    Ok(())
}

async fn resolve(client: &Client, base: &Url, scope: &Scope) -> Result<ResolvedAppIdentity, ResolveError> {
    let before = health(client, base, scope).await?;
    let apps_url = endpoint(base, &["apps", &scope.app_id]);
    let app = request(client, Method::GET, apps_url, None, "app discovery").await?;
    if string(&app, "app_id")? != scope.app_id {
        return Err(ResolveError::InvalidResponse("app discovery binding mismatch"));
    }
    let signers = app.get("current_signers").and_then(Value::as_array)
        .ok_or(ResolveError::InvalidResponse("current signers missing"))?;
    if signers.len() > MAX_NODES { return Err(ResolveError::TooManyNodes); }
    let mut candidates = BTreeSet::new();
    for signer in signers {
        let signer = signer.as_str().and_then(address)
            .ok_or(ResolveError::InvalidResponse("invalid current signer"))?;
        candidates.insert(signer);
    }
    let mut nodes = Vec::new();
    let mut identity_pending = false;
    let mut registered_at = None;
    let candidates: Vec<_> = candidates.into_iter().collect();
    for group in candidates.chunks(CONCURRENT_VERIFICATIONS) {
        let mut work = JoinSet::new();
        for signer in group {
            let client = client.clone();
            let url = endpoint(base, &["verify"]);
            let app_id = scope.app_id.clone();
            let signer = signer.clone();
            let chain_id = scope.chain_id;
            let registry = scope.registry.clone();
            work.spawn(async move {
                let body = serde_json::json!({"app_id": app_id, "signer": signer});
                let verdict = request(&client, Method::POST, url.clone(), Some(body.clone()), "node verification").await?;
                let reply = verify_reply(&verdict, &app_id, &signer, chain_id, &registry, now())?;
                if reply.pending {
                    // KMS admission can cache a valid node before its app TLS
                    // identity exists. Refresh once, not once per missing field.
                    let mut body = body;
                    body["refresh"] = Value::Bool(true);
                    let verdict = request(&client, Method::POST, url, Some(body), "node verification").await?;
                    let refreshed = verify_reply(&verdict, &app_id, &signer, chain_id, &registry, now())?;
                    if refreshed.registered_at != reply.registered_at {
                        return Err(ResolveError::ScopeChanged);
                    }
                    Ok(refreshed)
                } else {
                    Ok(reply)
                }
            });
        }
        while let Some(reply) = work.join_next().await {
            let reply = reply.map_err(|_| ResolveError::UpstreamFault)??;
            if registered_at.is_some_and(|epoch| epoch != reply.registered_at) {
                return Err(ResolveError::ScopeChanged);
            }
            registered_at = Some(reply.registered_at);
            identity_pending |= reply.pending;
            if let Some(node) = reply.node { nodes.push(node); }
        }
    }
    // A scan repointed to another registry while requests were in flight must
    // not combine the old candidates with the new verdicts into one identity.
    let after = health(client, base, scope).await?;
    if after.scanned_to_block < before.scanned_to_block {
        return Err(ResolveError::ScopeChanged);
    }
    let resolved_at = now();
    for node in &mut nodes {
        fresh(node.checked_at, resolved_at, "node check")?;
        if node.expires_at <= resolved_at { return Err(ResolveError::Stale("identity lease")); }
        node.expires_at = node.expires_at.min(resolved_at + ACCEPTANCE_TTL_SECS);
    }
    if nodes.is_empty() {
        return Err(if identity_pending {
            ResolveError::IdentityPending("no current node has a complete public identity yet")
        } else {
            ResolveError::NoVerifiedNodes
        });
    }
    let app_signers: BTreeSet<_> = nodes.iter().filter(|n| !n.app_signer.is_empty()).map(|n| n.app_signer.as_str()).collect();
    if app_signers.len() > 1 { return Err(ResolveError::InvalidResponse("nodes disagree about app signer")); }
    let mut references = std::collections::BTreeMap::new();
    let mut kms_roles = std::collections::BTreeMap::new();
    for node in &nodes {
        for reference in &node.key_commitments {
            let key = (&reference.material, &reference.scheme);
            if references.insert(key, &reference.commitment).is_some_and(|old| old != &reference.commitment) {
                return Err(ResolveError::InvalidResponse("nodes disagree about KMS commitment"));
            }
        }
        for key in node.identities.iter().filter(|key| key.key_source == "kms") {
            if kms_roles.insert(&key.role, key).is_some_and(|old| old != key) {
                return Err(ResolveError::InvalidResponse("nodes disagree about KMS identity"));
            }
        }
    }
    drop(references);
    drop(kms_roles);
    nodes.sort_by(|a, b| a.node_signer.cmp(&b.node_signer));
    Ok(ResolvedAppIdentity {
        chain_id: scope.chain_id, registry: scope.registry.clone(), app_id: scope.app_id.clone(),
        scanned_to_block: after.scanned_to_block, resolved_at, nodes,
        registered_at: registered_at.ok_or(ResolveError::NoVerifiedNodes)?,
    })
}

async fn health(client: &Client, base: &Url, scope: &Scope) -> Result<Health, ResolveError> {
    let value = request(client, Method::GET, endpoint(base, &["health"]), None, "scope check").await?;
    let chain_id = value.get("chain_id").and_then(Value::as_u64)
        .ok_or(ResolveError::InvalidResponse("scan chain id missing"))?;
    let registry = address(string(&value, "contract")?)
        .ok_or(ResolveError::InvalidResponse("invalid scan registry"))?;
    if chain_id != scope.chain_id || registry != scope.registry { return Err(ResolveError::ScopeMismatch); }
    let refreshed_at = integer(&value, "refreshed_at")?;
    fresh(refreshed_at, now(), "scan refresh")?;
    let scanned_to_block = value.get("scanned_to_block").and_then(Value::as_u64)
        .ok_or(ResolveError::InvalidResponse("scan block cursor missing"))?;
    Ok(Health { scanned_to_block })
}

fn verify_reply(value: &Value, app_id: &str, signer: &str, chain_id: u64, registry: &str, at: i64) -> Result<VerifiedReply, ResolveError> {
    if string(value, "app_id")? != app_id || address(string(value, "signer")?).as_deref() != Some(signer) {
        return Err(ResolveError::InvalidResponse("verification binding mismatch"));
    }
    let scope = value.get("scope").ok_or(ResolveError::InvalidResponse("identity scope missing"))?;
    if scope.get("chain_id").and_then(Value::as_u64) != Some(chain_id)
        || address(string(scope, "registry_address")?).as_deref() != Some(registry)
        || string(scope, "app_id")? != app_id { return Err(ResolveError::ScopeMismatch); }
    let registered_at = scope.get("registered_at").and_then(Value::as_u64).filter(|e| *e > 0)
        .ok_or(ResolveError::InvalidResponse("registration instance missing"))?;
    let verified = boolean(value, "verified")?;
    let status = value.get("status").filter(|v| v.is_object())
        .ok_or(ResolveError::InvalidResponse("verification status missing"))?;
    if string(status, "app_id")? != app_id || address(string(status, "signer")?).as_deref() != Some(signer) {
        return Err(ResolveError::InvalidResponse("status binding mismatch"));
    }
    if boolean(status, "verifier_fault")? { return Err(ResolveError::UpstreamFault); }
    let checked_at = integer(status, "checked_at")?;
    fresh(checked_at, at, "node check")?;
    let _app_latest_block = status.get("app_latest_block").and_then(Value::as_u64)
        .ok_or(ResolveError::InvalidResponse("app block missing"))?;
    let error = status.get("error").ok_or(ResolveError::InvalidResponse("status error field missing"))?;
    if !error.is_null() && !error.is_string() { return Err(ResolveError::InvalidResponse("invalid status error")); }
    if !verified {
        if string(value, "reason")?.trim().is_empty() {
            return Err(ResolveError::InvalidResponse("negative verification has no reason"));
        }
        return Ok(VerifiedReply { node: None, registered_at, pending: false });
    }
    if !error.is_null() || !string(value, "reason")?.is_empty() {
        return Err(ResolveError::InvalidResponse("positive verification contains an error"));
    }
    if status.get("registered_at").and_then(Value::as_u64) != Some(registered_at) {
        return Err(ResolveError::InvalidResponse("cached verification belongs to another registration instance"));
    }
    let expires_at = integer(value, "expires_at")?;
    if integer(value, "checked_at")? != checked_at || expires_at <= at || expires_at > checked_at + ACCEPTANCE_TTL_SECS {
        return Err(ResolveError::Stale("identity lease"));
    }
    let attested = status.get("attested").filter(|v| v.is_object())
        .ok_or(ResolveError::InvalidResponse("attested status missing"))?;
    if !boolean(attested, "fresh")? { return Err(ResolveError::InvalidResponse("fresh attestation was not established")); }
    if address(string(attested, "attested_signer")?).as_deref() != Some(signer) || !boolean(attested, "signer_ok")? {
        return Err(ResolveError::InvalidResponse("attested signer mismatch"));
    }
    if !boolean(attested, "runtime_replay_ok")? || boolean(attested, "td_debug")? {
        return Err(ResolveError::InvalidResponse("unsafe runtime verdict"));
    }
    let identities_verified = boolean(value, "identities_verified")?;
    if attested.get("identities_error").is_some_and(|e| !e.is_null()) {
        return Err(ResolveError::InvalidResponse("typed identities were not verified"));
    }
    let tcb_status = string(attested, "tcb_status")?;
    if tcb_status.is_empty() || tcb_status.eq_ignore_ascii_case("Revoked") {
        return Err(ResolveError::InvalidResponse("unacceptable platform TCB status"));
    }
    let advisories = attested.get("advisories").and_then(Value::as_array)
        .ok_or(ResolveError::InvalidResponse("TCB advisories missing"))?
        .iter().map(|a| a.as_str().map(str::to_string)
            .ok_or(ResolveError::InvalidResponse("invalid TCB advisory")))
        .collect::<Result<Vec<_>, _>>()?;
    let image_env = string(value, "image_env")?;
    if !matches!(image_env, "prod" | "dev") || string(attested, "image")?.is_empty() {
        return Err(ResolveError::InvalidResponse("image policy result missing"));
    }
    let identities: Vec<KeyIdentity> = serde_json::from_value(attested.get("identities").cloned()
        .ok_or(ResolveError::InvalidResponse("typed identities missing"))?)
        .map_err(|_| ResolveError::InvalidResponse("invalid typed identities"))?;
    let commitments: Vec<KeyCommitment> = serde_json::from_value(attested.get("key_commitments").cloned()
        .ok_or(ResolveError::InvalidResponse("key commitments missing"))?)
        .map_err(|_| ResolveError::InvalidResponse("invalid key commitments"))?;
    let tee_url = string(status, "tee_url")?;
    let url = Url::parse(tee_url).map_err(|_| ResolveError::InvalidResponse("invalid registered tee URL"))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() || !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err(ResolveError::InvalidResponse("invalid registered tee URL"));
    }
    if !identities_verified {
        // Scan deliberately strips unverified metadata. An absent legacy schema
        // is pending; malformed or leaked unverified metadata is a hard failure.
        if !identities.is_empty() || !commitments.is_empty()
            || attested.get("app_signer").is_some_and(|v| !v.is_null() && v.as_str() != Some("")) {
            return Err(ResolveError::InvalidResponse("unverified response contains typed metadata"));
        }
        return Ok(VerifiedReply { node: None, registered_at, pending: true });
    }
    if identities.is_empty() { return Err(ResolveError::InvalidResponse("empty typed identities")); }
    let pin = match attested.get("tls_public_key") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if s.is_empty() => None,
        Some(Value::String(s)) => Some(normalize_hex(s, 32)
            .ok_or(ResolveError::InvalidResponse("invalid app TLS SPKI hash"))?),
        _ => return Err(ResolveError::InvalidResponse("invalid app TLS SPKI hash")),
    };
    let mut app_signer = String::new();
    let mut materials = BTreeSet::new();
    for commitment in &commitments {
        if commitment.problem().is_some() || !materials.insert((commitment.material.as_str(), commitment.scheme.as_str())) {
            return Err(ResolveError::InvalidResponse("invalid or conflicting key commitments"));
        }
    }
    let mut roles = BTreeSet::new();
    for identity in &identities {
        if identity.problem().is_some() || identity.key_ref.as_ref().is_some_and(|r| !commitments.contains(r)) {
            return Err(ResolveError::InvalidResponse("invalid typed key or commitment reference"));
        }
        if identity.role == "node_signer" && identity.ethereum_address().as_deref() != Some(signer) {
            return Err(ResolveError::InvalidResponse("node public key/address mismatch"));
        }
        if identity.role == "tls" && (pin.is_none() || identity.tls_spki_hash().and_then(|s| normalize_hex(&s,32)).as_deref() != pin.as_deref()) {
            return Err(ResolveError::InvalidResponse("TLS public key/SPKI mismatch"));
        }
        if !roles.insert(identity.role.as_str()) { return Err(ResolveError::InvalidResponse("duplicate identity role")); }
        if identity.role == "app_signer" {
            if identity.algorithm != "ecdsa-secp256k1" || identity.key_source != "kms" || identity.key_ref.is_none() {
                return Err(ResolveError::InvalidResponse("invalid app signer identity"));
            }
            let public_key = hex::decode(identity.public_key.strip_prefix("0x").unwrap_or(""))
                .map_err(|_| ResolveError::InvalidResponse("invalid app signer public key"))?;
            let raw = crate::app_key::eth_address_of_public_key(&public_key)
                .ok_or(ResolveError::InvalidResponse("invalid app signer curve point"))?;
            app_signer = format!("0x{}", hex::encode(raw));
        }
    }
    if !roles.contains("node_signer") {
        return Err(ResolveError::InvalidResponse("node identity missing"));
    }
    if attested.get("app_signer").and_then(Value::as_str).unwrap_or("") != app_signer {
        return Err(ResolveError::InvalidResponse("app signer summary mismatch"));
    }
    if !roles.contains("tls") {
        if pin.is_some() {
            return Err(ResolveError::InvalidResponse("TLS fingerprint has no typed identity"));
        }
        return Ok(VerifiedReply { node: None, registered_at, pending: true });
    }
    let pin = pin.ok_or(ResolveError::InvalidResponse("app TLS SPKI hash missing"))?;
    Ok(VerifiedReply { registered_at, pending: false, node: Some(ResolvedNodeIdentity {
        node_signer: signer.to_string(), tee_url: tee_url.to_string(), tls_spki_sha256: pin,
        checked_at, expires_at,
        tcb_status: tcb_status.to_string(), advisories, image_env: image_env.to_string(),
        app_signer, identities, key_commitments: commitments,
        kms_unchecked: attested.get("identities_unchecked").and_then(Value::as_u64).unwrap_or(0),
    }) })
}

async fn request(client: &Client, method: Method, url: Url, body: Option<Value>, operation: &'static str) -> Result<Value, ResolveError> {
    let mut request = client.request(method, url);
    if matches!(operation, "node verification" | "identity refresh") {
        // A cold verification fetches a quote and then waits for the AS. The
        // resolver's outer deadline still caps the entire multi-node lookup.
        request = request.timeout(Duration::from_secs(90));
    }
    if let Some(body) = body { request = request.json(&body); }
    let mut response = request.send().await.map_err(|_| ResolveError::Transport(operation))?;
    if !response.status().is_success() {
        return Err(ResolveError::HttpStatus { operation, status: response.status().as_u16() });
    }
    if response.content_length().is_some_and(|n| n > MAX_RESPONSE_BYTES as u64) {
        return Err(ResolveError::ResponseTooLarge);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| ResolveError::Transport(operation))? {
        if chunk.len() > MAX_RESPONSE_BYTES - body.len() { return Err(ResolveError::ResponseTooLarge); }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| ResolveError::InvalidResponse("invalid JSON"))
}

fn scan_base(value: &str) -> Result<Url, ResolveError> {
    let url = Url::parse(value).map_err(|_| ResolveError::InvalidConfig("invalid scan URL"))?;
    if url.scheme() != "https" || url.host_str().is_none() || !url.username().is_empty() || url.password().is_some() || url.query().is_some() || url.fragment().is_some() {
        return Err(ResolveError::InvalidConfig("scan URL must be HTTPS without credentials, query or fragment"));
    }
    Ok(url)
}

fn endpoint(base: &Url, tail: &[&str]) -> Url {
    let mut url = base.clone();
    let has_api = base.path().trim_end_matches('/').rsplit('/').next() == Some("api");
    let mut path = url.path_segments_mut().expect("HTTPS URLs support path segments");
    path.pop_if_empty();
    if !has_api { path.push("api"); }
    for segment in tail { path.push(segment); }
    drop(path);
    url
}

fn normalize_hex(value: &str, bytes: usize) -> Option<String> {
    let value = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")).unwrap_or(value);
    if value.len() != bytes * 2 || !value.bytes().all(|b| b.is_ascii_hexdigit()) { return None; }
    Some(value.to_ascii_lowercase())
}

fn address(value: &str) -> Option<String> {
    let value = normalize_hex(value, 20)?;
    if value.bytes().all(|b| b == b'0') { return None; }
    Some(format!("0x{value}"))
}

fn fresh(timestamp: i64, at: i64, field: &'static str) -> Result<(), ResolveError> {
    if timestamp <= 0 || timestamp > at.saturating_add(CLOCK_SKEW_SECS) || timestamp <= at.saturating_sub(ACCEPTANCE_TTL_SECS) {
        return Err(ResolveError::Stale(field));
    }
    Ok(())
}

fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str, ResolveError> {
    value.get(key).and_then(Value::as_str).ok_or(ResolveError::InvalidResponse("required string missing"))
}
fn integer(value: &Value, key: &str) -> Result<i64, ResolveError> {
    value.get(key).and_then(Value::as_i64).ok_or(ResolveError::InvalidResponse("required timestamp missing"))
}
fn boolean(value: &Value, key: &str) -> Result<bool, ResolveError> {
    value.get(key).and_then(Value::as_bool).ok_or(ResolveError::InvalidResponse("required boolean missing"))
}
fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const REGISTRY: &str = "0x1111111111111111111111111111111111111111";
    const NODE: &str = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf";
    const NODE2: &str = "0x2b5ad5c4795c026514f8317c7a215e218dccd6cf";
    const PUB: &str = "0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    fn verdict() -> Value {
        let timestamp = now();
        let node = json!({"role":"node_signer","algorithm":"ecdsa-secp256k1","derivation":"tapp-app-signer-v1",
            "key_source":"local","public_key":PUB,"public_key_encoding":"sec1-compressed"});
        let app = json!({"role":"app_signer","algorithm":"ecdsa-secp256k1","derivation":"raw-scalar-v1",
            "key_source":"kms","public_key":PUB,"public_key_encoding":"sec1-compressed",
            "key_ref":{"material":"70726f7669646572","scheme":"poseidon-bn254-4-v1","commitment":format!("0x{}","01".repeat(32))}});
        let tls = json!({"role":"tls","algorithm":"ecdsa-p256","derivation":"tapp-tls-v1-sha256",
            "key_source":"local","public_key":"0x036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
            "public_key_encoding":"sec1-compressed"});
        let tls_pin = serde_json::from_value::<KeyIdentity>(tls.clone()).unwrap().tls_spki_hash().unwrap();
        let commitment = app["key_ref"].clone();
        json!({"app_id":"app","signer":NODE,"verified":true,"identities_verified":true,"reason":"",
            "scope":{"chain_id":16602,"registry_address":REGISTRY,"app_id":"app","registered_at":100},
            "scope_block":50,"checked_at":timestamp,"expires_at":timestamp+60,"image_env":"prod",
            "status":{"app_id":"app","signer":NODE,"tee_url":"https://node.example:50052","checked_at":timestamp,
                "app_latest_block":40,"registered_at":100,"error":null,"verifier_fault":false,
                "attested":{"fresh":true,"attested_signer":NODE,"signer_ok":true,"runtime_replay_ok":true,"td_debug":false,
                    "tls_public_key":tls_pin,"key_commitments":[commitment],"tcb_status":"UpToDate","advisories":[],"image":"release",
                    "app_signer":NODE,"identities":[node,app,tls]}}})
    }

    fn verdict_for(signer: &str) -> Value {
        let mut body = verdict();
        if signer == NODE2 {
            use k256::elliptic_curve::sec1::ToEncodedPoint;
            let mut scalar = [0u8; 32]; scalar[31] = 2;
            let key = k256::SecretKey::from_slice(&scalar).unwrap();
            let identity = KeyIdentity::node(key.public_key().to_encoded_point(true).as_bytes(), "app").unwrap();
            assert_eq!(identity.ethereum_address().as_deref(), Some(NODE2));
            body["status"]["attested"]["identities"][0] = serde_json::to_value(identity).unwrap();
        }
        body["signer"] = json!(signer);
        body["status"]["signer"] = json!(signer);
        body["status"]["attested"]["attested_signer"] = json!(signer);
        body
    }

    #[test]
    fn bindings_scope_freshness_and_typed_verification_are_required() {
        let good = verdict();
        assert!(verify_reply(&good,"app",NODE,16602,REGISTRY,now()).unwrap().node.is_some());
        for path in ["/scope/app_id","/status/app_id","/status/signer","/status/attested/attested_signer"] {
            let mut bad = good.clone();
            *bad.pointer_mut(path).unwrap() = json!("wrong");
            assert!(verify_reply(&bad,"app",NODE,16602,REGISTRY,now()).is_err(),"{path}");
        }
        let mut bad = good.clone(); bad["identities_verified"] = json!(false);
        assert!(verify_reply(&bad,"app",NODE,16602,REGISTRY,now()).is_err());
        let mut bad = good.clone(); bad["scope"]["registered_at"] = json!(0);
        assert!(verify_reply(&bad,"app",NODE,16602,REGISTRY,now()).is_err());
        let mut bad = good.clone(); bad["expires_at"] = json!(now()-1);
        assert!(verify_reply(&bad,"app",NODE,16602,REGISTRY,now()).is_err());
        let mut bad = good.clone(); bad["status"]["checked_at"] = json!(now()-301);
        assert!(verify_reply(&bad,"app",NODE,16602,REGISTRY,now()).is_err());
        let mut bad = good.clone(); bad["status"]["attested"]["app_signer"] = json!(REGISTRY);
        assert!(verify_reply(&bad,"app",NODE,16602,REGISTRY,now()).is_err());
        assert!(verify_reply(&good,"app",NODE,1,REGISTRY,now()).is_err());
    }

    #[test]
    fn url_prefix_and_app_id_are_encoded_as_segments() {
        let base = scan_base("https://scan.example/mainnet/").unwrap();
        assert_eq!(endpoint(&base,&["apps","a/b?c#d"]).as_str(),"https://scan.example/mainnet/api/apps/a%2Fb%3Fc%23d");
        assert_eq!(endpoint(&scan_base("https://scan.example/mainnet/api/").unwrap(),&["health"]).path(),"/mainnet/api/health");
        for invalid in ["http://scan.example","https://u:p@scan.example","https://scan.example/?net=mainnet"] {
            assert!(scan_base(invalid).is_err());
        }
    }

    struct ScanServer {
        url:String,
        pin:String,
        requests:Arc<std::sync::Mutex<Vec<Value>>>,
        task:tokio::task::JoinHandle<()>,
    }
    impl Drop for ScanServer { fn drop(&mut self) { self.task.abort(); } }

    async fn server(mode: &'static str) -> ScanServer {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let pin = pinned_tls::spki_sha256(&certificate.cert.der().clone()).unwrap();
        let config = rustls::ServerConfig::builder().with_no_client_auth()
            .with_single_cert(vec![certificate.cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.key_pair.serialize_der()).into()).unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("https://localhost:{}",listener.local_addr().unwrap().port());
        let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
        let received = requests.clone();
        let task = tokio::spawn(async move {
            loop {
                let (stream,_) = listener.accept().await.unwrap();
                let acceptor = acceptor.clone();
                let received = received.clone();
                tokio::spawn(async move {
                    let Ok(mut stream) = acceptor.accept(stream).await else { return };
                    let mut bytes = Vec::new();
                    let end = loop {
                        let mut buf = [0;1024];
                        let n = stream.read(&mut buf).await.unwrap_or(0);
                        if n == 0 { return; }
                        bytes.extend_from_slice(&buf[..n]);
                        if bytes.len() > 64*1024 { return; }
                        if let Some(i) = bytes.windows(4).position(|w| w == b"\r\n\r\n") { break i+4; }
                    };
                    let headers = String::from_utf8_lossy(&bytes[..end]).to_string();
                    let length = headers.lines().find_map(|line| {
                        let (key,value) = line.split_once(':')?;
                        key.eq_ignore_ascii_case("content-length").then(|| value.trim().parse::<usize>().ok()).flatten()
                    }).unwrap_or(0);
                    while bytes.len() < end+length {
                        let mut buf=[0;1024]; let n=stream.read(&mut buf).await.unwrap_or(0);
                        if n==0 { return; } bytes.extend_from_slice(&buf[..n]);
                    }
                    let path = headers.lines().next().unwrap().split_whitespace().nth(1).unwrap();
                    let (code, body, extra) = if mode == "redirect" {
                        (307,json!({}),"Location: http://127.0.0.1:1/identity\r\n")
                    } else if path.ends_with("/health") {
                        (200,json!({"chain_id":if mode=="scope" {1} else {16602},"contract":REGISTRY,
                            "scanned_to_block":50,"refreshed_at":now()}),"")
                    } else if path.ends_with("/apps/app") {
                        let signers = if mode.starts_with("multi_") { vec![NODE,NODE2] } else { vec![NODE] };
                        (200,json!({"app_id":"app","current_signers":signers}),"")
                    } else {
                        let req: Value = serde_json::from_slice(&bytes[end..end+length]).unwrap();
                        assert_eq!(req["app_id"], "app");
                        let signer = req["signer"].as_str().unwrap();
                        assert!(signer == NODE || (mode.starts_with("multi_") && signer == NODE2));
                        received.lock().unwrap().push(req.clone());
                        let mut body = verdict_for(signer);
                        let pending = mode == "still_pending"
                            || (mode == "pending_tls" && req["refresh"] != true)
                            || mode == "multi_all_pending"
                            || (mode.starts_with("multi_") && signer == NODE2);
                        if pending {
                            body["status"]["attested"]["identities"].as_array_mut().unwrap()
                                .retain(|identity| identity["role"] != "tls");
                            body["status"]["attested"]["tls_public_key"] = Value::Null;
                        }
                        if mode == "pending_metadata" && req["refresh"] != true {
                            body["identities_verified"] = json!(false);
                            body["status"]["attested"]["identities"] = json!([]);
                            body["status"]["attested"]["key_commitments"] = json!([]);
                            body["status"]["attested"]["app_signer"] = Value::Null;
                        }
                        if signer == NODE2 && (mode == "multi_pending_epoch"
                            || (mode == "multi_refresh_epoch" && req["refresh"] == true)) {
                            body["scope"]["registered_at"] = json!(101);
                            body["status"]["registered_at"] = json!(101);
                        }
                        if mode == "multi_pending_bad_node" && signer == NODE2 {
                            body["status"]["attested"]["identities"][0]["public_key"] = json!("0x00");
                        }
                        if mode == "multi_pending_bad_commitment" && signer == NODE2 {
                            body["status"]["attested"]["key_commitments"][0]["scheme"] = json!("invalid");
                        }
                        if mode == "invalid_metadata" {
                            body["status"]["attested"]["identities"][2]["public_key"] = json!("0x00");
                        }
                        if mode == "negative" {
                            body["verified"] = json!(false);
                            body["reason"] = json!("node is not ready");
                        }
                        (200,body,"")
                    };
                    let body = serde_json::to_vec(&body).unwrap();
                    let head = format!("HTTP/1.1 {code} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n",body.len());
                    let _ = stream.write_all(head.as_bytes()).await;
                    let _ = stream.write_all(&body).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        ScanServer{url,pin,requests,task}
    }

    #[tokio::test]
    async fn pinned_tls_resolves_app_identity_and_rejects_wrong_peer() {
        let scan = server("ok").await;
        let identity = resolve_app_identity(&scan.url,&scan.pin,16602,REGISTRY,"app").await.unwrap();
        assert_eq!(identity.registered_at,100);
        assert_eq!(identity.nodes[0].app_signer,NODE);
        assert_eq!(identity.nodes[0].identities.len(),3);
        assert!(identity.nodes[0].expires_at <= identity.nodes[0].checked_at+60);
        let wrong = "00".repeat(32);
        assert!(matches!(resolve_app_identity(&scan.url,&wrong,16602,REGISTRY,"app").await,Err(ResolveError::Transport(_))));
    }

    #[tokio::test]
    async fn redirects_and_wrong_scope_do_not_produce_an_identity() {
        let scan=server("redirect").await;
        assert!(matches!(resolve_app_identity(&scan.url,&scan.pin,16602,REGISTRY,"app").await,
            Err(ResolveError::HttpStatus{status:307,..})));
        let scan=server("scope").await;
        assert!(matches!(resolve_app_identity(&scan.url,&scan.pin,16602,REGISTRY,"app").await,Err(ResolveError::ScopeMismatch)));
    }

    #[tokio::test]
    async fn missing_identity_observation_is_refreshed_once_before_returning_identity() {
        for mode in ["pending_tls", "pending_metadata"] {
            let scan = server(mode).await;
            let identity = resolve_app_identity(&scan.url, &scan.pin, 16602, REGISTRY, "app").await.unwrap();
            assert!(!identity.nodes[0].tls_spki_sha256.is_empty());
            let requests = scan.requests.lock().unwrap();
            assert_eq!(requests.len(), 2);
            assert!(requests[0].get("refresh").is_none());
            assert_eq!(requests[1]["refresh"], true);
        }
    }

    #[tokio::test]
    async fn incomplete_identity_stops_after_one_refresh_and_malformed_identity_is_not_retried() {
        let scan = server("still_pending").await;
        assert!(matches!(resolve_app_identity(&scan.url, &scan.pin, 16602, REGISTRY, "app").await,
            Err(ResolveError::IdentityPending(_))));
        assert_eq!(scan.requests.lock().unwrap().len(), 2);

        let scan = server("invalid_metadata").await;
        assert!(matches!(resolve_app_identity(&scan.url, &scan.pin, 16602, REGISTRY, "app").await,
            Err(ResolveError::InvalidResponse(_))));
        assert_eq!(scan.requests.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_pending_node_does_not_block_a_ready_node_but_all_pending_is_retryable() {
        let scan = server("multi_one_pending").await;
        let identity = resolve_app_identity(&scan.url, &scan.pin, 16602, REGISTRY, "app").await.unwrap();
        assert_eq!(identity.registered_at, 100);
        assert_eq!(identity.nodes.len(), 1);
        assert_eq!(identity.nodes[0].node_signer, NODE);
        let requests = scan.requests.lock().unwrap();
        assert_eq!(requests.iter().filter(|req| req["signer"] == NODE).count(), 1);
        assert_eq!(requests.iter().filter(|req| req["signer"] == NODE2).count(), 2);
        assert_eq!(requests.iter().filter(|req| req["refresh"] == true).count(), 1);
        drop(requests);

        let scan = server("multi_all_pending").await;
        assert!(matches!(resolve_app_identity(&scan.url, &scan.pin, 16602, REGISTRY, "app").await,
            Err(ResolveError::IdentityPending(_))));
        assert_eq!(scan.requests.lock().unwrap().len(), 4);
    }

    #[tokio::test]
    async fn pending_nodes_cannot_hide_changed_scope_or_malformed_metadata() {
        for mode in ["multi_pending_epoch", "multi_refresh_epoch"] {
            let scan = server(mode).await;
            assert!(matches!(resolve_app_identity(&scan.url, &scan.pin, 16602, REGISTRY, "app").await,
                Err(ResolveError::ScopeChanged)), "{mode}");
        }
        for mode in ["multi_pending_bad_node", "multi_pending_bad_commitment"] {
            let scan = server(mode).await;
            assert!(matches!(resolve_app_identity(&scan.url, &scan.pin, 16602, REGISTRY, "app").await,
                Err(ResolveError::InvalidResponse(_))), "{mode}");
            assert!(!scan.requests.lock().unwrap().iter().any(|req| req["refresh"] == true),
                "malformed metadata must not be retried as pending");
        }
    }

    #[tokio::test]
    async fn refresh_uses_the_pinned_scan_and_rejects_redirects_and_negative_verdicts() {
        let scan = server("ok").await;
        refresh_node(&scan.url, &scan.pin, "app", NODE).await.unwrap();
        assert_eq!(scan.requests.lock().unwrap().as_slice(),
            &[json!({"app_id":"app", "signer":NODE, "refresh":true})]);
        assert!(matches!(refresh_node(&scan.url, &"00".repeat(32), "app", NODE).await,
            Err(ResolveError::Transport(_))));
        let scan = server("redirect").await;
        assert!(matches!(refresh_node(&scan.url, &scan.pin, "app", NODE).await,
            Err(ResolveError::HttpStatus { status:307, .. })));
        let scan = server("negative").await;
        assert!(matches!(refresh_node(&scan.url, &scan.pin, "app", NODE).await,
            Err(ResolveError::IdentityPending(_))));
    }
}
