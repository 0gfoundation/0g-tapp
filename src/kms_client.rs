use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn test_success_single_node() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/app-key"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "encrypted_secret": "0xdeadbeef" })),
            )
            .mount(&server)
            .await;

        let client = KmsClient::new(vec![server.uri()], &Default::default());
        let result = client
            .get_encrypted_secret("myapp", 1234567890, "pubkey_hex", "sig_hex", "")
            .await
            .unwrap();

        assert_eq!(result, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[tokio::test]
    async fn test_material_forwarded_and_empty_omitted() {
        use wiremock::matchers::body_partial_json;

        // Server only matches when the body carries the material field verbatim
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/app-key"))
            .and(body_partial_json(
                serde_json::json!({ "material": "deadbeef01" }),
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "encrypted_secret": "0xcafe" })),
            )
            .mount(&server)
            .await;

        let client = KmsClient::new(vec![server.uri()], &Default::default());

        // material passed through verbatim -> matches
        let result = client
            .get_encrypted_secret("myapp", 1234567890, "pubkey_hex", "sig_hex", "deadbeef01")
            .await
            .unwrap();
        assert_eq!(result, vec![0xca, 0xfe]);

        // empty material -> field omitted from the JSON body -> no match -> error
        let result = client
            .get_encrypted_secret("myapp", 1234567890, "pubkey_hex", "sig_hex", "")
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_failover_to_second_node() {
        // First node: returns 500
        let bad_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/app-key"))
            .respond_with(ResponseTemplate::new(500).set_body_string("internal error"))
            .mount(&bad_server)
            .await;

        // Second node: returns success
        let good_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/app-key"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "encrypted_secret": "cafebabe" })),
            )
            .mount(&good_server)
            .await;

        let client = KmsClient::new(vec![bad_server.uri(), good_server.uri()], &Default::default());
        let result = client
            .get_encrypted_secret("myapp", 1234567890, "pubkey_hex", "sig_hex", "")
            .await
            .unwrap();

        assert_eq!(result, vec![0xca, 0xfe, 0xba, 0xbe]);
    }

    #[tokio::test]
    async fn test_all_nodes_fail() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/app-key"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let client = KmsClient::new(vec![server.uri()], &Default::default());
        let result = client
            .get_encrypted_secret("myapp", 1234567890, "pubkey_hex", "sig_hex", "")
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_no_nodes_configured() {
        let client = KmsClient::new(vec![], &Default::default());
        let result = client
            .get_encrypted_secret("myapp", 1234567890, "pubkey_hex", "sig_hex", "")
            .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no KMS nodes"));
    }
}

#[derive(Serialize)]
struct KmsRequest<'a> {
    app_id: &'a str,
    timestamp: i64,
    /// hex-encoded public key for ECIES encryption by KMS
    /// format depends on ecies feature: secp256k1=uncompressed 65 bytes, x25519=raw 32 bytes
    pubkey: String,
    /// hex-encoded secp256k1 signature over "GetSecretResource:{timestamp}"
    signature: String,
    /// optional hex-encoded derivation material, opaque — forwarded verbatim to
    /// KMS /app-key which binds it into the derived key alongside app_id.
    /// Omitted from the JSON body when empty so the request is byte-identical
    /// to the pre-material format (KMS then derives purely from app_id).
    #[serde(skip_serializing_if = "str::is_empty")]
    material: &'a str,
}

#[derive(Deserialize)]
struct KmsResponse {
    encrypted_secret: String, // hex-encoded ECIES ciphertext
}

#[cfg(test)]
mod onchain_visibility_tests {
    use super::*;

    /// The 404 body the KMS serves for an app it cannot see on-chain yet, verbatim from a
    /// testnet node (`https://136.83.14.240:9443`) during a `start-app --register-onchain`
    /// whose registration had landed on chain seconds earlier.
    const APP_NOT_YET: &str = r#"{"error":"app not found on-chain: r2-probe"}"#;
    /// The 401 body for a signer the KMS's cached node list does not have, as 0g-kms builds
    /// it (`KmsError::InvalidSignature`, src/server.rs): what a node meets right after a
    /// restart replaced it on chain.
    const SIGNER_NOT_YET: &str = r#"{"error":"invalid signature: recovered address 0x2da59224845da5c33e114d2d428c9dc68c4ee0e3 not in on-chain signer list for app tapp-kmssync-test"}"#;
    /// With attested admission on: the scan answered 404 for a signer it has not synced yet
    /// (0g-kms `KmsError::NotAttested`, src/verifier.rs).
    const VERIFIER_NOT_YET: &str = r#"{"error":"attestation required: attestation not verified: not registered on-chain per verifier"}"#;
    /// A damped repeat that says why, as 0g-kms#15 (after 1dae41b) sends for a refusal. That
    /// KMS repeats the lag case above with its plain text rather than damping it; this shape
    /// is matched all the same, since the match is on the reason.
    const VERIFIER_DAMPED_NOT_YET: &str = r#"{"error":"attestation required: attestation not verified (recently checked): not registered on-chain per verifier"}"#;
    const VERIFIER_DAMPED_REFUSAL: &str = r#"{"error":"attestation required: attestation not verified (recently checked): the TD runs with DEBUG: its host can read and write its memory"}"#;
    /// The verifier could not answer: the KMS's first refusal, and its damped repeat
    /// (0g-kms src/verifier.rs). Since 0g-tapp-verifier#16 this is what a failed registry
    /// read at the scan looks like, so it is waited on; the KMS still refuses until the
    /// scan verifies.
    const VERIFIER_UNREACHABLE: &str = r#"{"error":"attestation required: attestation verifier unreachable and this signer has no fresh-enough verdict"}"#;
    const VERIFIER_UNREACHABLE_DAMPED: &str = r#"{"error":"attestation required: attestation not verified (recently checked): verifier unreachable"}"#;
    /// ...and from one that does not. It turns into the real answer within the KMS's 30s
    /// damping, so it is waited on: a lasting refusal then fails fast on that answer.
    const VERIFIER_DAMPED_BARE: &str = r#"{"error":"attestation required: attestation not verified (recently checked)"}"#;
    /// The scan has a result stored from before it recorded the DEBUG attribute and has not
    /// re-attested the node yet (0g-tapp-verifier#16, scan/src/api.rs).
    const VERIFIER_REATTESTING: &str = r#"{"error":"attestation required: attestation not verified: the TD's DEBUG attribute is not known for this result; it needs re-attesting"}"#;

    #[test]
    fn the_transient_answers_are_recognised_and_other_4xx_are_not() {
        let what = |body| not_onchain_yet(body).map(|n| n.what);
        assert_eq!(what(APP_NOT_YET), Some("this app on-chain"));
        assert_eq!(what(SIGNER_NOT_YET), Some("this node's signer on-chain"));
        // Attested admission (0g-kms src/verifier.rs): the verifier has not synced the
        // updateNode yet, or has not re-attested the node.
        for lag in [VERIFIER_NOT_YET, VERIFIER_DAMPED_NOT_YET, VERIFIER_DAMPED_BARE] {
            assert_eq!(what(lag), Some("this node's signer at the verifier"), "{lag}");
        }
        assert_eq!(what(VERIFIER_REATTESTING), Some("this node's evidence re-attested by the verifier"));
        for down in [VERIFIER_UNREACHABLE, VERIFIER_UNREACHABLE_DAMPED] {
            assert_eq!(what(down), Some("a verdict from the verifier"), "{down}");
        }

        // Everything else must keep failing fast — the KMS's own other bodies (0g-kms
        // src/error.rs), and a damped repeat that names a lasting reason, like the reason
        // itself. None of these change by waiting, and waiting on them would turn a clear
        // error into a four-minute hang.
        for fails_fast in [
            VERIFIER_DAMPED_REFUSAL,
            r#"{"error":"invalid signature: invalid signature hex"}"#,
            r#"{"error":"invalid timestamp: request timestamp too old"}"#,
            r#"{"error":"attestation required: attestation not verified: the TD runs with DEBUG: its host can read and write its memory"}"#,
            r#"{"error":"attestation required: attestation not verified: the boot chain matches a dev image, which this network does not accept"}"#,
            r#"{"error":"bad request: missing field"}"#,
            "",
        ] {
            assert!(not_onchain_yet(fails_fast).is_none(), "{fails_fast}");
        }
    }

    #[test]
    fn the_wait_is_long_enough_for_the_cache_it_waits_on() {
        // The KMS caches its on-chain view for ~30s, so anything at or below that is not a
        // wait at all — it would expire before the thing it is waiting for.
        let d = crate::config::RetryConfig::default();
        assert!(
            d.onchain_wait_ms >= 90_000,
            "onchain_wait_ms is {}ms; the KMS's on-chain view is cached ~30s, so a budget under \
             3x that will still fail the case this exists for",
            d.onchain_wait_ms
        );
        // And it is a different budget from the node-error retries, which are seconds.
        assert!(d.onchain_wait_ms > d.max_delay_ms);
        // Signed once, retried with that signature: past the KMS's 300s timestamp tolerance
        // the last attempts would fail on an expired signature, not on visibility.
        assert!(
            d.onchain_wait_ms <= 270_000,
            "onchain_wait_ms is {}ms; it must leave room under the KMS's 300s timestamp tolerance",
            d.onchain_wait_ms
        );
    }
}

#[cfg(test)]
mod pin_tests {
    use super::*;

    #[test]
    fn a_single_pin_is_read_back_as_the_hash_it_encodes() {
        // The value the verifier serves for a one-node app, and what curl would take.
        let body = "sha256//exPRMg5+vJOm7fgJ0Gz5tEcEZ3Rhxv6yxCBOkuVYfps=\n";
        assert_eq!(
            parse_pin_list(body),
            vec!["7b13d1320e7ebc93a6edf809d06cf9b44704677461c6feb2c4204e92e5587e9b"]
        );
    }

    #[test]
    fn every_key_of_a_multi_node_cluster_is_kept() {
        // The normal shape for a `local` key source, which the KMS cluster must use:
        // one key per node. Keeping only the first would reject four nodes out of five.
        let body = "sha256//PWILGq24CQ+HWw8utx3Z3jbMt/7MOIqm1HCjtpEQgpY=;\
                    sha256//TxmXIBTM7s9D2inQCI1Z7da1N5LXxiITb527Ya1q/oM=;\
                    sha256//kXFgqUaRfaPTVMsCZmn9cqlqcYEduu9ofSfk9HqatNQ=";
        assert_eq!(parse_pin_list(body).len(), 3);
    }

    #[test]
    fn a_body_that_is_not_a_pin_list_yields_nothing_rather_than_garbage() {
        // The verifier answers 404 with prose when an app has no attested key. Parsing
        // that into a pin would produce a set nothing can ever match, and the failure
        // would look like every node being compromised.
        for body in [
            "no attested TLS key for this app (nodes predate 0.4.0)",
            "",
            "sha256//!!!not-base64!!!",
        ] {
            assert!(parse_pin_list(body).is_empty(), "accepted {:?}", body);
        }
    }

    #[test]
    fn whitespace_around_entries_is_tolerated() {
        let body = " sha256//exPRMg5+vJOm7fgJ0Gz5tEcEZ3Rhxv6yxCBOkuVYfps= ; \
                     sha256//PWILGq24CQ+HWw8utx3Z3jbMt/7MOIqm1HCjtpEQgpY= \n";
        assert_eq!(parse_pin_list(body).len(), 2);
    }
}

/// An HTTP client that will talk only to peers holding one of `expected`.
///
/// Here rather than beside the verifier because tapp-common has no reqwest; the trust
/// decision itself is shared, only this wrapper is not.
fn pinned_client(expected: impl IntoIterator<Item = String>) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .use_preconfigured_tls(crate::pinned_tls::client_config(expected))
        .build()
        .map_err(|e| anyhow!("build pinned client: {}", e))
}

/// The innermost error, where reqwest puts the TLS failure.
fn root_cause(e: &reqwest::Error) -> String {
    let mut src: &dyn std::error::Error = e;
    while let Some(next) = src.source() {
        src = next;
    }
    src.to_string()
}

/// Whether a request failed because the peer's key was not among the attested ones,
/// as opposed to the network.
///
/// Matched on the message our own verifier produced, which is why that message is worded
/// distinctively — reqwest flattens the rustls error into a string by the time it gets
/// here, and treating a pin failure as "unreachable" would send an operator to look at
/// the wrong machine.
fn is_pin_failure(e: &reqwest::Error) -> bool {
    root_cause(e).contains("is not among the")
}

/// Read a verifier's `/cert` body into sha256 hex hashes.
///
/// The body is what `curl --pinnedpubkey` takes: `sha256//<base64>` entries separated by
/// `;`, several of them when the app's nodes hold a key each — which is the normal state
/// for a `local` key source, and the KMS cluster's only option.
fn parse_pin_list(body: &str) -> Vec<String> {
    use base64::Engine;
    body.trim()
        .split(';')
        .filter_map(|p| p.trim().strip_prefix("sha256//"))
        .filter_map(|b64| {
            base64::engine::general_purpose::STANDARD
                .decode(b64.trim())
                .ok()
        })
        .map(hex::encode)
        .collect()
}

/// Where the expected KMS keys come from, and the copy last obtained.
///
/// Cached because scan must not become a hard dependency of every secret fetch: an
/// attacker who can take it offline would otherwise stop the cluster working. The one
/// thing that never happens on any path is falling back to an unverified connection —
/// that would hand the same attacker a way to *disable* the check by attacking
/// availability, which is worse than not having it.
struct PinSource {
    /// `https://…` for the verifier, and the sha256 of its own TLS key. Both come from
    /// the measured trust-anchor configuration; see ClaimedRuntimeConfig.
    scan_url: String,
    scan_pubkey: String,
    /// The KMS app's id on chain, whose nodes' keys are being asked about.
    kms_app_id: String,
    cached: Vec<String>,
    /// When the cache was last refreshed, to stop a peer that keeps presenting a wrong
    /// certificate from driving unlimited traffic at the verifier.
    last_refresh: Option<std::time::Instant>,
}

/// Shortest gap between refreshes provoked by a pin mismatch.
const REFRESH_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(30);

pub struct KmsClient {
    node_urls: Vec<String>,
    http: reqwest::Client,
    max_retries: usize,
    initial_delay_ms: u64,
    max_delay_ms: u64,
    /// How long to keep retrying while the KMS reports the app as absent from the chain.
    /// Separate from the retry budget above, which is for a node being down or erroring and is
    /// deliberately short (seconds); this one waits out a cache, and the two are not the same
    /// kind of wait. See `get_encrypted_secret`.
    onchain_wait_ms: u64,
    /// `None` when no verifier is configured: the node then talks to KMS exactly as it
    /// did before, unverified. Kept possible on purpose — a tapp that has never been
    /// told which verifier to believe cannot invent one — but it is the weaker mode and
    /// says so in the logs.
    pins: Option<tokio::sync::Mutex<PinSource>>,
}

/// The KMS's view of the chain does not have what was just written yet: the app (a
/// registration), or this node's signer in it (a node replaced after a restart, or added) —
/// in the KMS's own cache or, with attested admission on, in the verifier's.
/// Distinguished from every other 4xx because it resolves on its own, given time.
#[derive(Debug, thiserror::Error)]
#[error("the KMS has not seen {what} yet")]
struct NotOnChainYet {
    what: &'static str,
}

/// Recognise the answers from the KMS that only waiting resolves. Without attested admission:
///
/// - 404 `{"error":"app not found on-chain: <id>"}` — no nodes for the app at all;
/// - 401 `{"error":"invalid signature: recovered address 0x… not in on-chain signer list for
///   app <id>"}` — the app is there, this signer is not. That is what a node meets right after
///   `updateNode` (a restart re-derives the signer) or `addNode`.
///
/// The KMS cannot tell "not visible yet" from "never registered" in either, so neither can
/// this; the deadline message says both. Matching the KMS's prose is the only signal on the
/// wire, and it is pinned in tests so a wording change on either side shows up as a failure.
///
/// With attested admission on (0g-kms#15), 403 `{"error":"attestation required: …"}` with:
///
/// - `not registered on-chain per verifier` — the KMS found the signer in its own list, but
///   the verifier has not synced the `updateNode` yet;
/// - `the TD's DEBUG attribute is not known for this result; it needs re-attesting` — the
///   verifier holds a result from before it recorded that attribute (0g-tapp-verifier#16);
/// - `attestation not verified (recently checked)` with no reason after it — the damped repeat
///   of an older KMS, which turns into the real answer within its 30s damping;
/// - `verifier unreachable`, first or damped — the scan could not answer, which since
///   0g-tapp-verifier#16 includes a failed registry read on its side. The KMS still refuses
///   until the scan verifies, so waiting admits nothing.
///
/// Every other "attestation required" reason (a DEBUG TD, an unpublished or dev image), and a
/// damped repeat that names one, is final and fails fast.
fn not_onchain_yet(body: &str) -> Option<NotOnChainYet> {
    const DAMPED: &str = "attestation not verified (recently checked)";
    let damped_bare = body
        .find(DAMPED)
        .is_some_and(|i| !body[i + DAMPED.len()..].starts_with(':'));
    let what = if body.contains("app not found on-chain") {
        "this app on-chain"
    } else if body.contains("not in on-chain signer list") {
        "this node's signer on-chain"
    } else if body.contains("not registered on-chain per verifier") || damped_bare {
        "this node's signer at the verifier"
    } else if body.contains("DEBUG attribute is not known for this result") {
        "this node's evidence re-attested by the verifier"
    } else if body.contains("verifier unreachable") {
        "a verdict from the verifier"
    } else {
        return None;
    };
    Some(NotOnChainYet { what })
}

impl KmsClient {
    pub fn new(node_urls: Vec<String>, retry: &crate::config::RetryConfig) -> Self {
        Self {
            node_urls,
            http: reqwest::Client::new(),
            max_retries: retry.max_retries,
            initial_delay_ms: retry.initial_delay_ms,
            max_delay_ms: retry.max_delay_ms,
            onchain_wait_ms: retry.onchain_wait_ms,
            pins: None,
        }
    }

    /// Verify KMS nodes against the keys `scan_url` attests for `kms_app_id`.
    pub fn with_verifier(
        mut self,
        scan_url: String,
        scan_pubkey: String,
        kms_app_id: String,
    ) -> Self {
        self.pins = Some(tokio::sync::Mutex::new(PinSource {
            scan_url,
            scan_pubkey,
            kms_app_id,
            cached: Vec::new(),
            last_refresh: None,
        }));
        self
    }

    /// The keys currently acceptable for a KMS node, refreshing from the verifier when
    /// the cache is empty or `force` is set and the cooldown has elapsed.
    ///
    /// A refresh failure with a cache in hand is a warning, not an error: the cached
    /// answer is still an attested one, merely older.
    async fn acceptable_keys(&self, force: bool) -> Result<Vec<String>> {
        let Some(pins) = &self.pins else {
            return Ok(Vec::new());
        };
        let mut p = pins.lock().await;

        let cooled = p
            .last_refresh
            .map(|t| t.elapsed() >= REFRESH_COOLDOWN)
            .unwrap_or(true);
        if p.cached.is_empty() || (force && cooled) {
            let url = format!(
                "{}/api/apps/{}/cert",
                p.scan_url.trim_end_matches('/'),
                p.kms_app_id
            );
            // Pinned to the verifier's own attested key. Without this the whole exercise
            // is circular: an attacker on this hop rewrites the very set that is supposed
            // to catch him.
            match pinned_client(std::iter::once(p.scan_pubkey.clone()))
            {
                Ok(c) => match c.get(&url).send().await {
                    Ok(resp) if resp.status().is_success() => match resp.text().await {
                        Ok(body) => {
                            let keys = parse_pin_list(&body);
                            if keys.is_empty() {
                                tracing::warn!(url = %url, "verifier returned no attested keys");
                            } else {
                                p.cached = keys;
                            }
                            p.last_refresh = Some(std::time::Instant::now());
                        }
                        Err(e) => tracing::warn!(url = %url, error = %e, "verifier body unreadable"),
                    },
                    Ok(resp) => {
                        tracing::warn!(url = %url, status = %resp.status(), "verifier refused");
                        p.last_refresh = Some(std::time::Instant::now());
                    }
                    Err(e) => tracing::warn!(url = %url, error = %e, "verifier unreachable"),
                },
                Err(e) => tracing::warn!(error = %e, "cannot build pinned client for verifier"),
            }
        }

        if p.cached.is_empty() {
            // No cache and no answer. Refusing is the point: proceeding unverified is
            // exactly the downgrade this exists to prevent.
            return Err(anyhow!(
                "no attested TLS keys for KMS app '{}' — the verifier at {} could not be \
                 reached and nothing is cached. Refusing to connect unverified.",
                p.kms_app_id,
                p.scan_url
            ));
        }
        Ok(p.cached.clone())
    }

    /// The HTTP client to use for KMS, pinned when a verifier is configured.
    async fn client_for(&self, force_refresh: bool) -> Result<reqwest::Client> {
        if self.pins.is_none() {
            return Ok(self.http.clone());
        }
        let keys = self.acceptable_keys(force_refresh).await?;
        pinned_client(keys)
    }

    /// Fetch key material, waiting out the window in which the KMS has not yet seen a
    /// just-landed on-chain registration, replacement or addition.
    ///
    /// The KMS authorises from the chain and caches that view for about 30 seconds, so an app
    /// registered moments ago is genuinely on-chain and genuinely absent from the KMS's answer.
    /// `start-app --register-onchain` registers and starts in one command, which lands squarely
    /// inside that window: the first volume-key fetch fails, and the error it used to produce
    /// asked whether the caller had registered the app -- which they had, seconds earlier.
    ///
    /// So the wait belongs here rather than in each caller. Every other failure is passed
    /// through untouched and still fails as fast as it did before.
    pub async fn get_encrypted_secret(
        &self,
        app_id: &str,
        timestamp: i64,
        pubkey_hex: &str,
        signature_hex: &str,
        material: &str,
    ) -> Result<Vec<u8>> {
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_millis(self.onchain_wait_ms);
        let mut delay = std::time::Duration::from_secs(5);
        loop {
            match self
                .get_encrypted_secret_once(app_id, timestamp, pubkey_hex, signature_hex, material)
                .await
            {
                Ok(v) => return Ok(v),
                Err(e) if e.downcast_ref::<NotOnChainYet>().is_some() => {
                    let what = e.downcast_ref::<NotOnChainYet>().map(|n| n.what).unwrap_or("this app on-chain");
                    let left = deadline.saturating_duration_since(std::time::Instant::now());
                    if left.is_zero() {
                        // Say what is actually known: the KMS did not see it for the whole
                        // window. Whether it is registered at all is the caller's next
                        // question, and the old message answered it for them, wrongly.
                        return Err(anyhow!(
                            "the KMS did not see {} for '{}' within {}s. If it was \
                             registered or replaced just now, the change may still be \
                             propagating — retry. If it never was, register it first \
                             (start-app --register-onchain).",
                            what,
                            app_id,
                            self.onchain_wait_ms / 1000
                        ));
                    }
                    let nap = delay.min(left);
                    tracing::info!(
                        app_id,
                        wait_s = nap.as_secs(),
                        remaining_s = left.as_secs(),
                        what,
                        "the KMS cannot vouch for this node yet (its view of the chain, or the verifier, lags); waiting"
                    );
                    tokio::time::sleep(nap).await;
                    delay = (delay * 2).min(std::time::Duration::from_secs(30));
                }
                Err(e) => return Err(e),
            }
        }
    }

    async fn get_encrypted_secret_once(
        &self,
        app_id: &str,
        timestamp: i64,
        pubkey_hex: &str,
        signature_hex: &str,
        material: &str,
    ) -> Result<Vec<u8>> {
        let req = KmsRequest {
            app_id,
            timestamp,
            pubkey: pubkey_hex.to_string(),
            signature: signature_hex.to_string(),
            material,
        };

        let mut last_err = anyhow!("no KMS nodes configured");
        for url in &self.node_urls {
            let endpoint = format!("{}/app-key", url.trim_end_matches('/'));

            // A client that will speak only to a node holding one of the attested keys.
            // Built per node rather than once, so a refresh below takes effect here and
            // does not have to wait for the next call.
            let mut client = match self.client_for(false).await {
                Ok(c) => c,
                Err(e) => {
                    // Nothing attested and nothing cached: this is not "that node is
                    // down", and saying so plainly is the difference between an operator
                    // checking the KMS and checking the verifier.
                    last_err = e;
                    break;
                }
            };
            let mut refreshed = false;

            let mut attempt = 0usize;
            loop {
                match client.post(&endpoint).json(&req).send().await {
                    Ok(resp) if resp.status().is_success() => {
                        let body: KmsResponse = resp.json().await
                            .map_err(|e| anyhow!("KMS {} invalid response: {}", url, e))?;
                        let bytes = hex::decode(body.encrypted_secret.trim_start_matches("0x"))
                            .map_err(|e| anyhow!("KMS {} invalid hex: {}", url, e))?;
                        return Ok(bytes);
                    }
                    Ok(resp) => {
                        let status = resp.status();
                        let body = resp.text().await.unwrap_or_default();
                        last_err = anyhow!("KMS {} returned {}: {}", url, status, body);
                        // "not on-chain yet" is the one 4xx that DOES change on its own, so it
                        // must not be swallowed by the rule below. The KMS decides authorisation
                        // from the chain and caches that view for ~30s, so for a window after a
                        // registration lands it answers 404 for an app that is genuinely
                        // registered. Signalled up to the caller, which waits and retries the
                        // whole request -- retrying this node would be pointless, since every
                        // node reads the same chain and will answer the same way.
                        if let Some(not_yet) = not_onchain_yet(&body) {
                            tracing::warn!(url = %url, "{}", not_yet);
                            return Err(not_yet.into());
                        }
                        // Don't retry on client errors (4xx) — request won't change
                        if status.is_client_error() {
                            tracing::warn!(url = %url, %status, "KMS client error, skipping node");
                            break;
                        }
                        tracing::warn!(url = %url, %status, attempt, "KMS server error, retrying");
                    }
                    // A pin failure is not "unreachable" and must not read as one: the
                    // node answered, and what it presented is not a key this app's
                    // attestation vouches for.
                    Err(e) if is_pin_failure(&e) => {
                        last_err = anyhow!(
                            "KMS {} presented a TLS key that is not attested for this cluster: {}",
                            url,
                            root_cause(&e)
                        );
                        if refreshed {
                            tracing::warn!(
                                url = %url, event = "KMS_PIN_REJECTED",
                                "Refused after refreshing the attested keys — skipping node"
                            );
                            break;
                        }
                        // Most likely the node rebooted and re-derived its key, which a
                        // `local` key does every boot. Ask the verifier once for a newer
                        // set before concluding anything worse.
                        tracing::warn!(
                            url = %url, event = "KMS_PIN_MISMATCH",
                            "TLS key not among the attested set; refreshing from the verifier"
                        );
                        refreshed = true;
                        match self.client_for(true).await {
                            Ok(c) => {
                                client = c;
                                continue; // retry this node immediately, without backoff
                            }
                            Err(e) => {
                                last_err = e;
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        last_err = anyhow!("KMS {} unreachable: {}", url, e);
                        tracing::warn!(url = %url, error = %e, attempt, "KMS unreachable, retrying");
                    }
                }
                attempt += 1;
                if attempt > self.max_retries {
                    break;
                }
                let delay = (self.initial_delay_ms * (1u64 << (attempt - 1))).min(self.max_delay_ms);
                tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
            }
        }
        Err(last_err)
    }
}
