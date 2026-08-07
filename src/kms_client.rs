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

/// Read a verifier's `/cert` body into sha256 hex hashes.
///
/// The body is what `curl --pinnedpubkey` takes: `sha256//<base64>` entries separated by
/// `;`, several of them when the app's nodes hold a key each — which is the normal state
/// for a `local` key source, and the KMS cluster's only option.
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
    /// `None` when no verifier is configured: the node then talks to KMS exactly as it
    /// did before, unverified. Kept possible on purpose — a tapp that has never been
    /// told which verifier to believe cannot invent one — but it is the weaker mode and
    /// says so in the logs.
    pins: Option<tokio::sync::Mutex<PinSource>>,
}

impl KmsClient {
    pub fn new(node_urls: Vec<String>, retry: &crate::config::RetryConfig) -> Self {
        Self {
            node_urls,
            http: reqwest::Client::new(),
            max_retries: retry.max_retries,
            initial_delay_ms: retry.initial_delay_ms,
            max_delay_ms: retry.max_delay_ms,
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
            match crate::pinned_tls::client(std::iter::once(p.scan_pubkey.clone()))
                .map_err(|e| anyhow!("{}", e))
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
        crate::pinned_tls::client(keys).map_err(|e| anyhow!("{}", e))
    }

    /// Request the encrypted secret from the KMS cluster.
    /// Tries each node in order and returns on the first success.
    pub async fn get_encrypted_secret(
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
