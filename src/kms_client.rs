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
            .get_encrypted_secret("myapp", 1234567890, "pubkey_hex", "sig_hex")
            .await
            .unwrap();

        assert_eq!(result, vec![0xde, 0xad, 0xbe, 0xef]);
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
            .get_encrypted_secret("myapp", 1234567890, "pubkey_hex", "sig_hex")
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
            .get_encrypted_secret("myapp", 1234567890, "pubkey_hex", "sig_hex")
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_no_nodes_configured() {
        let client = KmsClient::new(vec![], &Default::default());
        let result = client
            .get_encrypted_secret("myapp", 1234567890, "pubkey_hex", "sig_hex")
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
}

#[derive(Deserialize)]
struct KmsResponse {
    encrypted_secret: String, // hex-encoded ECIES ciphertext
}

pub struct KmsClient {
    node_urls: Vec<String>,
    http: reqwest::Client,
    max_retries: usize,
    initial_delay_ms: u64,
    max_delay_ms: u64,
}

impl KmsClient {
    pub fn new(node_urls: Vec<String>, retry: &crate::config::RetryConfig) -> Self {
        Self {
            node_urls,
            http: reqwest::Client::new(),
            max_retries: retry.max_retries,
            initial_delay_ms: retry.initial_delay_ms,
            max_delay_ms: retry.max_delay_ms,
        }
    }

    /// Request the encrypted secret from the KMS cluster.
    /// Tries each node in order and returns on the first success.
    pub async fn get_encrypted_secret(
        &self,
        app_id: &str,
        timestamp: i64,
        pubkey_hex: &str,
        signature_hex: &str,
    ) -> Result<Vec<u8>> {
        let req = KmsRequest {
            app_id,
            timestamp,
            pubkey: pubkey_hex.to_string(),
            signature: signature_hex.to_string(),
        };

        let mut last_err = anyhow!("no KMS nodes configured");
        for url in &self.node_urls {
            let endpoint = format!("{}/app-key", url.trim_end_matches('/'));
            let mut attempt = 0usize;
            loop {
                match self.http.post(&endpoint).json(&req).send().await {
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
