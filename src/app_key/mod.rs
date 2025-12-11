pub mod kbs_client;
pub use kbs_client::KbsClient;

use crate::config::KbsConfig;
use crate::error::{DockerError, TappResult};
use crate::proto::GetAppKeyResponse;
use k256::ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use sha3::{Digest, Keccak256};
use std::collections::HashMap;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

/// Ethereum key pair
#[derive(Clone)]
struct EthKeyPair {
    private_key: Vec<u8>, // 32-byte private key (can be used to reconstruct SigningKey)
    public_key: Vec<u8>,  // 64-byte uncompressed public key (without 0x04 prefix)
    eth_address: Vec<u8>, // 20-byte Ethereum address
}

/// Application key service implementation
pub struct AppKeyService {
    kbs_client: KbsClient,
    /// In-memory key storage: app_id -> EthKeyPair
    app_keys: Mutex<HashMap<String, EthKeyPair>>,
    /// Whether to use in-memory keys (if false, use KBS)
    use_in_memory: bool,
}

impl AppKeyService {
    /// Create new app key service
    pub async fn new(config: &KbsConfig, use_in_memory: bool) -> TappResult<Self> {
        let kbs_client = KbsClient::new(&config.endpoint).await?;

        info!(
            use_in_memory = use_in_memory,
            kbs_endpoint = %config.endpoint,
            "Initialized app key service"
        );

        Ok(Self {
            kbs_client,
            app_keys: Mutex::new(HashMap::new()),
            use_in_memory,
        })
    }

    /// Generate a new Ethereum key pair for an app
    fn generate_eth_keypair(app_id: &str) -> TappResult<EthKeyPair> {
        use k256::elliptic_curve::rand_core::OsRng;

        let signing_key = SigningKey::random(&mut OsRng);
        let private_key = signing_key.to_bytes().to_vec();
        let verifying_key = signing_key.verifying_key();

        // Get uncompressed public key
        let public_key_point = verifying_key.to_encoded_point(false);
        let public_key_bytes = public_key_point.as_bytes();

        // Remove the 0x04 prefix to get 64 bytes for address calculation
        let public_key_without_prefix = &public_key_bytes[1..];

        // Store complete public key (with prefix) if needed
        let public_key = public_key_bytes.to_vec();

        // Calculate Ethereum address from 64-byte public key (without prefix)
        let mut hasher = Keccak256::new();
        hasher.update(public_key_without_prefix);
        let hash = hasher.finalize();
        let eth_address = hash[12..].to_vec(); // Last 20 bytes

        debug!(
            app_id = %app_id,
            public_key_hex = %hex::encode(&public_key),
            eth_address_hex = %format!("0x{}", hex::encode(&eth_address)),
            "Generated new Ethereum key pair"
        );

        Ok(EthKeyPair {
            private_key,
            public_key,
            eth_address,
        })
    }

    /// Get or create key for an app (in-memory mode)
    async fn get_or_create_in_memory_key(&self, app_id: &str) -> TappResult<EthKeyPair> {
        let mut keys = self.app_keys.lock().await;

        if let Some(key_pair) = keys.get(app_id) {
            debug!(app_id = %app_id, "Using existing in-memory key");
            return Ok(key_pair.clone());
        }

        // Generate new key
        info!(app_id = %app_id, "Generating new in-memory key");
        let key_pair = Self::generate_eth_keypair(app_id)?;

        // Store it
        keys.insert(app_id.to_string(), key_pair.clone());

        Ok(key_pair)
    }

    /// Get private key for an app (internal use only - for CLI)
    /// WARNING: This returns sensitive private key material
    pub async fn get_private_key(&self, app_id: &str) -> TappResult<Vec<u8>> {
        if !self.use_in_memory {
            return Err(DockerError::ContainerOperationFailed {
                operation: "get_private_key".to_string(),
                reason: "Private key retrieval only supported in in-memory mode".to_string(),
            }
            .into());
        }

        let keys = self.app_keys.lock().await;
        if let Some(key_pair) = keys.get(app_id) {
            warn!(
                app_id = %app_id,
                "Private key retrieved - ensure this is for authorized CLI access only"
            );
            Ok(key_pair.private_key.clone())
        } else {
            Err(DockerError::ServiceNotFound {
                service_name: format!("Key for app_id: {}", app_id),
            }
            .into())
        }
    }

    /// Handle get app key request (public key only - for gRPC)
    pub async fn get_app_key(&self, app_id: &str, key_type: &str) -> TappResult<GetAppKeyResponse> {
        info!(
            app_id = %app_id,
            key_type = %key_type,
            use_in_memory = self.use_in_memory,
            "Processing app key request"
        );

        if self.use_in_memory {
            // Use in-memory key generation
            match key_type {
                "ethereum" => {
                    let key_pair = self.get_or_create_in_memory_key(app_id).await?;

                    Ok(GetAppKeyResponse {
                        success: true,
                        message: format!("In-memory Ethereum key for app {}", app_id),
                        public_key: key_pair.public_key.clone(),
                        eth_address: key_pair.eth_address.clone(),
                        key_source: "in-memory".to_string(),
                    })
                }
                _ => {
                    warn!(key_type = %key_type, "Unsupported key type for in-memory mode");
                    Err(DockerError::ContainerOperationFailed {
                        operation: "get_app_key".to_string(),
                        reason: format!("Unsupported key type: {}", key_type),
                    }
                    .into())
                }
            }
        } else {
            // Use KBS
            let resource_uri = format!("kbs:///default/key/{}", app_id);
            match self.kbs_client.get_resource(&resource_uri).await {
                Ok(key_data) => Ok(GetAppKeyResponse {
                    success: true,
                    message: format!("Key from KBS for app {}", app_id),
                    public_key: key_data,
                    eth_address: vec![],
                    key_source: "kbs".to_string(),
                }),
                Err(e) => {
                    tracing::error!(
                        app_id = %app_id,
                        error = %e,
                        "Failed to retrieve app key from KBS"
                    );
                    Err(e)
                }
            }
        }
    }
}

/// Sign a message using a private key
pub fn sign_message(private_key: &[u8], message: &[u8]) -> TappResult<Vec<u8>> {
    if private_key.len() != 32 {
        return Err(DockerError::ContainerOperationFailed {
            operation: "sign_message".to_string(),
            reason: format!("Private key must be 32 bytes, got {}", private_key.len()),
        }
        .into());
    }

    let signing_key =
        SigningKey::from_slice(private_key).map_err(|e| DockerError::ContainerOperationFailed {
            operation: "sign_message".to_string(),
            reason: format!("Invalid private key: {}", e),
        })?;

    let signature: Signature = signing_key.sign(message);
    Ok(signature.to_bytes().to_vec())
}

/// Verify a signature using a public key
pub fn verify_signature(public_key: &[u8], message: &[u8], signature: &[u8]) -> TappResult<bool> {
    if public_key.len() != 64 {
        return Err(DockerError::ContainerOperationFailed {
            operation: "verify_signature".to_string(),
            reason: format!("Public key must be 64 bytes, got {}", public_key.len()),
        }
        .into());
    }

    // Add 0x04 prefix for uncompressed public key
    let public_key_with_prefix = [&[0x04u8], &public_key[..]].concat();

    let verifying_key = VerifyingKey::from_sec1_bytes(&public_key_with_prefix).map_err(|e| {
        DockerError::ContainerOperationFailed {
            operation: "verify_signature".to_string(),
            reason: format!("Invalid public key: {}", e),
        }
    })?;

    let sig =
        Signature::from_slice(signature).map_err(|e| DockerError::ContainerOperationFailed {
            operation: "verify_signature".to_string(),
            reason: format!("Invalid signature: {}", e),
        })?;

    match verifying_key.verify(message, &sig) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        // Generate a test key pair
        let key_pair = AppKeyService::generate_eth_keypair("test-app").unwrap();

        // Test message
        let message = b"Hello, TAPP!";

        // Sign the message
        let signature = sign_message(&key_pair.private_key, message).unwrap();

        // Verify the signature
        let is_valid = verify_signature(&key_pair.public_key, message, &signature).unwrap();
        assert!(is_valid);

        // Verify with wrong message should fail
        let wrong_message = b"Wrong message";
        let is_valid = verify_signature(&key_pair.public_key, wrong_message, &signature).unwrap();
        assert!(!is_valid);
    }
}
