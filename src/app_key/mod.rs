use crate::error::{DockerError, TappResult};
use k256::ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey};
use sha3::{Digest, Keccak256};
use std::collections::HashMap;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

/// Ethereum key pair
#[derive(Clone)]
pub struct EthKeyPair {
    pub private_key: Vec<u8>, // 32-byte private key (can be used to reconstruct SigningKey)
    pub public_key: Vec<u8>,  // 64-byte uncompressed public key (without 0x04 prefix)
    pub eth_address: Vec<u8>, // 20-byte Ethereum address
    pub x25519_public_key: Option<Vec<u8>>, // 32-byte X25519 public key
}

/// Application key service — always uses in-memory key generation.
/// Keys are derived per app_id and persist for the lifetime of the process.
/// KBS/KMS secret retrieval is handled separately via kms_client.
pub struct AppKeyService {
    /// In-memory key storage: app_id -> EthKeyPair
    app_keys: Mutex<HashMap<String, EthKeyPair>>,
}

impl AppKeyService {
    pub fn new() -> Self {
        info!("Initialized app key service (in-memory)");
        Self {
            app_keys: Mutex::new(HashMap::new()),
        }
    }

    /// Generate a new Ethereum key pair for an app
    fn generate_eth_keypair(x25519: bool) -> TappResult<EthKeyPair> {
        use k256::elliptic_curve::rand_core::OsRng;

        let signing_key = SigningKey::random(&mut OsRng);
        let private_key = signing_key.to_bytes().to_vec();
        let verifying_key = signing_key.verifying_key();

        // Get uncompressed public key
        let public_key_point = verifying_key.to_encoded_point(false);
        let public_key_bytes = public_key_point.as_bytes();

        // Remove the 0x04 prefix to get 64 bytes for address calculation
        let public_key_without_prefix = &public_key_bytes[1..];

        // Store 64-byte public key (without 0x04 prefix), consistent with verify_signature()
        let public_key = public_key_without_prefix.to_vec();

        // Generate x25519 key pair if requested
        // Compatible with eciesjs: directly use secp256k1 private key as x25519 private key
        let x25519_public_key = if x25519 {
            // Convert secp256k1 private key to x25519 private key
            // eciesjs uses the same 32-byte private key for both secp256k1 and x25519
            let mut x25519_private_bytes = [0u8; 32];
            x25519_private_bytes.copy_from_slice(&private_key[..32]);

            // Create x25519 secret from the same private key
            let x25519_secret = x25519_dalek::StaticSecret::from(x25519_private_bytes);

            // Derive x25519 public key
            let x25519_public = x25519_dalek::PublicKey::from(&x25519_secret);

            Some(x25519_public.as_bytes().to_vec())
        } else {
            None
        };

        // Calculate Ethereum address from 64-byte public key (without prefix)
        let mut hasher = Keccak256::new();
        hasher.update(public_key_without_prefix);
        let hash = hasher.finalize();
        let eth_address = hash[12..].to_vec(); // Last 20 bytes

        Ok(EthKeyPair {
            private_key,
            public_key,
            eth_address,
            x25519_public_key,
        })
    }

    /// Get or create key for an app (in-memory mode)
    async fn get_or_create_in_memory_key(
        &self,
        app_id: &str,
        x25519: bool,
    ) -> TappResult<EthKeyPair> {
        let mut keys = self.app_keys.lock().await;

        if let Some(key_pair) = keys.get(app_id) {
            debug!(app_id = %app_id, "Using existing in-memory key");
            return Ok(key_pair.clone());
        }

        // Generate new key
        info!(
            app_id = %app_id,
            x25519_enabled = x25519,
            "Generating new in-memory key"
        );
        let key_pair = Self::generate_eth_keypair(x25519)?;

        // Store it
        keys.insert(app_id.to_string(), key_pair.clone());

        Ok(key_pair)
    }

    /// Get private key for an app (local access only)
    /// WARNING: Returns sensitive private key material
    pub async fn get_private_key(&self, app_id: &str) -> TappResult<Vec<u8>> {
        let keys = self.app_keys.lock().await;
        if let Some(key_pair) = keys.get(app_id) {
            warn!(
                app_id = %app_id,
                "Private key retrieved - ensure this is for local access only"
            );
            Ok(key_pair.private_key.clone())
        } else {
            Err(DockerError::ServiceNotFound {
                service_name: format!("Key for app_id: {}", app_id),
            }
            .into())
        }
    }

    /// Get public key for an app
    pub async fn get_public_key(
        &self,
        app_id: &str,
    ) -> TappResult<(Vec<u8>, Vec<u8>, Option<Vec<u8>>)> {
        let keys = self.app_keys.lock().await;
        if let Some(key_pair) = keys.get(app_id) {
            Ok((
                key_pair.eth_address.clone(),
                key_pair.public_key.clone(),
                key_pair.x25519_public_key.clone(),
            ))
        } else {
            Err(DockerError::ServiceNotFound {
                service_name: format!("Key for app_id: {}", app_id),
            }
            .into())
        }
    }

    /// Get app key pair (always in-memory)
    pub async fn get_app_key(
        &self,
        app_id: &str,
        key_type: &str,
        x25519: bool,
    ) -> TappResult<EthKeyPair> {
        info!(app_id = %app_id, key_type = %key_type, "Processing app key request");

        match key_type {
            "ethereum" => {
                let key_pair = self.get_or_create_in_memory_key(app_id, x25519).await?;
                info!(
                    app_id = %app_id,
                    eth_address = format!("0x{}", hex::encode(&key_pair.eth_address)),
                    "Returning in-memory key"
                );
                Ok(key_pair)
            }
            _ => {
                warn!(key_type = %key_type, "Unsupported key type");
                Err(DockerError::ContainerOperationFailed {
                    operation: "get_app_key".to_string(),
                    reason: format!("Unsupported key type: {}", key_type),
                }
                .into())
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
        let key_pair = AppKeyService::generate_eth_keypair(true).unwrap();

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
