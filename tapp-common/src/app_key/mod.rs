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

/// Application key service.
///
/// One **common signer** is generated randomly at startup (so it rotates with
/// every boot, like everything TEE-derived here), and every app signer is
/// DERIVED from it: `keccak("tapp-app-signer-v1" || common_priv || app_id)`.
/// The common signer is the node's own identity — it exists before any app
/// does, it is what `GetEvidence` attests when no app_id is given, and the
/// daemon's TLS listener key derives from it, which is what lets a client pin
/// the management channel against attested evidence instead of trusting the
/// network. The empty app_id resolves to the common signer everywhere.
/// KBS/KMS secret retrieval is handled separately via kms_client.
pub struct AppKeyService {
    /// The node's common key pair, fixed for the process lifetime.
    common: EthKeyPair,
    /// Derived-key cache: app_id -> EthKeyPair
    app_keys: Mutex<HashMap<String, EthKeyPair>>,
}

impl AppKeyService {
    pub fn new() -> Self {
        let common = Self::generate_eth_keypair(true)
            .expect("OS randomness must be available to generate the common signer");
        info!(
            common_signer = %format!("0x{}", hex::encode(&common.eth_address)),
            "Initialized app key service (common signer generated; app keys derive from it)"
        );
        Self {
            common,
            app_keys: Mutex::new(HashMap::new()),
        }
    }

    /// The node's common key pair. Public counterpart of every derived app key.
    pub fn common_key(&self) -> &EthKeyPair {
        &self.common
    }

    /// Generate a fresh random Ethereum key pair (used only for the common signer).
    fn generate_eth_keypair(x25519: bool) -> TappResult<EthKeyPair> {
        use k256::elliptic_curve::rand_core::OsRng;
        let signing_key = SigningKey::random(&mut OsRng);
        Self::keypair_from_signing_key(signing_key, x25519)
    }

    /// Deterministically derive an app's key pair from the common signer.
    /// Domain-separated and one-way: the app key says nothing about the common
    /// key, and distinct app_ids can never collide. The counter handles the
    /// astronomically unlikely hash-not-a-valid-scalar case.
    fn derive_eth_keypair(&self, app_id: &str, x25519: bool) -> TappResult<EthKeyPair> {
        for counter in 0u8..=255 {
            let mut hasher = Keccak256::new();
            hasher.update(b"tapp-app-signer-v1");
            hasher.update(&self.common.private_key);
            hasher.update(app_id.as_bytes());
            hasher.update([counter]);
            let candidate = hasher.finalize();
            if let Ok(signing_key) = SigningKey::from_slice(&candidate) {
                return Self::keypair_from_signing_key(signing_key, x25519);
            }
        }
        Err(DockerError::ContainerOperationFailed {
            operation: "derive_app_key".to_string(),
            reason: "no valid scalar in 256 attempts (statistically impossible)".to_string(),
        }
        .into())
    }

    fn keypair_from_signing_key(signing_key: SigningKey, x25519: bool) -> TappResult<EthKeyPair> {
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
        // The empty app_id IS the common signer — the node's own identity,
        // available before any app exists.
        if app_id.is_empty() {
            return Ok(self.common.clone());
        }
        let mut keys = self.app_keys.lock().await;

        if let Some(key_pair) = keys.get(app_id) {
            debug!(app_id = %app_id, "Using existing in-memory key");
            return Ok(key_pair.clone());
        }

        info!(
            app_id = %app_id,
            x25519_enabled = x25519,
            "Deriving app key from the common signer"
        );
        let key_pair = self.derive_eth_keypair(app_id, x25519)?;

        // Cache it (derivation is deterministic; the cache is an optimization)
        keys.insert(app_id.to_string(), key_pair.clone());

        Ok(key_pair)
    }

    /// Get private key for an app (local access only)
    /// WARNING: Returns sensitive private key material
    pub async fn get_private_key(&self, app_id: &str) -> TappResult<Vec<u8>> {
        if app_id.is_empty() {
            return Ok(self.common.private_key.clone());
        }
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
        if app_id.is_empty() {
            let c = &self.common;
            return Ok((c.eth_address.clone(), c.public_key.clone(), c.x25519_public_key.clone()));
        }
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

/// Sign a message using EIP-191 `personal_sign` format.
/// Wraps the message with `"\x19Ethereum Signed Message:\n{len}"`, hashes with
/// Keccak-256, and returns a 65-byte signature `r || s || v` where v is 0 or 1.
pub fn sign_message_eip191(private_key: &[u8], message: &[u8]) -> TappResult<Vec<u8>> {
    if private_key.len() != 32 {
        return Err(DockerError::ContainerOperationFailed {
            operation: "sign_message_eip191".to_string(),
            reason: format!("Private key must be 32 bytes, got {}", private_key.len()),
        }
        .into());
    }

    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut prefixed = Vec::with_capacity(prefix.len() + message.len());
    prefixed.extend_from_slice(prefix.as_bytes());
    prefixed.extend_from_slice(message);
    let hash = Keccak256::digest(&prefixed);

    let signing_key =
        SigningKey::from_slice(private_key).map_err(|e| DockerError::ContainerOperationFailed {
            operation: "sign_message_eip191".to_string(),
            reason: format!("Invalid private key: {}", e),
        })?;

    let (sig, rid) = signing_key.sign_prehash_recoverable(&hash).map_err(|e| {
        DockerError::ContainerOperationFailed {
            operation: "sign_message_eip191".to_string(),
            reason: format!("Sign failed: {}", e),
        }
    })?;

    let mut out = sig.to_bytes().to_vec();
    out.push(rid.to_byte());
    Ok(out)
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
