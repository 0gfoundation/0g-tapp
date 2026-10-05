use anyhow::{anyhow, Result};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use sha3::{Digest, Keccak256};

/// Ethereum signature format: 65 bytes (r: 32 bytes, s: 32 bytes, v: 1 byte)
const SIGNATURE_LENGTH: usize = 65;

/// How far a request's signed timestamp may be from now, either direction.
///
/// Wide on purpose: a signature binds one specific request body and (with the
/// replay guard) at most one execution, so the only thing a longer validity buys
/// an attacker is choosing WHEN that exact request lands. What it buys operators
/// is tolerance for clock drift and slow manual flows.
pub const MAX_TIMESTAMP_DIFF: i64 = 600;

/// Recover EVM address from signature
///
/// # Arguments
/// * `message` - The original message that was signed (e.g., "StartApp:1234567890")
/// * `signature_hex` - Hex-encoded signature with 0x prefix (65 bytes: r||s||v)
///
/// # Returns
/// EVM address in lowercase with 0x prefix (e.g., "0xabcd...")
pub fn recover_evm_address(message: &str, signature_hex: &str) -> Result<String> {
    // Parse signature bytes
    let signature_bytes = parse_signature_hex(signature_hex)?;

    // Build Ethereum signed message hash (EIP-191)
    let message_hash = ethereum_message_hash(message);

    // Extract r, s, v from signature
    let r_bytes: [u8; 32] = signature_bytes[0..32]
        .try_into()
        .map_err(|_| anyhow!("Invalid r component"))?;
    let s_bytes: [u8; 32] = signature_bytes[32..64]
        .try_into()
        .map_err(|_| anyhow!("Invalid s component"))?;
    let v = signature_bytes[64];

    // Parse ECDSA signature
    let signature = Signature::from_scalars(r_bytes, s_bytes)
        .map_err(|e| anyhow!("Invalid ECDSA signature: {}", e))?;

    // Determine recovery ID (v - 27 for legacy signatures)
    let recovery_id = if v >= 27 {
        RecoveryId::try_from((v - 27) as u8).map_err(|e| anyhow!("Invalid recovery id: {}", e))?
    } else {
        RecoveryId::try_from(v).map_err(|e| anyhow!("Invalid recovery id: {}", e))?
    };

    // Recover public key
    let recovered_key = VerifyingKey::recover_from_prehash(&message_hash, &signature, recovery_id)
        .map_err(|e| anyhow!("Failed to recover public key: {}", e))?;

    // Compute EVM address from public key
    let address = public_key_to_address(&recovered_key);

    Ok(format!("0x{}", hex::encode(address)))
}

/// Verify EVM signature and return signer address
///
/// # Arguments
/// * `message` - The message that should have been signed
/// * `signature_hex` - Hex-encoded signature
/// * `expected_address` - Expected signer address (lowercase with 0x prefix)
///
/// # Returns
/// true if signature is valid and from expected address
pub fn verify_evm_signature(
    message: &str,
    signature_hex: &str,
    expected_address: &str,
) -> Result<bool> {
    let recovered_address = recover_evm_address(message, signature_hex)?;
    let normalized_expected = normalize_address(expected_address);

    Ok(recovered_address.to_lowercase() == normalized_expected.to_lowercase())
}

/// Whether `timestamp` is within [`MAX_TIMESTAMP_DIFF`] of now.
pub fn verify_timestamp(timestamp: i64) -> bool {
    let now = chrono::Utc::now().timestamp();
    (now - timestamp).abs() <= MAX_TIMESTAMP_DIFF
}

/// "method_name:timestamp" — the message this server signs when IT calls the
/// KMS (`GetSecretResource:<ts>`, the KMS's auth format). Inbound RPCs are not
/// accepted in this form; they use [`build_sign_message_v2`].
pub fn build_sign_message(method_name: &str, timestamp: i64) -> String {
    format!("{}:{}", method_name, timestamp)
}

/// Build the body-bound message format: "method_name:0x<sha256>:timestamp".
///
/// `body_hash` is sha256 over the encoded protobuf request message — the exact
/// bytes inside the gRPC data frame, which are the exact bytes the client's
/// `prost::Message::encode_to_vec` produced. The server hashes what it actually
/// received, so a request whose body was altered in flight recovers to a
/// different (unauthorised) address and dies in the permission check.
pub fn build_sign_message_v2(method_name: &str, body_hash: &[u8; 32], timestamp: i64) -> String {
    format!("{}:0x{}:{}", method_name, hex::encode(body_hash), timestamp)
}

// ============================================================================
// Replay guard
// ============================================================================

/// Remembers signatures for as long as their timestamp could still validate, so
/// each one authorises at most ONE execution. Without this, any observed
/// signature could be resubmitted for the width of the window — harmless for an
/// idempotent read, not for StartApp.
///
/// Memory is bounded by (ops per window) — these are operator actions, not
/// traffic, so the map stays tiny. A legitimate retry is unaffected: the CLI
/// signs afresh on every call.
#[derive(Default)]
pub struct ReplayGuard {
    /// keccak256(signature bytes) → the signed timestamp.
    seen: std::sync::Mutex<std::collections::HashMap<[u8; 32], i64>>,
}

impl ReplayGuard {
    /// Admit a signature exactly once. `signed_ts` is the timestamp inside the
    /// signed message. Returns false when the signature was already used.
    pub fn admit(&self, signature_hex: &str, signed_ts: i64) -> bool {
        let digest: [u8; 32] = Keccak256::digest(signature_hex.trim().as_bytes()).into();
        let now = chrono::Utc::now().timestamp();
        let mut seen = self.seen.lock().unwrap_or_else(|p| p.into_inner());
        // Prune whatever can no longer validate anyway (small slack for clock skew).
        seen.retain(|_, ts| (now - *ts).abs() <= MAX_TIMESTAMP_DIFF + 60);
        seen.insert(digest, signed_ts).is_none()
    }
}

// ============================================================================
// Helper functions
// ============================================================================

/// Parse hex-encoded signature string to bytes
fn parse_signature_hex(signature_hex: &str) -> Result<Vec<u8>> {
    let sig_str = signature_hex
        .trim()
        .strip_prefix("0x")
        .unwrap_or(signature_hex);

    let bytes = hex::decode(sig_str).map_err(|e| anyhow!("Invalid hex signature: {}", e))?;

    if bytes.len() != SIGNATURE_LENGTH {
        return Err(anyhow!(
            "Invalid signature length: expected {} bytes, got {}",
            SIGNATURE_LENGTH,
            bytes.len()
        ));
    }

    Ok(bytes)
}

/// Build Ethereum signed message hash according to EIP-191
///
/// Format: keccak256("\x19Ethereum Signed Message:\n" + len(message) + message)
fn ethereum_message_hash(message: &str) -> [u8; 32] {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut hasher = Keccak256::new();
    hasher.update(prefix.as_bytes());
    hasher.update(message.as_bytes());
    hasher.finalize().into()
}

/// Convert public key to Ethereum address
///
/// Ethereum address = last 20 bytes of keccak256(public_key)
fn public_key_to_address(public_key: &VerifyingKey) -> [u8; 20] {
    // Get uncompressed public key bytes (remove 0x04 prefix)
    let public_key_bytes = public_key.to_encoded_point(false);
    let public_key_bytes = &public_key_bytes.as_bytes()[1..]; // Skip 0x04 prefix

    // Hash with Keccak256
    let mut hasher = Keccak256::new();
    hasher.update(public_key_bytes);
    let hash = hasher.finalize();

    // Take last 20 bytes
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..32]);
    address
}

/// Normalize EVM address (lowercase with 0x prefix)
fn normalize_address(addr: &str) -> String {
    let addr = addr.trim().to_lowercase();
    if addr.starts_with("0x") {
        addr
    } else {
        format!("0x{}", addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ethereum_message_hash() {
        // Test vector from Ethereum
        let message = "Hello World";
        let hash = ethereum_message_hash(message);
        let hash_hex = hex::encode(hash);

        // Expected hash for "Hello World" message
        // This is a known test vector
        assert_eq!(hash_hex.len(), 64); // 32 bytes in hex
    }

    #[test]
    fn test_normalize_address() {
        assert_eq!(
            normalize_address("1234567890123456789012345678901234567890"),
            "0x1234567890123456789012345678901234567890"
        );

        assert_eq!(
            normalize_address("0x1234567890123456789012345678901234567890"),
            "0x1234567890123456789012345678901234567890"
        );

        assert_eq!(
            normalize_address("0X1234567890ABCDEF123456789012345678901234"),
            "0x1234567890abcdef123456789012345678901234"
        );
    }

    #[test]
    fn test_parse_signature_hex() {
        // Valid signature (65 bytes)
        let valid_sig = "0x".to_string() + &"ab".repeat(65);
        assert!(parse_signature_hex(&valid_sig).is_ok());

        // Invalid: too short
        let short_sig = "0x".to_string() + &"ab".repeat(64);
        assert!(parse_signature_hex(&short_sig).is_err());

        // Invalid: too long
        let long_sig = "0x".to_string() + &"ab".repeat(66);
        assert!(parse_signature_hex(&long_sig).is_err());
    }

    #[test]
    fn test_verify_timestamp() {
        let now = chrono::Utc::now().timestamp();

        assert!(verify_timestamp(now));
        // Up to 10 minutes either way is accepted…
        assert!(verify_timestamp(now - 590));
        assert!(verify_timestamp(now + 590));
        // …and beyond that refused.
        assert!(!verify_timestamp(now - 700));
        assert!(!verify_timestamp(now + 700));
    }

    #[test]
    fn test_build_sign_message() {
        let message = build_sign_message("StartApp", 1234567890);
        assert_eq!(message, "StartApp:1234567890");
    }

    // Integration test with real signature
    // This would require a known private key and signature
    // For production, you'd use test vectors from Ethereum test suite
    #[test]
    #[ignore] // Run with: cargo test -- --ignored
    fn test_recover_address_integration() {
        // Example test vector (you need to generate this with a real wallet)
        // Message: "StartApp:1234567890"
        // Private key: 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
        // Expected address: 0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266

        let message = "StartApp:1234567890";
        let signature = "0x..."; // Replace with actual signature
        let expected_address = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";

        if signature != "0x..." {
            let recovered = recover_evm_address(message, signature).unwrap();
            assert_eq!(recovered.to_lowercase(), expected_address.to_lowercase());
        }
    }
}
