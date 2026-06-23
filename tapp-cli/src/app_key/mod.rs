// Minimal app_key module: only sign/verify functions needed by tapp-cli.
// Stripped of Docker, KBS, X25519, and in-memory key storage.

use crate::error::{DockerError, TappResult};
use k256::ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey};
use sha3::{Digest, Keccak256};

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
