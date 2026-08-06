//! What a quote's 64-byte `report_data` commits to.
//!
//! It used to be the 20-byte signer address, left-aligned and zero-padded. That made a
//! quote self-describing — you could read the signer straight out of it — but it left
//! nothing to extend with, and 20 + a 32-byte binding + a challenge already overflows
//! 64 bytes.
//!
//! So `report_data` is now `sha512` of a small JSON object that travels beside the quote
//! inside the evidence. Two consequences worth knowing:
//!
//! - **A quote alone no longer names its signer.** The structure must accompany it.
//!   Evidence has always been carried as `{quote, cc_eventlog}` JSON, so this is a third
//!   field of the same object and nothing in the system passes a bare quote.
//! - **Verifiers hash the bytes exactly as transmitted** and never re-serialise them, so
//!   there is no canonical form for the two sides to agree on and drift apart over. The
//!   `RuntimeData` struct is a convenience for reading the fields, never a re-encoder.
//!
//! `sha512` is not arbitrary: TDX `report_data` is 64 bytes and sha512 fills it exactly,
//! which is also what CoCo-AS expects when it is handed `runtime_data` and asked to check
//! the binding itself.

use crate::error::{DockerError, TappResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

/// Field name under which the hashed bytes travel inside the evidence JSON.
pub const EVIDENCE_FIELD: &str = "runtime_data";

/// Longest challenge accepted, in bytes. A caller only needs enough to be unguessable;
/// the cap exists so a request cannot inflate every quote this node produces.
pub const MAX_NONCE_LEN: usize = 64;

/// The object `report_data` is the hash of.
///
/// Empty fields are omitted rather than serialised as `""`, so evidence produced before
/// a field existed and evidence produced after it are byte-identical whenever the field
/// is unused.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeData {
    /// Caller-supplied challenge, `0x…`. Evidence is self-authenticating but undated:
    /// nothing in a quote says when it was produced, so a cached copy is indistinguishable
    /// from a fresh one. A caller that sends a random value per request can tell them
    /// apart; one that serves cached results to many readers sends nothing.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub nonce: String,

    /// The app's TEE-derived signer, `0x…`. This is the identity TappRegistry records.
    pub signer: String,

    /// sha256 of the app's TLS public key, `0x…`. Reserved — populated once apps derive a
    /// TLS key, at which point this is what lets a client tie the certificate it was
    /// handed during a handshake to a TEE running this app.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tls_public_key: String,
}

impl RuntimeData {
    pub fn new(signer_eth_address: &[u8], nonce: &[u8]) -> TappResult<Self> {
        if signer_eth_address.len() != 20 {
            return Err(DockerError::ContainerOperationFailed {
                operation: "runtime_data".to_string(),
                reason: format!(
                    "signer must be 20 bytes, got {}",
                    signer_eth_address.len()
                ),
            }
            .into());
        }
        if nonce.len() > MAX_NONCE_LEN {
            return Err(DockerError::ContainerOperationFailed {
                operation: "runtime_data".to_string(),
                reason: format!(
                    "nonce must be at most {} bytes, got {}",
                    MAX_NONCE_LEN,
                    nonce.len()
                ),
            }
            .into());
        }
        Ok(Self {
            nonce: if nonce.is_empty() {
                String::new()
            } else {
                format!("0x{}", hex::encode(nonce))
            },
            signer: format!("0x{}", hex::encode(signer_eth_address)),
            tls_public_key: String::new(),
        })
    }

    /// Serialise, and return the bytes together with the `report_data` they produce.
    /// Callers must transmit *these* bytes; re-serialising elsewhere would change them.
    pub fn seal(&self) -> TappResult<(Vec<u8>, Vec<u8>)> {
        let bytes =
            serde_json::to_vec(self).map_err(|e| DockerError::ContainerOperationFailed {
                operation: "runtime_data".to_string(),
                reason: format!("serialise: {}", e),
            })?;
        let report_data = report_data_of(&bytes);
        Ok((bytes, report_data))
    }
}

/// The `report_data` a given set of transmitted bytes commits to.
pub fn report_data_of(runtime_data: &[u8]) -> Vec<u8> {
    Sha512::digest(runtime_data).to_vec()
}

/// Hex without the `0x`, lowercase — for comparing a field against raw bytes.
pub fn strip_hex(s: &str) -> &str {
    s.strip_prefix("0x").unwrap_or(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIGNER: [u8; 20] = [0xab; 20];

    #[test]
    fn report_data_is_exactly_64_bytes_so_it_fills_the_quote_field() {
        let (_, rd) = RuntimeData::new(&SIGNER, &[]).unwrap().seal().unwrap();
        assert_eq!(rd.len(), 64);
    }

    #[test]
    fn an_absent_nonce_is_omitted_not_empty_string() {
        let (bytes, _) = RuntimeData::new(&SIGNER, &[]).unwrap().seal().unwrap();
        let s = String::from_utf8(bytes).unwrap();
        assert!(!s.contains("nonce"), "got {}", s);
        assert!(!s.contains("tls_public_key"), "got {}", s);
    }

    #[test]
    fn a_different_nonce_gives_a_different_report_data() {
        let (_, a) = RuntimeData::new(&SIGNER, b"one").unwrap().seal().unwrap();
        let (_, b) = RuntimeData::new(&SIGNER, b"two").unwrap().seal().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn the_transmitted_bytes_reproduce_the_report_data() {
        let (bytes, rd) = RuntimeData::new(&SIGNER, b"chal").unwrap().seal().unwrap();
        assert_eq!(report_data_of(&bytes), rd);
    }

    #[test]
    fn a_verifier_reads_the_fields_back_without_re_encoding() {
        let (bytes, _) = RuntimeData::new(&SIGNER, b"chal").unwrap().seal().unwrap();
        let parsed: RuntimeData = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(strip_hex(&parsed.signer), hex::encode(SIGNER));
        assert_eq!(strip_hex(&parsed.nonce), hex::encode(b"chal"));
    }

    #[test]
    fn an_oversized_nonce_is_refused_rather_than_truncated() {
        assert!(RuntimeData::new(&SIGNER, &[0u8; MAX_NONCE_LEN + 1]).is_err());
    }
}
