//! Algorithm-specific identities beside algorithm-neutral KMS commitments.
//! These descriptions are computed by tapp from actual keys, never caller supplied.
use p256::pkcs8::EncodePublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const COMMITMENT_SCHEME: &str = "poseidon-bn254-4-v1";
pub const APP_SIGNER_MATERIAL: &str = "70726f7669646572";
pub const TLS_MATERIAL: &str = "746c73";
pub const RAW_SCALAR: &str = "raw-scalar-v1";
pub const LOCAL_TLS_DERIVATION: &str = "tapp-tls-v1-sha256";

// Fields remain alphabetical: RuntimeData is canonical JSON hashed as exact bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyCommitment {
    pub commitment: String,
    pub material: String,
    pub scheme: String,
}
impl KeyCommitment {
    pub fn problem(&self) -> Option<&'static str> {
        if self.scheme != COMMITMENT_SCHEME {
            return Some("unsupported commitment scheme");
        }
        if !canonical_hex(&self.material, None) || self.material.len() > 512 {
            return Some("invalid material");
        }
        let Some(c) = self.commitment.strip_prefix("0x") else {
            return Some("invalid commitment encoding");
        };
        if !canonical_hex(c, Some(32)) {
            return Some("invalid commitment encoding");
        }
        // BN254 scalar field modulus; reject encodings that would silently reduce.
        if c >= "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001" {
            return Some("noncanonical commitment field element");
        }
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyIdentity {
    pub algorithm: String,
    pub derivation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_ref: Option<KeyCommitment>,
    pub key_source: String,
    pub public_key: String,
    pub public_key_encoding: String,
    pub role: String,
}
impl KeyIdentity {
    pub fn problem(&self) -> Option<&'static str> {
        if self.public_key_encoding != "sec1-compressed" {
            return Some("unsupported public key encoding");
        }
        let Some(raw) = self.public_key.strip_prefix("0x") else {
            return Some("invalid public key encoding");
        };
        if !canonical_hex(raw, Some(33)) {
            return Some("invalid public key encoding");
        }
        let bytes = hex::decode(raw).ok()?;
        let valid = match self.algorithm.as_str() {
            "ecdsa-secp256k1" => k256::PublicKey::from_sec1_bytes(&bytes).is_ok(),
            "ecdsa-p256" => p256::PublicKey::from_sec1_bytes(&bytes).is_ok(),
            _ => return Some("unsupported identity algorithm"),
        };
        if !valid {
            return Some("invalid public key point");
        }
        match (
            self.role.as_str(),
            self.algorithm.as_str(),
            self.key_source.as_str(),
        ) {
            ("node_signer", "ecdsa-secp256k1", "local") => {
                if !matches!(
                    self.derivation.as_str(),
                    "node-native-v1" | "tapp-app-signer-v1"
                ) || self.key_ref.is_some()
                {
                    return Some("invalid node identity provenance");
                }
            }
            ("tls", "ecdsa-p256", "local") => {
                if self.derivation != LOCAL_TLS_DERIVATION || self.key_ref.is_some() {
                    return Some("invalid local TLS provenance");
                }
            }
            ("app_signer", "ecdsa-secp256k1", "kms") | ("tls", "ecdsa-p256", "kms") => {
                if self.derivation != RAW_SCALAR {
                    return Some("unsupported KMS identity derivation");
                }
                let Some(r) = &self.key_ref else {
                    return Some("KMS identity has no commitment");
                };
                if let Some(p) = r.problem() {
                    return Some(p);
                }
                let material = if self.role == "app_signer" {
                    APP_SIGNER_MATERIAL
                } else {
                    TLS_MATERIAL
                };
                if r.material != material {
                    return Some("identity uses the wrong purpose material");
                }
            }
            _ => return Some("unsupported identity role or source"),
        }
        None
    }
    pub fn ethereum_address(&self) -> Option<String> {
        if self.algorithm != "ecdsa-secp256k1" {
            return None;
        }
        let raw = hex::decode(self.public_key.strip_prefix("0x")?).ok()?;
        crate::app_key::eth_address_of_public_key(&raw).map(|a| format!("0x{}", hex::encode(a)))
    }
    /// Legacy TLS field: 0x-prefixed SHA-256 of the P-256 SubjectPublicKeyInfo.
    pub fn tls_spki_hash(&self) -> Option<String> {
        if self.algorithm != "ecdsa-p256" {
            return None;
        }
        let raw = hex::decode(self.public_key.strip_prefix("0x")?).ok()?;
        let public = p256::PublicKey::from_sec1_bytes(&raw).ok()?;
        let der = public.to_public_key_der().ok()?;
        Some(format!("0x{}", hex::encode(Sha256::digest(der.as_bytes()))))
    }
    pub fn node(public_key: &[u8], app_id: &str) -> Result<Self, String> {
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        let raw = if public_key.len() == 64 {
            [&[4u8][..], public_key].concat()
        } else {
            public_key.to_vec()
        };
        let public = k256::PublicKey::from_sec1_bytes(&raw).map_err(|_| "invalid node key")?;
        Ok(Self {
            algorithm: "ecdsa-secp256k1".into(),
            derivation: if app_id.is_empty() {
                "node-native-v1"
            } else {
                "tapp-app-signer-v1"
            }
            .into(),
            key_ref: None,
            key_source: "local".into(),
            public_key: format!(
                "0x{}",
                hex::encode(public.to_encoded_point(true).as_bytes())
            ),
            public_key_encoding: "sec1-compressed".into(),
            role: "node_signer".into(),
        })
    }
    pub fn app_signer(secret: &[u8], key_ref: KeyCommitment) -> Result<Self, String> {
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        let key = k256::SecretKey::from_slice(secret).map_err(|_| "invalid app signing scalar")?;
        Ok(Self::kms(
            "app_signer",
            "ecdsa-secp256k1",
            key.public_key().to_encoded_point(true).as_bytes(),
            key_ref,
        ))
    }
    pub fn tls(secret: &[u8], key_ref: Option<KeyCommitment>) -> Result<Self, String> {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let key = p256::SecretKey::from_slice(secret).map_err(|_| "invalid TLS scalar")?;
        Ok(Self {
            algorithm: "ecdsa-p256".into(),
            derivation: if key_ref.is_some() {
                RAW_SCALAR
            } else {
                LOCAL_TLS_DERIVATION
            }
            .into(),
            key_source: if key_ref.is_some() { "kms" } else { "local" }.into(),
            key_ref,
            public_key: format!(
                "0x{}",
                hex::encode(key.public_key().to_encoded_point(true).as_bytes())
            ),
            public_key_encoding: "sec1-compressed".into(),
            role: "tls".into(),
        })
    }
    fn kms(role: &str, algorithm: &str, public: &[u8], key_ref: KeyCommitment) -> Self {
        Self {
            algorithm: algorithm.into(),
            derivation: RAW_SCALAR.into(),
            key_ref: Some(key_ref),
            key_source: "kms".into(),
            public_key: format!("0x{}", hex::encode(public)),
            public_key_encoding: "sec1-compressed".into(),
            role: role.into(),
        }
    }
}
fn canonical_hex(s: &str, bytes: Option<usize>) -> bool {
    s.len().is_multiple_of(2)
        && bytes.is_none_or(|b| s.len() == b * 2)
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Public metadata only. Same-purpose conflicts are retained, so a verifier sees them.
#[derive(Debug, Default)]
pub struct MetadataLog {
    commitments: BTreeMap<String, BTreeMap<(String, String, String), KeyCommitment>>,
    identities: BTreeMap<String, BTreeMap<(String, String, String, String), KeyIdentity>>,
}
impl MetadataLog {
    pub fn record(
        &mut self,
        app_id: &str,
        commitment: KeyCommitment,
        identity: Option<KeyIdentity>,
    ) {
        self.commitments.entry(app_id.into()).or_default().insert(
            (
                commitment.material.clone(),
                commitment.scheme.clone(),
                commitment.commitment.clone(),
            ),
            commitment,
        );
        if let Some(id) = identity {
            self.record_identity(app_id, id);
        }
    }
    pub fn record_identity(&mut self, app_id: &str, identity: KeyIdentity) {
        let reference = identity
            .key_ref
            .as_ref()
            .map(|r| r.commitment.clone())
            .unwrap_or_default();
        self.identities.entry(app_id.into()).or_default().insert(
            (
                identity.role.clone(),
                identity.algorithm.clone(),
                identity.public_key.clone(),
                reference,
            ),
            identity,
        );
    }
    pub fn of(&self, app_id: &str) -> (Vec<KeyIdentity>, Vec<KeyCommitment>) {
        (
            self.identities
                .get(app_id)
                .map(|m| m.values().cloned().collect())
                .unwrap_or_default(),
            self.commitments
                .get(app_id)
                .map(|m| m.values().cloned().collect())
                .unwrap_or_default(),
        )
    }
    pub fn contains(
        &self,
        app_id: &str,
        commitment: &KeyCommitment,
        identity: Option<&KeyIdentity>,
    ) -> bool {
        let (ids, refs) = self.of(app_id);
        refs.contains(commitment) && identity.is_none_or(|id| ids.contains(id))
    }
    pub fn restore(cc_eventlog: &str) -> anyhow::Result<Self> {
        let mut log = Self::default();
        for event in crate::verify::eventlog_tapp_events(cc_eventlog, "get_secret_resource")? {
            if event["result"] != "success" {
                continue;
            }
            let Some(app_id) = event["app_id"].as_str().filter(|s| !s.is_empty()) else {
                continue;
            };
            let Ok(c) = serde_json::from_value::<KeyCommitment>(event["key_commitment"].clone())
            else {
                continue;
            };
            if c.problem().is_some() || event["material"].as_str() != Some(c.material.as_str()) {
                continue;
            }
            let identity = event
                .get("identity")
                .and_then(|v| serde_json::from_value::<KeyIdentity>(v.clone()).ok())
                .filter(|id| id.problem().is_none() && id.key_ref.as_ref() == Some(&c));
            log.record(app_id, c, identity);
        }
        Ok(log)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn key() -> KeyIdentity {
        let c = crate::kms::commitment("sandbox", APP_SIGNER_MATERIAL, &[1; 32]).unwrap();
        KeyIdentity::app_signer(&[1; 32], c).unwrap()
    }
    #[test]
    fn roles_are_explicit_and_mislabelled_keys_are_refused() {
        let id = key();
        assert_eq!(id.problem(), None);
        let mut bad = id.clone();
        bad.algorithm = "ecdsa-p256".into();
        assert!(bad.problem().is_some());
        bad = id.clone();
        bad.key_source = "local".into();
        assert!(bad.problem().is_some());
        bad = id.clone();
        bad.key_ref = None;
        assert!(bad.problem().is_some());
        bad = id.clone();
        bad.key_ref.as_mut().unwrap().material = TLS_MATERIAL.into();
        assert!(bad.problem().is_some());
        bad = id;
        bad.public_key = "0x00".into();
        assert!(bad.problem().is_some());
    }
    #[test]
    fn identity_public_keys_match_legacy_node_and_tls_encodings() {
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        let k = k256::SecretKey::from_slice(&[2; 32]).unwrap();
        let uncompressed = k.public_key().to_encoded_point(false);
        let node = KeyIdentity::node(&uncompressed.as_bytes()[1..], "sandbox").unwrap();
        assert_eq!(node.problem(), None);
        assert_eq!(node.key_ref, None);
        let c = crate::kms::commitment("sandbox", TLS_MATERIAL, &[3; 32]).unwrap();
        let tls = KeyIdentity::tls(&[3; 32], Some(c)).unwrap();
        let local = KeyIdentity::tls(&[3; 32], None).unwrap();
        assert_eq!(tls.problem(), None);
        assert_eq!(local.problem(), None);
        assert_eq!(tls.tls_spki_hash(), local.tls_spki_hash());
        assert!(tls.ethereum_address().is_none());
        assert_ne!(tls.public_key, node.public_key);
    }
    #[test]
    fn metadata_keeps_conflicts_and_other_apps_apart_without_secrets() {
        let a = key();
        let mut log = MetadataLog::default();
        log.record("sandbox", a.key_ref.clone().unwrap(), Some(a.clone()));
        log.record("sandbox", a.key_ref.clone().unwrap(), Some(a.clone()));
        let b = KeyIdentity::app_signer(
            &[2; 32],
            crate::kms::commitment("sandbox", APP_SIGNER_MATERIAL, &[2; 32]).unwrap(),
        )
        .unwrap();
        log.record("sandbox", b.key_ref.clone().unwrap(), Some(b));
        assert_eq!(log.of("sandbox").0.len(), 2);
        assert!(log.of("other").0.is_empty());
        let json = serde_json::to_string(&log.of("sandbox")).unwrap();
        assert!(!json.contains(&"01".repeat(32)));
    }
    #[test]
    fn commitment_field_encoding_is_not_reduced_modulo_the_field() {
        let mut c = key().key_ref.unwrap();
        c.commitment = "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001".into();
        assert!(c.problem().is_some());
        c.commitment = format!("0x{}", "00".repeat(32));
        assert!(c.problem().is_none());
    }
    fn event_log(events: &[serde_json::Value]) -> String {
        use base64::Engine;
        let mut bytes = vec![0; 28];
        bytes.extend_from_slice(&0u32.to_le_bytes());
        for event in events {
            let text = format!("tapp.0g.com get_secret_resource {event}");
            let mut data = vec![0; 4];
            data.extend_from_slice(&(text.len() as u32).to_le_bytes());
            data.extend_from_slice(text.as_bytes());
            bytes.extend_from_slice(&4u32.to_le_bytes());
            bytes.extend_from_slice(&6u32.to_le_bytes());
            bytes.extend_from_slice(&1u32.to_le_bytes());
            bytes.extend_from_slice(&0xcu16.to_le_bytes());
            bytes.extend_from_slice(&[0; 48]);
            bytes.extend_from_slice(&(data.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&data);
        }
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }
    #[test]
    fn measured_metadata_restores_without_fetching_a_secret() {
        let id = key();
        let c = id.key_ref.clone().unwrap();
        let good = serde_json::json!({"app_id":"sandbox","material":c.material,"result":"success","identity":id,"key_commitment":c});
        let mut failed = good.clone();
        failed["result"] = "failure".into();
        let mut wrong = good.clone();
        wrong["material"] = "dead".into();
        let log = MetadataLog::restore(&event_log(&[failed, wrong, good])).unwrap();
        assert_eq!(log.of("sandbox"), (vec![id], vec![c.clone()]));
        assert!(log.of("other").0.is_empty());
    }
    #[test]
    fn generic_commitment_does_not_claim_a_signing_algorithm() {
        let c = crate::kms::commitment("sandbox", "ab", &[255; 32]).unwrap();
        let e = serde_json::json!({"app_id":"sandbox","material":"ab","result":"success","key_commitment":c});
        let log = MetadataLog::restore(&event_log(&[e])).unwrap();
        assert!(log.of("sandbox").0.is_empty());
        assert_eq!(log.of("sandbox").1, vec![c]);
    }
}
