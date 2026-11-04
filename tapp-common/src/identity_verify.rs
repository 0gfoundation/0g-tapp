//! Validation of quote-bound typed identities. This authenticates tapp's
//! declaration, not an external ZK proof of the secret-to-public-key relation.

use crate::identity::{KeyCommitment, KeyIdentity, MetadataLog};
use serde_json::Value;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Default)]
pub struct IdentityVerification {
    pub present: bool,
    pub identities: Vec<KeyIdentity>,
    pub key_commitments: Vec<KeyCommitment>,
    pub error: Option<String>,
    /// Commitments without a successful matching event saying kms_attested=true.
    /// Includes generic secrets as well as service signer and TLS materials.
    pub unchecked: usize,
}

impl IdentityVerification {
    /// The caller must first match SHA512 of these exact bytes to report_data.
    pub(crate) fn read(bytes: &[u8], app_id: &str, signer: &str, tls: &str) -> Self {
        let value: Value = match serde_json::from_slice(bytes) {
            Ok(value) => value,
            Err(_) => return Self::default(),
        };
        if value.get("identities").is_none() && value.get("key_commitments").is_none() {
            return Self::default();
        }
        match Self::parse(&value, app_id, signer, tls) {
            Ok(out) => out,
            Err(error) => Self {
                present: true,
                error: Some(error),
                ..Self::default()
            },
        }
    }

    fn parse(value: &Value, app_id: &str, signer: &str, tls: &str) -> Result<Self, String> {
        let fail = |message: &str| Err(message.to_string());
        if value.get("app_id").and_then(Value::as_str) != Some(app_id) {
            return fail("typed identity app_id does not match the requested app");
        }
        let identities: Vec<KeyIdentity> =
            serde_json::from_value(value.get("identities").cloned().unwrap_or(Value::Null))
                .map_err(|_| "invalid typed identities".to_string())?;
        let key_commitments: Vec<KeyCommitment> =
            serde_json::from_value(value.get("key_commitments").cloned().unwrap_or(Value::Null))
                .map_err(|_| "invalid key commitments".to_string())?;
        if identities.is_empty() {
            return fail("typed node identity is missing");
        }
        let mut materials = BTreeSet::new();
        for key in &key_commitments {
            if let Some(problem) = key.problem() {
                return fail(problem);
            }
            if !materials.insert(&key.material) {
                return fail("conflicting or duplicate commitment material");
            }
        }
        let mut roles = BTreeSet::new();
        for identity in &identities {
            if let Some(problem) = identity.problem() {
                return fail(problem);
            }
            if !roles.insert(identity.role.as_str()) {
                return fail("conflicting or duplicate identity role");
            }
            if identity
                .key_ref
                .as_ref()
                .is_some_and(|reference| !key_commitments.contains(reference))
            {
                return fail("identity key_ref is not in runtime_data.key_commitments");
            }
            if identity.role == "node_signer" {
                let expected = if app_id.is_empty() {
                    "node-native-v1"
                } else {
                    "tapp-app-signer-v1"
                };
                if identity.derivation != expected
                    || !identity
                        .ethereum_address()
                        .is_some_and(|address| address.eq_ignore_ascii_case(signer))
                {
                    return fail("typed node public key does not match legacy quote signer");
                }
            }
            if identity.role == "tls"
                && !identity
                    .tls_spki_hash()
                    .is_some_and(|hash| hash.eq_ignore_ascii_case(tls))
            {
                return fail("typed TLS key does not match legacy SPKI fingerprint");
            }
        }
        if !roles.contains("node_signer") || (!tls.is_empty() && !roles.contains("tls")) {
            return fail("node or TLS typed identity is missing");
        }
        Ok(Self {
            present: true,
            identities,
            unchecked: key_commitments.len(),
            key_commitments,
            error: None,
        })
    }

    /// Called only after AS verification proved the event log replays. No
    /// authenticated-output decision is made here; the verdict's trust gate
    /// additionally requires quote, challenge, platform and workload checks.
    pub(crate) fn reconcile_log(&mut self, cc_eventlog: &str, app_id: &str) {
        if !self.present || self.error.is_some() {
            return;
        }
        if let Err(error) = self.check_log(cc_eventlog, app_id) {
            self.error = Some(error);
        }
    }

    fn check_log(&mut self, cc_eventlog: &str, app_id: &str) -> Result<(), String> {
        let log = MetadataLog::restore(cc_eventlog)
            .map_err(|_| "typed identity event log could not be parsed")?;
        let (logged_identities, logged_keys) = log.of(app_id);
        let mut materials = std::collections::BTreeMap::new();
        for reference in &logged_keys {
            if materials
                .insert(&reference.material, &reference.commitment)
                .is_some_and(|old| old != &reference.commitment)
            {
                return Err("the measured log has conflicting commitments for one material".into());
            }
        }
        let mut roles = std::collections::BTreeMap::new();
        for identity in &logged_identities {
            if roles
                .insert(&identity.role, identity)
                .is_some_and(|old| old != identity)
            {
                return Err("the measured log has conflicting identities for one role".into());
            }
        }
        for reference in &self.key_commitments {
            if !log.contains(app_id, reference, None) {
                return Err(
                    "commitment has no successful measured event for this app/material".into(),
                );
            }
        }
        for identity in &self.identities {
            if let Some(reference) = &identity.key_ref {
                if !log.contains(app_id, reference, Some(identity)) {
                    return Err("KMS identity differs from its measured app/material/commitment declaration".into());
                }
            }
        }
        let events = crate::verify::eventlog_tapp_events(cc_eventlog, "get_secret_resource")
            .map_err(|_| "cannot read KMS provenance events")?;
        self.unchecked = self
            .key_commitments
            .iter()
            .filter(|reference| {
                !events.iter().any(|event| {
                    event["app_id"].as_str() == Some(app_id)
                        && event["result"].as_str() == Some("success")
                        && event["material"].as_str() == Some(reference.material.as_str())
                        && serde_json::from_value::<KeyCommitment>(event["key_commitment"].clone())
                            .ok()
                            .as_ref()
                            == Some(*reference)
                        && event["kms_attested"].as_bool() == Some(true)
                })
            })
            .count();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use serde_json::json;

    fn fixture() -> (Value, Vec<Value>, String, String) {
        let public = k256::SecretKey::from_slice(&[2; 32])
            .unwrap()
            .public_key()
            .to_encoded_point(false);
        let node = KeyIdentity::node(public.as_bytes(), "sandbox").unwrap();
        let app = KeyIdentity::app_signer(
            &[1; 32],
            crate::kms::commitment("sandbox", crate::identity::APP_SIGNER_MATERIAL, &[1; 32])
                .unwrap(),
        )
        .unwrap();
        let tls = KeyIdentity::tls(
            &[3; 32],
            Some(
                crate::kms::commitment("sandbox", crate::identity::TLS_MATERIAL, &[3; 32]).unwrap(),
            ),
        )
        .unwrap();
        let events = [&app,&tls].into_iter().map(|id| json!({
            "app_id":"sandbox","result":"success","material":id.key_ref.as_ref().unwrap().material,
            "key_commitment":id.key_ref,"identity":id,"kms_attested":true,"kms_url":"https://kms:9443"
        })).collect();
        let signer = node.ethereum_address().unwrap();
        let pin = tls.tls_spki_hash().unwrap();
        (
            json!({"app_id":"sandbox","identities":[node,app,tls],"key_commitments":[app.key_ref,tls.key_ref]}),
            events,
            signer,
            pin,
        )
    }

    fn event_log(events: &[Value]) -> String {
        let mut log = vec![0u8; 28];
        log.extend_from_slice(&0u32.to_le_bytes());
        for event in events {
            let text = format!("tapp.0g.com get_secret_resource {event}");
            let mut data = vec![0u8; 4];
            data.extend_from_slice(&(text.len() as u32).to_le_bytes());
            data.extend_from_slice(text.as_bytes());
            log.extend_from_slice(&4u32.to_le_bytes());
            log.extend_from_slice(&6u32.to_le_bytes());
            log.extend_from_slice(&1u32.to_le_bytes());
            log.extend_from_slice(&0xcu16.to_le_bytes());
            log.extend_from_slice(&[0; 48]);
            log.extend_from_slice(&(data.len() as u32).to_le_bytes());
            log.extend_from_slice(&data);
        }
        base64::engine::general_purpose::STANDARD.encode(log)
    }

    fn read(value: &Value, signer: &str, pin: &str) -> IdentityVerification {
        IdentityVerification::read(&serde_json::to_vec(value).unwrap(), "sandbox", signer, pin)
    }

    #[test]
    fn new_identity_metadata_binds_points_commitments_and_the_measured_log() {
        let (raw, events, signer, pin) = fixture();
        let mut result = read(&raw, &signer, &pin);
        assert!(result.present && result.error.is_none());
        result.reconcile_log(&event_log(&events), "sandbox");
        assert!(result.error.is_none(), "{:?}", result.error);
        assert_eq!(result.identities.len(), 3);
        assert_eq!(result.key_commitments.len(), 2);
        assert_eq!(result.unchecked, 0);
        assert_eq!(
            result.identities[1].key_ref.as_ref().unwrap().commitment,
            "0x0d2e61c0c36e0879b239181b05600f6e64fec76cc972c63198b0286533460ab3"
        );
    }

    #[test]
    fn typed_parser_refuses_scope_encoding_address_fingerprint_and_reference_errors() {
        let (raw, _, signer, pin) = fixture();
        for path in [
            "/app_id",
            "/identities/0/public_key",
            "/identities/1/algorithm",
            "/identities/2/public_key_encoding",
            "/identities/1/key_ref/commitment",
            "/key_commitments/0/scheme",
        ] {
            let mut bad = raw.clone();
            *bad.pointer_mut(path).unwrap() = json!("bad");
            assert!(read(&bad, &signer, &pin).error.is_some(), "{path}");
        }
        assert!(
            read(&raw, "0x0000000000000000000000000000000000000001", &pin)
                .error
                .is_some()
        );
        assert!(read(&raw, &signer, &format!("0x{}", "00".repeat(32)))
            .error
            .is_some());
        let mut bad = raw.clone();
        bad["identities"][1]["role"] = json!("node_signer");
        assert!(read(&bad, &signer, &pin).error.is_some());
        let mut bad = raw.clone();
        bad["key_commitments"][1] = bad["key_commitments"][0].clone();
        assert!(read(&bad, &signer, &pin).error.is_some());
    }

    #[test]
    fn replayed_events_must_match_app_material_commitment_and_exact_identity() {
        let (raw, events, signer, pin) = fixture();
        for field in ["app_id", "material", "result", "identity", "key_commitment"] {
            let mut bad_events = events.clone();
            bad_events[0][field] = json!("wrong");
            let mut out = read(&raw, &signer, &pin);
            out.reconcile_log(&event_log(&bad_events), "sandbox");
            assert!(out.error.is_some(), "{field}");
        }
        let mut extra = events.clone();
        let mut conflict = events[0].clone();
        conflict["key_commitment"]["commitment"] = json!(format!("0x{:064x}", 1));
        extra.push(conflict);
        let mut out = read(&raw, &signer, &pin);
        out.reconcile_log(&event_log(&extra), "sandbox");
        assert!(out.error.is_some());
    }

    #[test]
    fn unchecked_kms_and_tls_acquisitions_remain_visible_as_warnings() {
        let (raw, mut events, signer, pin) = fixture();
        events[1].as_object_mut().unwrap().remove("kms_attested");
        events[1]["kms_url"] = json!("http://kms:9443");
        let mut out = read(&raw, &signer, &pin);
        out.reconcile_log(&event_log(&events), "sandbox");
        assert!(out.error.is_none());
        assert_eq!(out.unchecked, 1);
        events[0]["kms_attested"] = json!(false);
        let mut out = read(&raw, &signer, &pin);
        out.reconcile_log(&event_log(&events), "sandbox");
        assert!(out.error.is_none());
        assert_eq!(out.unchecked, 2);
    }

    #[test]
    fn legacy_and_public_extensions_never_synthesize_a_typed_identity() {
        let raw = json!({"signer":"0x1","extensions":{"identities":[{}],"proof":"external"}});
        let out = read(&raw, "0x1", "");
        assert!(!out.present && out.identities.is_empty());
        let (mut raw, _, signer, pin) = fixture();
        raw["extensions"] = json!({"proof":"external"});
        assert!(read(&raw, &signer, &pin).error.is_none());
    }
}
