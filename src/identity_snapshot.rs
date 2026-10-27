//! Derive every public evidence field from the same metadata snapshot.

use tapp_common::identity::{KeyCommitment, KeyIdentity, MetadataLog};

pub(crate) fn tls_hash(identities: &[KeyIdentity]) -> Option<String> {
    let hashes: std::collections::BTreeSet<_> = identities
        .iter()
        .filter(|id| id.role == "tls")
        .filter_map(KeyIdentity::tls_spki_hash)
        .collect();
    if hashes.len() == 1 {
        hashes.into_iter().next()
    } else {
        None
    }
}

/// Called under the metadata lock, and only after measurement succeeded.
/// A generic secret adds a commitment but no public-identity refresh hint.
pub(crate) fn publish_measured(
    log: &mut MetadataLog,
    app_id: &str,
    commitment: &KeyCommitment,
    identity: Option<&KeyIdentity>,
) -> bool {
    let changed = identity.is_some_and(|id| !log.contains(app_id, commitment, Some(id)));
    log.record(app_id, commitment.clone(), identity.cloned());
    changed
}

pub(crate) fn publish_local(log: &mut MetadataLog, app_id: &str, identity: KeyIdentity) -> bool {
    let changed = !log.of(app_id).0.contains(&identity);
    log.record_identity(app_id, identity);
    changed
}

#[cfg(test)]
mod tests {
    use super::*;
    use tapp_common::{
        identity::{APP_SIGNER_MATERIAL, TLS_MATERIAL},
        kms,
    };

    #[test]
    fn only_new_public_identities_produce_refresh_hints() {
        let mut log = MetadataLog::default();
        let generic = kms::commitment("app", "aa", &[1; 32]).unwrap();
        assert!(!publish_measured(&mut log, "app", &generic, None));
        let c = kms::commitment("app", APP_SIGNER_MATERIAL, &[1; 32]).unwrap();
        let signer = KeyIdentity::app_signer(&[1; 32], c.clone()).unwrap();
        assert!(publish_measured(&mut log, "app", &c, Some(&signer)));
        assert!(!publish_measured(&mut log, "app", &c, Some(&signer)));
        // Restored metadata is the same publication; returning the cached key is not one.
        assert!(log.contains("app", &c, Some(&signer)));
        let c2 = kms::commitment("app", APP_SIGNER_MATERIAL, &[2; 32]).unwrap();
        let signer2 = KeyIdentity::app_signer(&[2; 32], c2.clone()).unwrap();
        assert!(publish_measured(&mut log, "app", &c2, Some(&signer2)));
        let local = KeyIdentity::tls(&[1; 32], None).unwrap();
        assert!(publish_local(&mut log, "app", local.clone()));
        assert!(!publish_local(&mut log, "app", local));
    }

    #[test]
    fn first_tls_publication_cannot_mix_a_snapshot_with_an_older_pin() {
        let mut log = MetadataLog::default();
        let (before, _) = log.of("app");
        let c = kms::commitment("app", TLS_MATERIAL, &[1; 32]).unwrap();
        let tls = KeyIdentity::tls(&[1; 32], Some(c.clone())).unwrap();
        assert!(publish_measured(&mut log, "app", &c, Some(&tls)));
        // A publication between taking the snapshot and sealing evidence cannot change
        // either field of the already captured snapshot.
        assert!(before.is_empty());
        assert_eq!(tls_hash(&before), None);
        let (after, refs) = log.of("app");
        assert_eq!(tls_hash(&after), tls.tls_spki_hash());
        assert_eq!(after, [tls]);
        assert_eq!(refs, [c]);
    }

    #[test]
    fn a_conflicting_tls_history_is_not_silently_reduced_to_the_cached_key() {
        let a = KeyIdentity::tls(&[1; 32], None).unwrap();
        let b = KeyIdentity::tls(&[2; 32], None).unwrap();
        assert_eq!(tls_hash(&[a.clone(), a.clone()]), a.tls_spki_hash());
        assert_eq!(tls_hash(&[a, b]), None);
    }
}
