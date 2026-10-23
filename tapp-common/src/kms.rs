//! Algorithm-neutral KMS access and the frozen v1 commitment relation.
//! A secret is not assumed to be an EC scalar. Dedicated purposes interpret it
//! through explicit identity constructors (app signer, TLS, or an application adapter).
use crate::identity::{KeyCommitment, COMMITMENT_SCHEME};
use ark_bn254::Fr;
use light_poseidon::{Poseidon, PoseidonBytesHasher};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CommitmentError {
    #[error("KMS secret must contain exactly 32 bytes")]
    SecretLength,
    #[error("invalid KMS material")]
    Material,
    #[error("app id is too long")]
    AppId,
    #[error("Poseidon commitment failed")]
    Poseidon,
    #[error("KMS response commitment does not match the requested context and secret")]
    Mismatch,
}

/// ctx=SHA256("tapp-kms-commit-v1" || 0 || U32BE(len(app UTF8)) || app UTF8
///            || U32BE(len(decoded material)) || decoded material).
/// C=circomlib Poseidon4(ctx_hi,ctx_lo,S_hi,S_lo), each limb an unsigned u128.
/// BN254 t=5, RF=8, RP=60, x^5, initial capacity=0; canonical 32-byte BE output.
pub fn commitment(
    app_id: &str,
    material: &str,
    secret: &[u8],
) -> Result<KeyCommitment, CommitmentError> {
    if secret.len() != 32 {
        return Err(CommitmentError::SecretLength);
    }
    let material =
        crate::report_data::check_material(material).map_err(|_| CommitmentError::Material)?;
    let decoded = hex::decode(&material).map_err(|_| CommitmentError::Material)?;
    let app_len = u32::try_from(app_id.len()).map_err(|_| CommitmentError::AppId)?;
    let mut h = Sha256::new();
    h.update(b"tapp-kms-commit-v1\0");
    h.update(app_len.to_be_bytes());
    h.update(app_id.as_bytes());
    h.update((decoded.len() as u32).to_be_bytes());
    h.update(&decoded);
    let context = h.finalize();
    let mut inputs = [[0u8; 32]; 4];
    for (i, limb) in [&context[..16], &context[16..], &secret[..16], &secret[16..]]
        .iter()
        .enumerate()
    {
        inputs[i][16..].copy_from_slice(limb);
    }
    let mut poseidon = Poseidon::<Fr>::new_circom(4).map_err(|_| CommitmentError::Poseidon)?;
    let c = poseidon
        .hash_bytes_be(&[&inputs[0], &inputs[1], &inputs[2], &inputs[3]])
        .map_err(|_| CommitmentError::Poseidon)?;
    Ok(KeyCommitment {
        commitment: format!("0x{}", hex::encode(c)),
        material,
        scheme: COMMITMENT_SCHEME.into(),
    })
}

/// Validate the returned relation; this authenticates no remote peer by itself.
/// The caller must already be using its trusted local tapp socket/channel.
pub fn verify_commitment(
    app_id: &str,
    material: &str,
    secret: &[u8],
    scheme: &str,
    value: &[u8],
) -> Result<KeyCommitment, CommitmentError> {
    let expected = commitment(app_id, material, secret)?;
    if scheme != expected.scheme
        || value != hex::decode(&expected.commitment[2..]).map_err(|_| CommitmentError::Mismatch)?
    {
        return Err(CommitmentError::Mismatch);
    }
    Ok(expected)
}

pub struct SecretResource {
    pub secret: [u8; 32],
    pub commitment: KeyCommitment,
    pub measured_in_evidence: bool,
}

pub async fn get_secret(
    client: &mut crate::proto::tapp_service_client::TappServiceClient<tonic::transport::Channel>,
    app_id: &str,
    material: &str,
) -> anyhow::Result<SecretResource> {
    let normalized = crate::report_data::check_material(material)
        .map_err(|_| anyhow::anyhow!("invalid KMS material"))?;
    let r = client
        .get_secret_resource(crate::proto::GetSecretResourceRequest {
            app_id: app_id.into(),
            material: normalized.clone(),
        })
        .await?
        .into_inner();
    if !r.success || !r.measured_in_evidence {
        anyhow::bail!("KMS secret retrieval was not successfully measured");
    }
    let c = verify_commitment(
        app_id,
        &normalized,
        &r.secret,
        &r.commitment_scheme,
        &r.commitment,
    )?;
    let secret = r
        .secret
        .try_into()
        .map_err(|_| CommitmentError::SecretLength)?;
    Ok(SecretResource {
        secret,
        commitment: c,
        measured_in_evidence: r.measured_in_evidence,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn circomlib_poseidon4_known_answer() {
        use light_poseidon::PoseidonHasher;
        let params =
            light_poseidon::parameters::bn254_x5::get_poseidon_parameters::<Fr>(5).unwrap();
        assert_eq!(
            (
                params.width,
                params.full_rounds,
                params.partial_rounds,
                params.alpha
            ),
            (5, 8, 60, 5)
        );
        let actual = Poseidon::<Fr>::new_circom(4)
            .unwrap()
            .hash(&[
                Fr::from(1u64),
                Fr::from(2u64),
                Fr::from(3u64),
                Fr::from(4u64),
            ])
            .unwrap();
        assert_eq!(
            actual.to_string(),
            "18821383157269793795438455681495246036402687001665670618754263018637548127333"
        );
    }
    #[test]
    fn commitment_separates_contexts_and_covers_all_secret_bits() {
        let secret = [0xff; 32]; // not a secp scalar; still a valid generic secret
        let c = commitment("app", "0xAB", &secret).unwrap();
        assert_eq!(c, commitment("app", "ab", &secret).unwrap());
        assert_eq!(c.problem(), None);
        assert_ne!(c, commitment("app2", "ab", &secret).unwrap());
        assert_ne!(c, commitment("app", "ac", &secret).unwrap());
        let mut changed = secret;
        changed[0] ^= 1;
        assert_ne!(c, commitment("app", "ab", &changed).unwrap());
        changed = secret;
        changed[31] ^= 1;
        assert_ne!(c, commitment("app", "ab", &changed).unwrap());
        assert!(commitment("app", "ab", &[0; 31]).is_err());
        assert!(commitment("app", "zz", &secret).is_err());
        assert!(verify_commitment(
            "other",
            "ab",
            &secret,
            &c.scheme,
            &hex::decode(&c.commitment[2..]).unwrap()
        )
        .is_err());
    }
    #[test]
    fn full_context_commitment_known_answer() {
        let c = commitment("sandbox", crate::identity::APP_SIGNER_MATERIAL, &[1; 32]).unwrap();
        assert_eq!(
            c.commitment,
            "0x0d2e61c0c36e0879b239181b05600f6e64fec76cc972c63198b0286533460ab3"
        );
        let identity = crate::identity::KeyIdentity::app_signer(&[1; 32], c).unwrap();
        assert_eq!(
            identity.public_key,
            "0x031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
        );
        assert_eq!(
            identity.ethereum_address().as_deref(),
            Some("0x1a642f0e3c3af545e7acbd38b07251b3990914f1")
        );
    }
}
