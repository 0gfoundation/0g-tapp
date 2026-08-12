//! The app's TLS identity: a P-256 key plus a certificate for it.
//!
//! Three things here are load-bearing and none is obvious from the code alone.
//!
//! **The key is always derived, never randomly generated** — but from one of two places,
//! and the choice changes what a verifier learns. See [`crate::config::TlsKeySource`]: from
//! the app's own signer, the key never leaves this CVM and the statement is "you are talking
//! to *this* TEE"; from KMS, the key is stable across restarts and shared by every node of
//! the app, which is what pinning and transparency monitoring need, and the statement
//! weakens to "some TEE of this app". Neither is the safe default for all cases.
//!
//! **Self-signed is not a lesser certificate here.** What a verifier checks is the public
//! key against the one the quote committed to; who signed the certificate has no part in
//! that. The issuer matters only for clients that will not do the check — browsers and
//! anything else driving off a system trust store.
//!
//! **Randomness would be worse than either.** A fresh key per process would still be
//! attestable, but it could not be reproduced by anything, so a key that appeared in a log
//! or a pin could never be checked against an expectation.

use crate::error::{DockerError, TappResult};
use p256::pkcs8::EncodePrivateKey;
use sha2::{Digest, Sha256};

/// Derivation namespace. Deliberately not the app's signer material: a key used for TLS
/// handshakes should not also be the identity that signs chain transactions and decrypts
/// KMS payloads.
///
/// **Hex, because KMS decodes it** (`proto/tapp_service.proto`: "hex-encoded derivation
/// material"). Passing the ASCII `"tls"` gets a 500 from the cluster, which is not obvious
/// from anything on this side — hence the constant rather than a literal at the call site.
/// This is `hex("tls")`, kept legible so it can still be recognised in a log.
pub const KMS_MATERIAL: &str = "746c73";

/// Names are ours to hand out, so no domain-control validation is involved. A private CA
/// that would sign arbitrary names is an interception tool against everyone holding its
/// root, so issuance stays inside a namespace we own. Custom domains go to a public CA.
const NAME_SUFFIX: &str = "tapp.0g.ai";

/// When a self-signed certificate stops claiming validity. Deliberately far out: nothing
/// checks it, so an expiry would only break clients one day without having protected
/// anyone in the meantime. A CA-issued certificate gets whatever lifetime the CA decides,
/// and that one does mean something.
const SELF_SIGNED_NOT_AFTER: (i32, u8, u8) = (2035, 1, 1);

pub struct TlsIdentity {
    pub key_pem: String,
    pub cert_pem: String,
    pub csr_pem: String,
    pub issuer: &'static str,
    /// "local" or "kms" — which derivation produced this key. Reported because a client
    /// deciding whether to pin the public key needs to know if it survives a restart.
    pub key_source: &'static str,
    /// sha256 of the SubjectPublicKeyInfo, hex. What `report_data` commits to.
    pub public_key_sha256: String,
}

fn fail(reason: impl Into<String>) -> crate::error::TappError {
    DockerError::ContainerOperationFailed {
        operation: "app_tls_cert".to_string(),
        reason: reason.into(),
    }
    .into()
}

/// The name this app's certificate is issued for.
pub fn dns_name(app_id: &str) -> String {
    format!("{}.{}", app_id, NAME_SUFFIX)
}

/// The app's TLS key pair, from the derived secret.
///
/// Shared so the certificate and any signing request are provably the same key — deriving
/// it twice by two routes would be a place for them to diverge.
fn key_pair_from(secret: &[u8]) -> TappResult<rcgen::KeyPair> {
    // A derived secret is uniform bytes; P-256 wants a scalar in range, which from_slice
    // enforces. Rejecting is correct rather than reducing: a secret that does not map to a
    // valid key means the derivation changed shape, and quietly mangling it would produce
    // a key nobody can reproduce.
    let secret_key = p256::SecretKey::from_slice(secret)
        .map_err(|e| fail(format!("derived secret is not a valid P-256 key: {}", e)))?;
    let pkcs8 = secret_key
        .to_pkcs8_der()
        .map_err(|e| fail(format!("encode private key: {}", e)))?;
    rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
        &rustls_pki_types::PrivatePkcs8KeyDer::from(pkcs8.as_bytes()),
        &rcgen::PKCS_ECDSA_P256_SHA256,
    )
    .map_err(|e| fail(format!("load key pair: {}", e)))
}

/// A certificate signing request for `domain`, signed by the app's own TLS key.
///
/// Separate from `build` because the two answer different questions. `build` produces the
/// identity the app serves — a certificate for `<app-id>.tapp.0g.ai`, which is what a
/// verifier checks against the attestation and needs no authority behind it. This produces
/// something to hand to an authority that will vouch for a name it recognises, and the name
/// is therefore the caller's to choose.
///
/// **The key is the same one.** That is the entire point: a certificate the CA issues from
/// this request carries the public key the attestation already commits to, so both checks
/// pass at once — a browser matches the name the CA vouched for, a verifier matches the key
/// the TEE vouched for, and they read different fields without interfering.
///
/// Nothing secret leaves: a signing request is a public key, a name, and a signature proving
/// the requester holds the private half. Publishing one gives away nothing the eventual
/// certificate would not.
pub fn signing_request(secret: &[u8], domain: &str) -> TappResult<String> {
    if domain.is_empty() {
        return Err(fail("domain must not be empty"));
    }
    // rcgen rejects a malformed name later and less clearly; refusing here keeps the error
    // next to the input that caused it.
    if domain.starts_with('.')
        || domain.ends_with('.')
        || domain.contains("..")
        || !domain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '*')
    {
        return Err(fail(format!("not a usable domain name: {:?}", domain)));
    }

    let key_pair = key_pair_from(secret)?;
    let mut params = rcgen::CertificateParams::new(vec![domain.to_string()])
        .map_err(|e| fail(format!("certificate params: {}", e)))?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, domain.to_string());
    params.extended_key_usages = vec![
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
    ];
    params
        .serialize_request(&key_pair)
        .map_err(|e| fail(format!("build signing request: {}", e)))?
        .pem()
        .map_err(|e| fail(format!("encode signing request: {}", e)))
}

/// sha256 of a DER-encoded SubjectPublicKeyInfo, hex.
///
/// The public key rather than the whole certificate: the key is what the TEE holds and
/// what survives reissuance, and it is also the unit every certificate-pinning
/// implementation uses.
pub fn public_key_sha256_hex(spki_der: &[u8]) -> String {
    hex::encode(Sha256::digest(spki_der))
}

/// The TLS key belonging to an app signer, for the local (no-KMS) source.
///
/// Hashed with a domain separator rather than used directly: the signer is a secp256k1
/// scalar and this must be a P-256 one, ranges differ, and one key doing two jobs on two
/// curves is how cross-protocol mistakes start. Hashing also makes the derivation one-way,
/// so possession of the TLS key says nothing about the signer — which matters, because the
/// signer is the identity that signs chain transactions and decrypts KMS payloads.
pub fn derive_from_signer(signer_private_key: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b"tapp-tls-v1");
    h.update(signer_private_key);
    h.finalize().to_vec()
}

/// Turn derived bytes into a certificate, asking `ca_url` to sign when one is set.
///
/// Without a CA the certificate is self-signed and the signing request is returned
/// alongside, so the deployer can obtain a publicly-trusted certificate for the same key
/// later without coming back for the key.
pub async fn build(
    app_id: &str,
    secret: &[u8],
    key_source: &'static str,
    ca_url: Option<&str>,
) -> TappResult<TlsIdentity> {
    let key_pair = key_pair_from(secret)?;
    let public_key_sha256 = public_key_sha256_hex(&key_pair.public_key_der());

    let name = dns_name(app_id);
    let mut params = rcgen::CertificateParams::new(vec![name.clone()])
        .map_err(|e| fail(format!("certificate params: {}", e)))?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name.clone());
    // Usable in both directions. An app calling another app presents this same
    // certificate as a client certificate, and a strict peer refuses one that only
    // claims server authentication.
    params.use_authority_key_identifier_extension = false;
    params.extended_key_usages = vec![
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
    ];

    let csr_pem = params
        .serialize_request(&key_pair)
        .map_err(|e| fail(format!("build signing request: {}", e)))?
        .pem()
        .map_err(|e| fail(format!("encode signing request: {}", e)))?;

    let (cert_pem, issuer) = match ca_url {
        Some(url) => (sign_with_ca(url, &csr_pem).await?, "ca"),
        None => {
            let mut p = params;
            let (y, m, d) = SELF_SIGNED_NOT_AFTER;
            p.not_after = rcgen::date_time_ymd(y, m, d);
            (
                p.self_signed(&key_pair)
                    .map_err(|e| fail(format!("self-sign: {}", e)))?
                    .pem(),
                "self-signed",
            )
        }
    };

    Ok(TlsIdentity {
        key_pem: key_pair.serialize_pem(),
        cert_pem,
        csr_pem,
        issuer,
        key_source,
        public_key_sha256,
    })
}

/// Hand the signing request to the CA. Nothing secret travels: a signing request carries
/// the public key and a proof of possession, never the private key, and a certificate is
/// public by definition — so this needs no confidential channel, only a truthful answer,
/// which the caller gets by checking the result chains to a root it already trusts.
async fn sign_with_ca(ca_url: &str, csr_pem: &str) -> TappResult<String> {
    let resp = reqwest::Client::new()
        .post(format!("{}/sign", ca_url.trim_end_matches('/')))
        .header("content-type", "application/x-pem-file")
        .body(csr_pem.to_string())
        .send()
        .await
        .map_err(|e| fail(format!("CA {} unreachable: {}", ca_url, e)))?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(fail(format!("CA {} returned {}: {}", ca_url, status, body)));
    }
    if !body.contains("BEGIN CERTIFICATE") {
        return Err(fail(format!("CA {} did not return a certificate", ca_url)));
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    // A fixed, valid P-256 scalar — stands in for whatever KMS derives.
    const SECRET: [u8; 32] = [
        0x4c, 0x0b, 0x1f, 0x6d, 0x2a, 0x91, 0x33, 0x7e, 0x58, 0xc4, 0x0d, 0xa2, 0x66, 0x19,
        0xfb, 0x87, 0x35, 0x92, 0xee, 0x41, 0x7a, 0x0c, 0xb3, 0x5d, 0x28, 0x6f, 0x94, 0x11,
        0xd7, 0x03, 0x8a, 0x56,
    ];

    #[tokio::test]
    async fn the_same_derived_secret_always_yields_the_same_public_key() {
        // This is the property the whole design leans on: restarts and other nodes of the
        // same app must present the same key, or pinning and CT monitoring are worthless.
        let a = build("demo", &SECRET, "local", None).await.unwrap();
        let b = build("demo", &SECRET, "local", None).await.unwrap();
        assert_eq!(a.public_key_sha256, b.public_key_sha256);
        assert_eq!(a.key_pem, b.key_pem);
    }

    #[tokio::test]
    async fn a_different_app_gets_a_different_key_only_because_kms_derives_differently() {
        // Same secret, different app: identical keys. The separation comes from the
        // derivation namespace, never from anything this module does.
        let a = build("one", &SECRET, "local", None).await.unwrap();
        let b = build("two", &SECRET, "local", None).await.unwrap();
        assert_eq!(a.public_key_sha256, b.public_key_sha256);
        assert_ne!(a.cert_pem, b.cert_pem, "but the names differ");
    }

    #[tokio::test]
    async fn without_a_ca_the_certificate_is_self_signed_and_the_request_still_comes_back() {
        let id = build("demo", &SECRET, "local", None).await.unwrap();
        assert_eq!(id.issuer, "self-signed");
        assert!(id.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(id.csr_pem.contains("BEGIN CERTIFICATE REQUEST"));
        assert!(id.key_pem.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn a_signing_request_carries_the_name_that_was_asked_for() {
        // The whole reason this exists: the built-in certificate is issued for
        // <app-id>.tapp.0g.ai, and a public CA validates the request's names against the
        // order — so a request that cannot name the caller's domain is unusable there.
        let csr = signing_request(&[7u8; 32], "api.example.com").unwrap();
        assert!(csr.contains("BEGIN CERTIFICATE REQUEST"));

        // Decode the PEM body rather than pulling in a parser: the name appears verbatim
        // in the DER, so finding it there is enough to show it reached the request.
        let b64: String = csr
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<Vec<_>>()
            .join("");
        let der = base64::decode(b64.trim()).unwrap();
        let text = String::from_utf8_lossy(&der);
        assert!(text.contains("api.example.com"), "name missing from request");
        assert!(
            !text.contains("tapp.0g.ai"),
            "the built-in name leaked into a request asked for another"
        );
    }

    #[tokio::test]
    async fn a_signing_request_uses_the_same_key_as_the_certificate() {
        // If these could differ, a CA would certify a key the attestation does not commit
        // to, and both checks would pass separately while describing different endpoints.
        let id = build("app", &SECRET, "local", None).await.unwrap();
        let kp = key_pair_from(&SECRET).unwrap();
        assert_eq!(
            public_key_sha256_hex(&kp.public_key_der()),
            id.public_key_sha256
        );
        assert!(signing_request(&SECRET, "other.example.com")
            .unwrap()
            .contains("BEGIN CERTIFICATE REQUEST"));
    }

    #[test]
    fn a_domain_that_is_not_one_is_refused_rather_than_encoded() {
        for bad in ["", ".leading", "trailing.", "a..b", "has space", "semi;colon"] {
            assert!(
                signing_request(&[7u8; 32], bad).is_err(),
                "accepted {:?}",
                bad
            );
        }
    }

    #[tokio::test]
    async fn the_name_is_derived_from_the_app_id_not_supplied_by_the_caller() {
        assert_eq!(dns_name("0g-sandbox-provider"), "0g-sandbox-provider.tapp.0g.ai");
    }

    #[tokio::test]
    async fn a_secret_that_is_not_a_valid_key_is_refused_rather_than_reduced() {
        assert!(build("demo", &[0u8; 32], "local", None).await.is_err(), "zero is not a scalar");
        assert!(build("demo", &[0u8; 16], "local", None).await.is_err(), "wrong length");
    }
}

#[cfg(test)]
mod material {
    /// KMS decodes the derivation material as hex, so a readable ASCII namespace silently
    /// becomes a 500 from the cluster. Cheap to assert, and the failure it prevents costs
    /// a real deployment to discover.
    #[test]
    fn the_derivation_material_is_valid_hex() {
        assert!(
            hex::decode(super::KMS_MATERIAL).is_ok(),
            "KMS_MATERIAL must be hex; KMS rejects anything else"
        );
    }
}

#[cfg(test)]
mod local_derivation {
    use super::*;

    const SIGNER: [u8; 32] = [0x7f; 32];

    #[test]
    fn the_tls_key_is_not_the_signer_key() {
        // Reusing the signer scalar directly would put one key on two curves doing two
        // jobs — and would mean holding the TLS key implies holding the chain identity.
        assert_ne!(derive_from_signer(&SIGNER), SIGNER.to_vec());
    }

    #[test]
    fn the_same_signer_always_gives_the_same_tls_key() {
        // Within one boot the signer does not change, so neither may this: an app asking
        // twice must get the same certificate rather than silently rotating.
        assert_eq!(derive_from_signer(&SIGNER), derive_from_signer(&SIGNER));
    }

    #[test]
    fn a_different_signer_gives_a_different_tls_key() {
        // The point of the local source: the key is bound to this instance, and a restart
        // re-derives the signer, so the TLS key must move with it.
        assert_ne!(derive_from_signer(&SIGNER), derive_from_signer(&[0x11; 32]));
    }

    #[tokio::test]
    async fn a_locally_derived_secret_is_a_usable_p256_key() {
        // sha256 output is uniform over 32 bytes, so it can in principle fall outside the
        // P-256 order. Checking a real derivation reaches a certificate keeps that from
        // being a theory nobody tested.
        let id = build("demo", &derive_from_signer(&SIGNER), "local", None)
            .await
            .unwrap();
        assert_eq!(id.key_source, "local");
        assert!(id.cert_pem.contains("BEGIN CERTIFICATE"));
    }
}
