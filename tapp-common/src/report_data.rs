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
//! - **Verifiers hash the bytes exactly as transmitted** and never re-serialise them. The
//!   `RuntimeData` struct is a convenience for reading the fields, never a re-encoder.
//!   (The bytes are also canonical JSON, by design, so CoCo-AS can check them itself: see
//!   [`RuntimeData`].)
//!
//! `sha512` is not arbitrary: TDX `report_data` is 64 bytes and sha512 fills it exactly.
//! CoCo-AS checks the binding itself only when handed the object as
//! `structured_runtime_data` with `sha512` named (its default is sha384, and raw runtime
//! data it compares unhashed).

use crate::error::{DockerError, TappResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::collections::{BTreeMap, HashMap};

/// Field name under which the hashed bytes travel inside the evidence JSON.
pub const EVIDENCE_FIELD: &str = "runtime_data";

/// Longest challenge accepted, in bytes. A caller only needs enough to be unguessable;
/// the cap exists so a request cannot inflate every quote this node produces.
pub const MAX_NONCE_LEN: usize = 64;

/// Longest derivation material `GetSecretResource` takes, in bytes. A material names a
/// key, and names this long are already generous (AgenticID's is 60 bytes). Every material
/// an app uses is written into its evidence and into an event, so without a limit one
/// request could grow both by megabytes.
pub const MAX_MATERIAL_LEN: usize = 256;

/// The object `report_data` is the hash of.
///
/// Empty top-level fields are omitted rather than serialised as `""` or `[]`, so evidence
/// produced before a field existed and evidence produced after it are byte-identical
/// whenever the field is unused.
///
/// Fields are declared in alphabetical order, and so are [`KmsKey`]'s. serde writes them in
/// declaration order, so the bytes are the canonical JSON (sorted keys, no whitespace)
/// that CoCo-AS computes when it is handed this object as `structured_runtime_data` and
/// checks the binding itself. A new field must keep that order.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeData {
    /// The keys this app has taken from the KMS through `GetSecretResource` this boot,
    /// sorted by material and then address. Normally one per material; two for one
    /// material mean this node got two different keys for it, from two KMS clusters or
    /// with one answer substituted (see [`KmsKeyLog`]).
    ///
    /// The whole boot, not just this tapp-server process: a restarted process lists again
    /// what the `get_secret_resource` events of this boot name.
    ///
    /// Only what was asked for through `GetSecretResource`. The TLS key has its own field
    /// below, and the volume key is no identity anybody verifies.
    ///
    /// Never read by deserialising this struct, which skips the field as readers older than
    /// the field (tapp-cli ≤ 0.11.0) do, so nothing it holds can stop the signer being read.
    /// Read it with [`read_kms_keys`].
    #[serde(skip_serializing_if = "Vec::is_empty", skip_deserializing)]
    pub kms_keys: Vec<KmsKey>,

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

/// A key the app took from the KMS, as the evidence names it.
///
/// The app is expected to use the 32-byte secret as a secp256k1 private key, and `address`
/// and `public_key` are that key's. A verifier that finds an address here learns that this
/// TEE, the one registered on chain as `signer`, holds the key for `material` of this app,
/// as given by the KMS node that answered when it was taken. The KMS derives one key per
/// (app_id, material), so every node of the app that took the same material from the same
/// cluster names the same address, and that stays true across restarts.
///
/// Fields in alphabetical order, for the reason given on [`RuntimeData`].
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct KmsKey {
    /// The key's Ethereum address, `0x…`, lowercase.
    pub address: String,

    /// The derivation material as the KMS reads it: hex, lowercase, without `0x`. Empty is
    /// the app's base key. Always written, even when empty, so every entry has the same
    /// fields, and an entry without it is not one tapp-server wrote.
    pub material: String,

    /// The key's compressed secp256k1 public key (33 bytes), `0x…`, lowercase.
    pub public_key: String,
}

impl KmsKey {
    /// The entry for `secret`, taken under `material`. `None` when the secret is not a
    /// usable private key (see `app_key::eth_identity_of_secret`).
    pub fn of_secret(material: &str, secret: &[u8]) -> Option<Self> {
        let (address, public_key) = crate::app_key::eth_identity_of_secret(secret)?;
        Some(Self {
            address: format!("0x{}", hex::encode(address)),
            material: normalize_material(material),
            public_key: format!("0x{}", hex::encode(public_key)),
        })
    }

    /// Whether `address` is the address of `public_key`. tapp-server computes both from the
    /// same secret, so a mismatch is a malformed entry, and a verifier believes neither half.
    pub fn is_consistent(&self) -> bool {
        let Ok(public_key) = hex::decode(strip_hex(&self.public_key)) else {
            return false;
        };
        crate::app_key::eth_address_of_public_key(&public_key)
            .is_some_and(|a| strip_hex(&self.address).eq_ignore_ascii_case(&hex::encode(a)))
    }

    /// Why a verifier must not believe this entry, or `None` when it may.
    ///
    /// tapp-server writes every field in one form only, so an entry in any other form did
    /// not come from it. Holding entries to that form also lets a verifier compare them as
    /// plain strings, and print them without escaping.
    pub fn problem(&self) -> Option<&'static str> {
        let lower_hex = |s: &str| s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !lower_hex(&self.material)
            || !self.material.len().is_multiple_of(2)
            || self.material.len() > 2 * MAX_MATERIAL_LEN
        {
            return Some("its material is not lowercase hex of at most 256 bytes, without 0x");
        }
        match self.address.strip_prefix("0x") {
            Some(a) if a.len() == 40 && lower_hex(a) => {}
            _ => return Some("its address is not 0x and 40 lowercase hex digits"),
        }
        match self.public_key.strip_prefix("0x") {
            Some(p) if p.len() == 66 && lower_hex(p) => {}
            _ => return Some("its public key is not 0x and 66 lowercase hex digits"),
        }
        if !self.is_consistent() {
            return Some("its address is not its public key's");
        }
        None
    }
}

/// Most entries a verifier reads out of one `kms_keys`; the rest count as dropped. Far past
/// any real app: evidence that large is refused by the AS long before.
pub const MAX_KMS_KEYS_READ: usize = 100_000;

/// How many reasons for dropped entries a verifier keeps.
const REASONS_KEPT: usize = 3;

/// Longest entry a verifier parses, in bytes. The longest tapp-server writes, with a material
/// of [`MAX_MATERIAL_LEN`] bytes, is under 700.
const MAX_KMS_KEY_ENTRY_LEN: usize = 1024;

/// The `kms_keys` of a runtime_data as a verifier reads them.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct KmsKeysRead {
    /// The entries in the one form tapp-server writes ([`KmsKey::problem`]).
    pub keys: Vec<KmsKey>,
    /// How many entries were not, or 1 when the field could not be read at all.
    pub dropped: usize,
    /// Why, for the first few only and each kept short: evidence built to be huge must not
    /// make a verifier's report huge.
    pub reasons: Vec<String>,
}

impl KmsKeysRead {
    fn drop_one(&mut self, why: impl FnOnce() -> String) {
        self.dropped += 1;
        if self.reasons.len() < REASONS_KEPT {
            self.reasons.push(why());
        }
    }
}

/// Read `kms_keys` out of a runtime_data's bytes. Nothing here fails: an absent field is an
/// empty list, and anything unreadable is counted in `dropped` and said in `reasons`.
///
/// Entries are read one at a time, so a list of any length costs memory for the entries
/// kept, not for the list.
pub fn read_kms_keys(runtime_data: &[u8]) -> KmsKeysRead {
    #[derive(Deserialize)]
    struct Only {
        #[serde(default)]
        kms_keys: StreamedKmsKeys,
    }
    match serde_json::from_slice::<Only>(runtime_data) {
        Ok(only) => only.kms_keys.0,
        Err(e) => {
            let mut read = KmsKeysRead::default();
            let e: String = e.to_string().chars().take(120).collect();
            read.drop_one(|| format!("kms_keys unreadable: {}", e));
            read
        }
    }
}

#[derive(Default)]
struct StreamedKmsKeys(KmsKeysRead);

impl<'de> Deserialize<'de> for StreamedKmsKeys {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(StreamedKmsKeysVisitor)
    }
}

struct StreamedKmsKeysVisitor;

impl StreamedKmsKeysVisitor {
    fn not_a_list() -> StreamedKmsKeys {
        let mut read = KmsKeysRead::default();
        read.drop_one(|| "kms_keys is not a list".to_string());
        StreamedKmsKeys(read)
    }
}

impl<'de> serde::de::Visitor<'de> for StreamedKmsKeysVisitor {
    type Value = StreamedKmsKeys;

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("a list of KMS keys")
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut read = KmsKeysRead::default();
        // Each element borrowed as its raw text: nothing is built for one too long to be an
        // entry tapp-server wrote, whatever its shape, and one malformed element costs only
        // itself.
        while let Some(raw) = seq.next_element::<&'de serde_json::value::RawValue>()? {
            let text = raw.get();
            if text.len() > MAX_KMS_KEY_ENTRY_LEN {
                read.drop_one(|| format!("an entry of {} bytes, longer than any key entry", text.len()));
                continue;
            }
            if read.keys.len() >= MAX_KMS_KEYS_READ {
                read.drop_one(|| format!("more than {} entries", MAX_KMS_KEYS_READ));
                continue;
            }
            match serde_json::from_str::<KmsKey>(text) {
                Ok(k) => match k.problem() {
                    None => read.keys.push(k),
                    // Debug-formatted and cut short: the material is whatever the entry says,
                    // and it ends up on a terminal.
                    Some(why) => read.drop_one(|| {
                        let shown: String = k.material.chars().take(64).collect();
                        format!("kms key for material {:?}: {}", shown, why)
                    }),
                },
                Err(_) => read.drop_one(|| "an entry that is not a KMS key".to_string()),
            }
        }
        Ok(StreamedKmsKeys(read))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StreamedKmsKeys::default())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StreamedKmsKeys::default())
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(Self::not_a_list())
    }

    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(Self::not_a_list())
    }

    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(Self::not_a_list())
    }

    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
        Ok(Self::not_a_list())
    }

    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
        Ok(Self::not_a_list())
    }

    fn visit_map<M: serde::de::MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
        while map
            .next_entry::<serde::de::IgnoredAny, serde::de::IgnoredAny>()?
            .is_some()
        {}
        Ok(Self::not_a_list())
    }
}

/// The fields a `get_secret_resource` event adds beside `material`: the key the app took, if
/// it took one through `GetSecretResource`, and the KMS node that answered with whether the
/// connection to it was checked against attestation. What `verify::eventlog_kms_keys` reads
/// back; one function, so the writer and the reader cannot drift apart.
pub fn kms_event_fields(
    key: Option<&KmsKey>,
    answer: Option<(&str, bool)>,
) -> serde_json::Map<String, serde_json::Value> {
    let mut fields = serde_json::Map::new();
    if let Some(k) = key {
        fields.insert("address".into(), k.address.clone().into());
        fields.insert("public_key".into(), k.public_key.clone().into());
    }
    if let Some((url, attested)) = answer {
        fields.insert("kms_url".into(), url.into());
        fields.insert("kms_attested".into(), attested.into());
    }
    fields
}

/// A derivation material in the form the KMS reads it, so two spellings of one material
/// count as the one key they are: the KMS strips leading `0x` and decodes hex in either
/// case, so `0xAB01` and `ab01` derive the same key.
pub fn normalize_material(material: &str) -> String {
    material.trim_start_matches("0x").to_ascii_lowercase()
}

/// `material` as `GetSecretResource` accepts it, normalized; or why it is refused.
///
/// Hex as the KMS decodes it (hex digits in either case, with an optional `0x`) and at
/// most [`MAX_MATERIAL_LEN`] bytes. Checked before the KMS is asked, so what reaches the
/// evidence never depends on how the KMS happens to parse.
pub fn check_material(material: &str) -> Result<String, String> {
    let normalized = normalize_material(material);
    let bytes = hex::decode(&normalized).map_err(|e| format!("material must be hex: {}", e))?;
    if bytes.len() > MAX_MATERIAL_LEN {
        return Err(format!(
            "material must be at most {} bytes, got {}",
            MAX_MATERIAL_LEN,
            bytes.len()
        ));
    }
    Ok(normalized)
}

/// The KMS keys each app has taken through `GetSecretResource` this boot, as `GetEvidence`
/// lists them: per app, one entry per material and key, in that order. tapp-server fills
/// it from this boot's `get_secret_resource` events when it starts, and then from each
/// request it serves.
///
/// Kept by key as well as by material. A material normally has one key, but a node whose
/// KMS cluster was changed while it ran (`UpdateTrustAnchors`) gets a second one, and
/// keeping only the newer would hide the very thing a verifier needs to see.
#[derive(Debug, Default)]
pub struct KmsKeyLog(HashMap<String, BTreeMap<(String, String), KmsKey>>);

impl KmsKeyLog {
    pub fn record(&mut self, app_id: &str, key: KmsKey) {
        self.0
            .entry(app_id.to_string())
            .or_default()
            .insert((key.material.clone(), key.address.clone()), key);
    }

    /// The keys `app_id` has taken, in material and then address order.
    pub fn of(&self, app_id: &str) -> Vec<KmsKey> {
        self.0
            .get(app_id)
            .map(|keys| keys.values().cloned().collect())
            .unwrap_or_default()
    }
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
            kms_keys: Vec::new(),
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

    fn secret(last: u8) -> [u8; 32] {
        let mut s = [0u8; 32];
        s[31] = last;
        s
    }

    #[test]
    fn no_kms_keys_leaves_the_bytes_as_they_were() {
        // Evidence for an app that took no key must not change at all: a verifier that
        // predates the field hashes the same bytes it always did.
        let (bytes, _) = RuntimeData::new(&SIGNER, b"chal").unwrap().seal().unwrap();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            format!(r#"{{"nonce":"0x{}","signer":"0x{}"}}"#, hex::encode(b"chal"), hex::encode(SIGNER))
        );
    }

    fn full() -> RuntimeData {
        let mut rd = RuntimeData::new(&SIGNER, b"chal").unwrap();
        rd.tls_public_key = format!("0x{}", "cd".repeat(32));
        rd.kms_keys = vec![
            KmsKey::of_secret("", &secret(1)).unwrap(),
            KmsKey::of_secret("0x7369676E6572", &secret(2)).unwrap(),
        ];
        rd
    }

    #[test]
    fn kms_keys_come_first_and_read_back() {
        let rd = full();
        let (bytes, _) = rd.seal().unwrap();
        let s = String::from_utf8(bytes.clone()).unwrap();
        assert!(
            s.starts_with(
                r#"{"kms_keys":[{"address":"0x7e5f4552091a69125d5dfcb7b8c2659029395bdf","material":"","public_key":"0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"},{"address":"0x"#
            ),
            "got {}",
            s
        );
        assert!(s.contains(r#""material":"7369676e6572""#), "got {}", s);
        let read = read_kms_keys(&bytes);
        assert_eq!(read.keys, rd.kms_keys);
        assert_eq!((read.dropped, read.reasons.len()), (0, 0));
        // The struct itself never reads the field back; read_kms_keys does.
        let parsed: RuntimeData = serde_json::from_slice(&bytes).unwrap();
        assert!(parsed.kms_keys.is_empty());
        assert_eq!(parsed.signer, rd.signer);
    }

    /// `v` with every object's keys sorted, whether or not serde_json preserves order.
    fn sorted(v: serde_json::Value) -> serde_json::Value {
        match v {
            serde_json::Value::Object(m) => {
                let mut entries: Vec<_> = m.into_iter().collect();
                entries.sort_by(|a, b| a.0.cmp(&b.0));
                serde_json::Value::Object(entries.into_iter().map(|(k, v)| (k, sorted(v))).collect())
            }
            serde_json::Value::Array(a) => serde_json::Value::Array(a.into_iter().map(sorted).collect()),
            other => other,
        }
    }

    #[test]
    fn the_bytes_are_the_canonical_json_coco_as_hashes() {
        // CoCo-AS, handed this object as structured_runtime_data, re-serialises it with
        // sorted keys and no whitespace before hashing, so a field out of order makes its
        // own binding check fail.
        for rd in [RuntimeData::new(&SIGNER, &[]).unwrap(), full()] {
            let (bytes, _) = rd.seal().unwrap();
            let canonical =
                serde_json::to_vec(&sorted(serde_json::from_slice(&bytes).unwrap())).unwrap();
            assert_eq!(String::from_utf8(canonical).unwrap(), String::from_utf8(bytes).unwrap());
        }
    }

    #[test]
    fn a_runtime_data_from_before_kms_keys_still_parses() {
        let parsed: RuntimeData = serde_json::from_str(r#"{"signer":"0xab"}"#).unwrap();
        assert!(parsed.kms_keys.is_empty());
    }

    #[test]
    fn nothing_in_kms_keys_costs_the_signer() {
        // Values serde_json's ignore path skips but a typed reader would choke on, as well
        // as plain junk. The struct skips the field as readers older than it do, so all of
        // these parse.
        let deep = format!("[{}0{}]", "[".repeat(200), "]".repeat(200));
        for kms_keys in [
            "null",
            "\"not a list\"",
            "{\"a\":1}",
            "[{\"address\":\"0x01\"}]",
            "[1e400]",
            "[\"\\ud800\"]",
            deep.as_str(),
        ] {
            let text = format!(r#"{{"kms_keys":{},"signer":"0xab"}}"#, kms_keys);
            let parsed: RuntimeData = serde_json::from_str(&text).unwrap();
            assert_eq!(parsed.signer, "0xab", "{kms_keys}");
            assert!(read_kms_keys(text.as_bytes()).keys.is_empty(), "{kms_keys}");
        }
        let twice = r#"{"kms_keys":[],"kms_keys":[],"signer":"0xab"}"#;
        assert_eq!(serde_json::from_str::<RuntimeData>(twice).unwrap().signer, "0xab");
        assert_eq!(read_kms_keys(twice.as_bytes()).dropped, 1);
    }

    #[test]
    fn one_bad_entry_costs_only_itself() {
        let good = serde_json::to_string(&KmsKey::of_secret("", &secret(1)).unwrap()).unwrap();
        let deep = format!("{}0{}", "[".repeat(200), "]".repeat(200));
        let huge = format!("[{}0]", "0,".repeat(100_000));
        for bad in ["1e400", "\"\\ud800\"", deep.as_str(), huge.as_str()] {
            let text = format!(r#"{{"kms_keys":[{},{}]}}"#, bad, good);
            let read = read_kms_keys(text.as_bytes());
            assert_eq!(read.keys.len(), 1, "{}", &bad[..bad.len().min(20)]);
            assert_eq!(read.dropped, 1);
        }
    }

    #[test]
    fn what_is_dropped_is_counted_and_said_briefly() {
        let good = serde_json::to_string(&KmsKey::of_secret("", &secret(1)).unwrap()).unwrap();
        let mut no_material: serde_json::Value = serde_json::from_str(&good).unwrap();
        no_material.as_object_mut().unwrap().remove("material");
        let text = format!(
            r#"{{"kms_keys":[42,{},{},"{}"],"signer":"0xab"}}"#,
            good,
            no_material,
            "x".repeat(1 << 20)
        );
        let read = read_kms_keys(text.as_bytes());
        assert_eq!(read.keys.len(), 1);
        assert_eq!(read.dropped, 3);
        assert!(read.reasons.iter().all(|r| r.len() < 200), "{:?}", read.reasons);
        assert!(read_kms_keys(br#"{"kms_keys":"x"}"#).reasons[0].contains("not a list"));
        assert_eq!(read_kms_keys(br#"{"signer":"0xab"}"#), KmsKeysRead::default());

        // Thousands of junk entries: every one counted, only a few explained.
        let junk = format!(r#"{{"kms_keys":[{}0]}}"#, "0,".repeat(10_000));
        let read = read_kms_keys(junk.as_bytes());
        assert_eq!(read.dropped, 10_001);
        assert_eq!(read.reasons.len(), REASONS_KEPT);
    }

    #[test]
    fn only_entries_in_the_form_tapp_server_writes_are_believed() {
        let good = KmsKey::of_secret("ab01", &secret(1)).unwrap();
        assert_eq!(good.problem(), None);
        let other = KmsKey::of_secret("ab01", &secret(2)).unwrap();
        let with = |f: &dyn Fn(&mut KmsKey)| {
            let mut k = good.clone();
            f(&mut k);
            k.problem()
        };
        for (what, broken) in [
            ("0x on material", with(&|k| k.material = "0xab01".into())),
            ("upper-case material", with(&|k| k.material = "AB01".into())),
            ("odd-length material", with(&|k| k.material = "ab0".into())),
            ("escape in material", with(&|k| k.material = "\u{1b}[8m".into())),
            ("over-long material", with(&|k| k.material = "ab".repeat(MAX_MATERIAL_LEN + 1))),
            ("upper-case address", with(&|k| k.address = k.address.to_uppercase().replacen("0X", "0x", 1))),
            ("address without 0x", with(&|k| k.address = k.address[2..].to_string())),
            ("short public key", with(&|k| k.public_key.truncate(20))),
            ("another key's address", with(&|k| k.address = other.address.clone())),
        ] {
            assert!(broken.is_some(), "{what} was accepted");
        }
        // The longest material tapp-server accepts is still a believable entry.
        assert_eq!(with(&|k| k.material = "ab".repeat(MAX_MATERIAL_LEN)), None);
    }

    #[test]
    fn one_material_spelled_two_ways_is_one_material() {
        assert_eq!(normalize_material("0xAB01"), normalize_material("ab01"));
        assert_eq!(normalize_material("0x"), "");
        assert_eq!(normalize_material(""), "");
    }

    #[test]
    fn material_is_checked_as_the_kms_reads_it() {
        assert_eq!(check_material(""), Ok(String::new()));
        assert_eq!(check_material("0x"), Ok(String::new()));
        assert_eq!(check_material("0xAB01"), Ok("ab01".to_string()));
        // The KMS strips every leading 0x, so this is the material ab there too.
        assert_eq!(check_material("0x0xab"), Ok("ab".to_string()));
        assert_eq!(check_material(&"ab".repeat(MAX_MATERIAL_LEN)), Ok("ab".repeat(MAX_MATERIAL_LEN)));
        for refused in ["zz", "abc", "0Xab", " ab", &"ab".repeat(MAX_MATERIAL_LEN + 1)] {
            assert!(check_material(refused).is_err(), "{refused:?} was accepted");
        }
    }

    #[test]
    fn an_address_that_is_not_its_public_keys_is_caught() {
        let mut k = KmsKey::of_secret("", &secret(1)).unwrap();
        assert!(k.is_consistent());
        k.address = KmsKey::of_secret("", &secret(2)).unwrap().address;
        assert!(!k.is_consistent());
        k.public_key = "0xnothex".into();
        assert!(!k.is_consistent());
    }

    #[test]
    fn the_log_keeps_every_key_once_in_material_then_address_order() {
        let mut log = KmsKeyLog::default();
        log.record("a", KmsKey::of_secret("0xAB", &secret(2)).unwrap());
        log.record("a", KmsKey::of_secret("ab", &secret(2)).unwrap()); // same key, other spelling
        log.record("a", KmsKey::of_secret("", &secret(1)).unwrap());
        // The same material from another KMS cluster: a second key, kept beside the first.
        log.record("a", KmsKey::of_secret("ab", &secret(3)).unwrap());
        log.record("b", KmsKey::of_secret("", &secret(4)).unwrap());

        let a = log.of("a");
        let order: Vec<_> = a.iter().map(|k| (k.material.as_str(), k.address.as_str())).collect();
        let mut sorted = order.clone();
        sorted.sort();
        assert_eq!(order, sorted);
        assert_eq!(a.len(), 3, "{a:?}");
        assert_eq!(a.iter().filter(|k| k.material == "ab").count(), 2);
        assert_eq!(log.of("b").len(), 1);
        assert!(log.of("c").is_empty());
    }
}
