//! Fordefi's API, for `--fordefi`: the vault holding the owner key signs once its approval
//! policy has run, and nothing is pasted.
//!
//! Calls are made as a Fordefi *API user*. Fordefi takes a request only when it carries a
//! signature by the API user's own P-256 key over `<path>|<timestamp>|<body>`, so the access
//! token alone cannot make the vault sign; the key is a PEM file on this machine. The
//! settings, and their names, are the ones 0g-fordefi-signer reads, so its `.env` works here
//! unchanged:
//!
//! | variable                   |                                                         |
//! |----------------------------|---------------------------------------------------------|
//! | `FORDEFI_API_USER_TOKEN`   | the API user's access token                             |
//! | `FORDEFI_PRIVATE_KEY_PATH` | the API user's P-256 private key, PEM                   |
//! | `FORDEFI_EVM_VAULT_ID`     | the EVM vault whose address is the signer               |
//! | `FORDEFI_API_HOST`         | optional, default `api.fordefi.com`                     |
//!
//! What comes back is never trusted as it is: a signature must recover to the signer, and a
//! transaction is created with `push_mode: manual` — Fordefi signs and hands it back, and it
//! is checked and broadcast by the caller exactly like a Ledger's.

use std::sync::OnceLock;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ethers::types::{Address, U256};
use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};
use serde_json::{json, Value};

/// Creates a transaction and waits (server side, briefly) for it to reach `wait_for_state`.
const CREATE: &str = "/api/v1/transactions/create-and-wait";

/// How long a transaction may wait for approval and signing before it is aborted. A request
/// signature has a shorter limit of its own: the server's window.
const APPROVAL_WAIT: Duration = Duration::from_secs(30 * 60);

/// States after which nothing will be signed. The others that end a transaction (dropped,
/// canceled, error_pushing_to_blockchain, …) come after a push, which `push_mode: manual`
/// and a message never reach.
const FAILED: &[&str] = &["cannot_create_transaction", "aborted", "error_signing"];

/// What a state means for whoever is waiting. `approved` is where a transaction waits for
/// the API Signer, so one that stays there points at the API Signer, not at Fordefi.
fn describe(state: &str) -> String {
    match state {
        "waiting_for_approval" => "waiting for approval in Fordefi (policy)".to_string(),
        "approved" => "approved; waiting for the API Signer to sign — if this lasts, check that \
                       the API Signer is running"
            .to_string(),
        other => other.replace('_', " "),
    }
}

/// The API user, its key, and the vault it signs with.
pub struct Config {
    base: String,
    token: String,
    vault_id: String,
    key: SigningKey,
    poll: Duration,
}

static CONFIG: OnceLock<Config> = OnceLock::new();

pub(super) fn configure(config: Config) -> Result<()> {
    CONFIG
        .set(config)
        .map_err(|_| anyhow!("Fordefi was already configured"))
}

pub(super) fn config() -> Result<&'static Config> {
    CONFIG
        .get()
        .ok_or_else(|| anyhow!("Fordefi is not configured (use_backend(Backend::Fordefi) first)"))
}

impl Config {
    /// From the environment (see the module documentation). Everything is checked here,
    /// including that the key file holds a P-256 key, so a bad setting stops the command
    /// before anything is asked of Fordefi.
    pub fn from_env() -> Result<Self> {
        let var = |name: &str| {
            std::env::var(name)
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        let token = var("FORDEFI_API_USER_TOKEN")
            .ok_or_else(|| anyhow!("FORDEFI_API_USER_TOKEN is not set (the API user's access token)"))?;
        let vault_id = var("FORDEFI_EVM_VAULT_ID")
            .ok_or_else(|| anyhow!("FORDEFI_EVM_VAULT_ID is not set (the vault whose address signs)"))?;
        let key_path = var("FORDEFI_PRIVATE_KEY_PATH").ok_or_else(|| {
            anyhow!("FORDEFI_PRIVATE_KEY_PATH is not set (the API user's P-256 private key, PEM)")
        })?;
        let pem = std::fs::read_to_string(&key_path)
            .map_err(|e| anyhow!("FORDEFI_PRIVATE_KEY_PATH {}: {}", key_path, e))?;
        let key = parse_key(&pem).map_err(|e| anyhow!("FORDEFI_PRIVATE_KEY_PATH {}: {}", key_path, e))?;
        let host = var("FORDEFI_API_HOST").unwrap_or_else(|| "api.fordefi.com".to_string());
        Ok(Config {
            base: base_url(&host),
            token,
            vault_id,
            key,
            poll: Duration::from_secs(2),
        })
    }

    pub fn vault_id(&self) -> &str {
        &self.vault_id
    }
}

/// `api.fordefi.com` → `https://api.fordefi.com`; a value with a scheme is taken as it is.
fn base_url(host: &str) -> String {
    let host = host.trim().trim_end_matches('/');
    if host.contains("://") {
        host.to_string()
    } else {
        format!("https://{host}")
    }
}

/// The API user's key, as `openssl ecparam -name prime256v1 -genkey` writes it (SEC1,
/// `EC PRIVATE KEY`) or as PKCS#8 (`PRIVATE KEY`).
fn parse_key(pem: &str) -> Result<SigningKey> {
    use p256::pkcs8::DecodePrivateKey;
    if let Ok(secret) = p256::SecretKey::from_sec1_pem(pem) {
        return Ok(secret.into());
    }
    SigningKey::from_pkcs8_pem(pem)
        .map_err(|_| anyhow!("not a P-256 private key in PEM (EC PRIVATE KEY or PRIVATE KEY)"))
}

/// The `x-signature` header: ECDSA P-256 / SHA-256 over `<path>|<timestamp>|<body>`, DER,
/// base64. The timestamp is in milliseconds, as Fordefi's authentication page specifies
/// (0g-fordefi-signer sends seconds).
fn sign_request(key: &SigningKey, path: &str, timestamp: i64, body: &str) -> String {
    let signature: Signature = key.sign(format!("{path}|{timestamp}|{body}").as_bytes());
    BASE64.encode(signature.to_der().as_bytes())
}

/// What Fordefi said, in one line: its `detail` or `title` when the answer is its JSON error,
/// else the start of the text.
fn error_text(text: &str) -> String {
    if let Ok(v) = serde_json::from_str::<Value>(text) {
        for field in ["detail", "title", "message"] {
            if let Some(s) = v.get(field).and_then(Value::as_str) {
                return s.to_string();
            }
        }
    }
    text.chars().take(300).collect()
}

async fn call(config: &Config, method: reqwest::Method, path: &str, body: Option<&Value>) -> Result<Value> {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    let client = CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .unwrap_or_default()
    });
    let body = body.map(Value::to_string).unwrap_or_default();
    let timestamp = chrono::Utc::now().timestamp_millis();
    let mut request = client
        .request(method, format!("{}{}", config.base, path))
        .bearer_auth(&config.token)
        .header("x-timestamp", timestamp.to_string())
        .header("x-signature", sign_request(&config.key, path, timestamp, &body));
    if !body.is_empty() {
        request = request.header("content-type", "application/json").body(body);
    }
    let response = request.send().await.map_err(|e| anyhow!("Fordefi {}: {}", path, e))?;
    let status = response.status();
    let text = response.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(anyhow!("Fordefi {}: {} — {}", path, status, error_text(&text)));
    }
    serde_json::from_str(&text).map_err(|e| anyhow!("Fordefi {}: the answer is not JSON ({})", path, e))
}

/// A transaction's state, which Fordefi gives either as a string or as `{"status": …}`.
fn state_of(tx: &Value) -> &str {
    match tx.get("state") {
        Some(Value::String(s)) => s,
        Some(v) => v.get("status").and_then(Value::as_str).unwrap_or("unknown"),
        None => "unknown",
    }
}

/// The first signature of a signed message, decoded (`signatures[0].data`, base64).
fn signature_of(tx: &Value) -> Option<Result<Vec<u8>>> {
    let first = tx.get("signatures")?.as_array()?.first()?;
    let b64 = first.get("data").and_then(Value::as_str).or_else(|| first.as_str())?;
    Some(
        BASE64
            .decode(b64)
            .map_err(|e| anyhow!("its signature is not base64: {}", e)),
    )
}

/// The signed transaction of a `push_mode: manual` transaction (`raw_transaction`, 0x-hex).
fn raw_transaction_of(tx: &Value) -> Option<Result<Vec<u8>>> {
    let raw = tx.get("raw_transaction")?.as_str().filter(|s| !s.is_empty())?;
    Some(match raw.strip_prefix("0x") {
        Some(hex_str) => hex::decode(hex_str).map_err(|e| anyhow!("its raw_transaction is not hex: {}", e)),
        None => BASE64
            .decode(raw)
            .map_err(|_| anyhow!("its raw_transaction is neither 0x-hex nor base64")),
    })
}

/// A request for a `personal_sign` (EIP-191) of `message`. A personal message is not tied to
/// a chain; the chain only tells Fordefi which kind of vault signs it.
fn message_request(vault_id: &str, message: &str, note: &str) -> Value {
    json!({
        "vault_id": vault_id,
        "signer_type": "api_signer",
        "type": "evm_message",
        "details": {
            "type": "personal_message_type",
            "raw_data": format!("0x{}", hex::encode(message.as_bytes())),
            "chain": "ethereum_mainnet",
        },
        "note": note,
        "wait_for_state": "signed",
    })
}

/// A request to sign, not send, a legacy contract call.
#[allow(clippy::too_many_arguments)]
fn transaction_request(
    vault_id: &str,
    chain: &str,
    to: &Address,
    data: &[u8],
    value: U256,
    gas: U256,
    gas_price: U256,
    note: &str,
) -> Value {
    json!({
        "vault_id": vault_id,
        "signer_type": "api_signer",
        "sign_mode": "auto",
        "type": "evm_transaction",
        "details": {
            "type": "evm_raw_transaction",
            "push_mode": "manual",
            "chain": chain,
            "to": format!("0x{:x}", to),
            "value": value.to_string(),
            "data": { "type": "hex", "hex_data": format!("0x{}", hex::encode(data)) },
            "gas": {
                "type": "custom",
                "gas_limit": gas.to_string(),
                "details": { "type": "legacy", "price": gas_price.to_string() },
            },
        },
        "note": note,
        "wait_for_state": "signed",
    })
}

/// Fordefi's id for an EVM chain: `evm_<chain id>`, for its built-in chains (0G mainnet is
/// `evm_16661`) and for custom ones alike.
fn chain_unique_id(chain_id: u64) -> String {
    format!("evm_{chain_id}")
}

enum Waited<T> {
    Done(T),
    TimedOut,
}

/// Follow a created transaction until `ready` finds what was asked for in it, it fails, or
/// `until` passes — then it is aborted, so nobody approves something no longer waited for.
async fn wait_for<T>(
    config: &Config,
    created: Value,
    until: Instant,
    ready: impl Fn(&Value) -> Option<Result<T>>,
) -> Result<Waited<T>> {
    let id = created
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("Fordefi did not say which transaction it created"))?
        .to_string();
    eprintln!("  Fordefi transaction {id}");
    let mut tx = created;
    let mut shown = String::new();
    loop {
        if let Some(found) = ready(&tx) {
            return found
                .map(Waited::Done)
                .map_err(|e| anyhow!("Fordefi transaction {}: {}", id, e));
        }
        let state = state_of(&tx).to_string();
        if FAILED.contains(&state.as_str()) {
            return Err(anyhow!("Fordefi transaction {} ended {}", id, state));
        }
        if state != shown {
            eprintln!("  … {}", describe(&state));
            shown = state;
        }
        if Instant::now() >= until {
            let path = format!("/api/v1/transactions/{id}/abort");
            if let Err(e) = call(config, reqwest::Method::POST, &path, None).await {
                eprintln!("  (aborting {id}: {e})");
            }
            return Ok(Waited::TimedOut);
        }
        tokio::time::sleep(config.poll).await;
        let path = format!("/api/v1/transactions/{id}");
        match call(config, reqwest::Method::GET, &path, None).await {
            Ok(v) => tx = v,
            Err(e) => eprintln!("  (reading {id}: {e}; retrying)"),
        }
    }
}

/// When to stop waiting for a request signature: its deadline, as an instant.
fn deadline(valid_until: Option<i64>) -> Instant {
    match valid_until {
        Some(t) => {
            let left = t - chrono::Utc::now().timestamp();
            Instant::now() + Duration::from_secs(left.max(0) as u64)
        }
        None => Instant::now() + APPROVAL_WAIT,
    }
}

/// Have the vault `personal_sign` `message`. Returns the signature as Fordefi gave it; the
/// caller normalises it and checks who made it. Past `valid_until` the request is aborted
/// and [`super::Expired`] returned.
pub(super) async fn sign_message(
    config: &Config,
    message: &str,
    what: &str,
    valid_until: Option<i64>,
) -> Result<Vec<u8>> {
    let request = message_request(&config.vault_id, message, &format!("tapp-cli: {what}"));
    let created = call(config, reqwest::Method::POST, CREATE, Some(&request)).await?;
    match wait_for(config, created, deadline(valid_until), signature_of).await? {
        Waited::Done(sig) => Ok(sig),
        Waited::TimedOut if valid_until.is_some() => Err(super::Expired.into()),
        Waited::TimedOut => Err(anyhow!(
            "not signed within {} min; the Fordefi transaction was aborted",
            APPROVAL_WAIT.as_secs() / 60
        )),
    }
}

/// Have the vault sign, not send, a contract call. Returns the signed transaction for the
/// caller to check and broadcast.
#[allow(clippy::too_many_arguments)]
pub(super) async fn sign_transaction(
    config: &Config,
    chain_id: u64,
    to: &Address,
    data: &[u8],
    value: U256,
    gas: U256,
    gas_price: U256,
    what: &str,
) -> Result<Vec<u8>> {
    let chain = chain_unique_id(chain_id);
    let request = transaction_request(
        &config.vault_id,
        &chain,
        to,
        data,
        value,
        gas,
        gas_price,
        &format!("tapp-cli: {what}"),
    );
    let created = call(config, reqwest::Method::POST, CREATE, Some(&request))
        .await
        .map_err(|e| {
            anyhow!(
                "{} (chain {} — one Fordefi does not support out of the box must be added to the \
                 organisation as a custom chain: Settings > Chains > Add EVM chain)",
                e,
                chain
            )
        })?;
    match wait_for(config, created, Instant::now() + APPROVAL_WAIT, raw_transaction_of).await? {
        Waited::Done(raw) => Ok(raw),
        Waited::TimedOut => Err(anyhow!(
            "not signed within {} min; the Fordefi transaction was aborted",
            APPROVAL_WAIT.as_secs() / 60
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::signers::{LocalWallet, Signer as _};
    use ethers::types::transaction::eip2718::TypedTransaction;
    use ethers::types::TransactionRequest;
    use p256::ecdsa::{signature::Verifier as _, VerifyingKey};
    use std::io::{BufRead, BufReader, Read, Write};
    use std::sync::{Arc, Mutex};

    const WALLET: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

    fn api_key() -> SigningKey {
        SigningKey::from_slice(&[7u8; 32]).unwrap()
    }

    fn config(base: String) -> Config {
        Config {
            base,
            token: "token".into(),
            vault_id: "vault-1".into(),
            key: api_key(),
            poll: Duration::from_millis(10),
        }
    }

    /// Does `x-signature` verify, with `key`, over `<path>|<x-timestamp>|<body>`?
    fn verifies(key: &VerifyingKey, path: &str, timestamp: &str, body: &str, signature: &str) -> bool {
        let Ok(der) = BASE64.decode(signature) else { return false };
        let Ok(sig) = Signature::from_der(&der) else { return false };
        key.verify(format!("{path}|{timestamp}|{body}").as_bytes(), &sig).is_ok()
    }

    /// A stand-in for Fordefi on 127.0.0.1: refuses a request whose x-signature does not
    /// verify with the API user's key, otherwise answers with `answer(method, path, body)`.
    /// Returns its base URL and the requests it took, as "METHOD path".
    fn fordefi(
        answer: impl Fn(&str, &str, &str) -> Value + Send + 'static,
    ) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        let key = VerifyingKey::from(&api_key());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let mut parts = line.split_whitespace();
                let (method, path) = (parts.next().unwrap().to_string(), parts.next().unwrap().to_string());
                let (mut length, mut timestamp, mut signature, mut bearer) = (0, String::new(), String::new(), String::new());
                loop {
                    let mut header = String::new();
                    reader.read_line(&mut header).unwrap();
                    let header = header.trim_end();
                    if header.is_empty() {
                        break;
                    }
                    let (name, value) = header.split_once(':').unwrap();
                    let value = value.trim().to_string();
                    match name.to_ascii_lowercase().as_str() {
                        "content-length" => length = value.parse().unwrap(),
                        "x-timestamp" => timestamp = value,
                        "x-signature" => signature = value,
                        "authorization" => bearer = value,
                        _ => {}
                    }
                }
                let mut body = vec![0u8; length];
                reader.read_exact(&mut body).unwrap();
                let body = String::from_utf8(body).unwrap();
                log.lock().unwrap().push(format!("{method} {path}"));
                let (status, reply) = if bearer != "Bearer token" || !verifies(&key, &path, &timestamp, &body, &signature) {
                    ("401 Unauthorized", json!({"title": "bad request signature"}))
                } else {
                    ("200 OK", answer(&method, &path, &body))
                };
                let reply = reply.to_string();
                write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                    reply.len()
                )
                .unwrap();
            }
        });
        (base, seen)
    }

    /// What the vault would return for a personal message: the wallet's signature, base64.
    fn signed_message(body: &str) -> Value {
        let request: Value = serde_json::from_str(body).unwrap();
        let raw = request["details"]["raw_data"].as_str().unwrap();
        let message = String::from_utf8(hex::decode(raw.trim_start_matches("0x")).unwrap()).unwrap();
        let wallet: LocalWallet = WALLET.parse().unwrap();
        let sig = wallet.sign_hash(ethers::utils::hash_message(&message)).unwrap();
        json!({"id": "tx-1", "state": "signed", "signatures": [{"data": BASE64.encode(sig.to_vec())}]})
    }

    #[test]
    fn a_request_is_signed_over_path_timestamp_and_body() {
        let key = api_key();
        let signature = sign_request(&key, CREATE, 1_760_000_000_000, "{\"a\":1}");
        let verifying = VerifyingKey::from(&key);
        assert!(verifies(&verifying, CREATE, "1760000000000", "{\"a\":1}", &signature));
        assert!(!verifies(&verifying, CREATE, "1760000000000", "{\"a\":2}", &signature), "other body");
        assert!(!verifies(&verifying, CREATE, "1760000000001", "{\"a\":1}", &signature), "other time");
        assert!(!verifies(&verifying, "/api/v1/transactions", "1760000000000", "{\"a\":1}", &signature), "other path");
    }

    /// `openssl ecparam -genkey` writes SEC1; other tools write PKCS#8. Both are read.
    #[test]
    fn the_api_users_key_is_read_from_either_pem_form() {
        use p256::pkcs8::{EncodePrivateKey, LineEnding};
        let secret = p256::SecretKey::from_slice(&[7u8; 32]).unwrap();
        let sec1 = secret.to_sec1_pem(LineEnding::LF).unwrap();
        let pkcs8 = secret.to_pkcs8_pem(LineEnding::LF).unwrap();
        assert_eq!(parse_key(&sec1).unwrap(), api_key());
        assert_eq!(parse_key(&pkcs8).unwrap(), api_key());
        assert!(parse_key("-----BEGIN EC PRIVATE KEY-----\nnope\n-----END EC PRIVATE KEY-----").is_err());
    }

    #[test]
    fn the_host_becomes_a_url() {
        assert_eq!(base_url("api.fordefi.com"), "https://api.fordefi.com");
        assert_eq!(base_url("api.fordefi.com/"), "https://api.fordefi.com");
        assert_eq!(base_url("http://127.0.0.1:8080"), "http://127.0.0.1:8080");
    }

    #[test]
    fn a_message_request_carries_the_text_as_hex() {
        let request = message_request("vault-1", "StartApp:0x00ff:1791400000", "tapp-cli: StartApp");
        assert_eq!(request["vault_id"], "vault-1");
        assert_eq!(request["signer_type"], "api_signer");
        assert_eq!(request["type"], "evm_message");
        assert_eq!(request["details"]["type"], "personal_message_type");
        assert_eq!(
            request["details"]["raw_data"],
            format!("0x{}", hex::encode("StartApp:0x00ff:1791400000"))
        );
        assert_eq!(request["wait_for_state"], "signed");
    }

    #[test]
    fn a_transaction_request_is_signed_only() {
        let to: Address = "0x5f0d9c243048F5a55468472c6F090184E2E333c7".parse().unwrap();
        let request = transaction_request(
            "vault-1",
            "evm_16661",
            &to,
            &[0x81, 0x73],
            U256::from(10u64).pow(U256::from(18u64)),
            U256::from(120_000u64),
            U256::from(4_000_000_000u64),
            "note",
        );
        let details = &request["details"];
        assert_eq!(details["push_mode"], "manual", "Fordefi must not broadcast");
        assert_eq!(details["type"], "evm_raw_transaction");
        assert_eq!(details["chain"], "evm_16661");
        assert_eq!(details["to"], "0x5f0d9c243048f5a55468472c6f090184e2e333c7");
        assert_eq!(details["value"], "1000000000000000000");
        assert_eq!(details["data"]["hex_data"], "0x8173");
        assert_eq!(details["gas"]["gas_limit"], "120000");
        assert_eq!(details["gas"]["details"]["price"], "4000000000");
    }

    #[test]
    fn answers_are_read_in_the_shapes_fordefi_uses() {
        assert_eq!(state_of(&json!({"state": "signed"})), "signed");
        assert_eq!(state_of(&json!({"state": {"status": "approved"}})), "approved");
        assert_eq!(state_of(&json!({})), "unknown");

        let sig = signature_of(&json!({"signatures": [{"data": BASE64.encode([1u8, 2, 3])}]}));
        assert_eq!(sig.unwrap().unwrap(), vec![1, 2, 3]);
        assert!(signature_of(&json!({"signatures": []})).is_none());
        assert!(signature_of(&json!({"signatures": [{"data": "%%"}]})).unwrap().is_err());

        assert_eq!(raw_transaction_of(&json!({"raw_transaction": "0x0102"})).unwrap().unwrap(), vec![1, 2]);
        assert_eq!(
            raw_transaction_of(&json!({"raw_transaction": BASE64.encode([1u8, 2])})).unwrap().unwrap(),
            vec![1, 2]
        );
        assert!(raw_transaction_of(&json!({"raw_transaction": ""})).is_none());
        assert!(raw_transaction_of(&json!({"state": "approved"})).is_none());
    }

    /// The chain id read from the RPC is all Fordefi needs: no table of names to keep.
    #[test]
    fn a_chain_is_named_by_its_id() {
        assert_eq!(chain_unique_id(16661), "evm_16661");
        assert_eq!(chain_unique_id(16602), "evm_16602");
    }

    /// Created waiting for approval, then signed: the signature is followed to the end.
    #[tokio::test]
    async fn a_message_is_followed_until_the_vault_has_signed_it() {
        let created: Arc<Mutex<String>> = Arc::default();
        let reads = Arc::new(Mutex::new(0));
        let (c, r) = (created.clone(), reads.clone());
        let (base, seen) = fordefi(move |method, _path, body| {
            if method == "POST" {
                *c.lock().unwrap() = body.to_string();
                return json!({"id": "tx-1", "state": "waiting_for_approval", "has_timed_out": true});
            }
            let mut n = r.lock().unwrap();
            *n += 1;
            if *n < 2 {
                json!({"id": "tx-1", "state": {"status": "approved"}})
            } else {
                signed_message(&c.lock().unwrap())
            }
        });
        let message = "StartApp:0x00ff:1791400000";
        let raw = sign_message(&config(base), message, "StartApp", None).await.unwrap();
        let sig = super::super::parse_signature(&hex::encode(raw)).unwrap();
        let wallet: LocalWallet = WALLET.parse().unwrap();
        assert_eq!(super::super::recover_personal(message, &sig).unwrap(), wallet.address());
        let seen = seen.lock().unwrap();
        assert_eq!(seen[0], format!("POST {CREATE}"));
        assert!(seen[1..].iter().all(|s| s == "GET /api/v1/transactions/tx-1"), "{seen:?}");
    }

    /// The vault signs a transaction it is asked for and hands it back unsent; what comes
    /// back passes the same check a Ledger's does.
    #[tokio::test]
    async fn a_transaction_comes_back_signed_and_unsent() {
        let (base, _) = fordefi(|_, _, body| {
            let request: Value = serde_json::from_str(body).unwrap();
            let d = &request["details"];
            assert_eq!(d["push_mode"], "manual");
            assert_eq!(d["chain"], "evm_16661");
            let wallet: LocalWallet = WALLET.parse::<LocalWallet>().unwrap().with_chain_id(16661u64);
            let tx: TypedTransaction = TransactionRequest::new()
                .from(wallet.address())
                .to(d["to"].as_str().unwrap().parse::<Address>().unwrap())
                .data(hex::decode(d["data"]["hex_data"].as_str().unwrap().trim_start_matches("0x")).unwrap())
                .value(U256::from_dec_str(d["value"].as_str().unwrap()).unwrap())
                .gas(U256::from_dec_str(d["gas"]["gas_limit"].as_str().unwrap()).unwrap())
                .gas_price(U256::from_dec_str(d["gas"]["details"]["price"].as_str().unwrap()).unwrap())
                .nonce(3)
                .chain_id(16661u64)
                .into();
            let sig = wallet.sign_transaction_sync(&tx).unwrap();
            json!({"id": "tx-2", "state": "signed", "raw_transaction": format!("0x{}", hex::encode(tx.rlp_signed(&sig)))})
        });
        let wallet: LocalWallet = WALLET.parse().unwrap();
        let from = wallet.address();
        let to: Address = "0x5f0d9c243048F5a55468472c6F090184E2E333c7".parse().unwrap();
        let data = vec![0x81, 0x73, 0x0e, 0xad];
        let value = U256::from(5u64);
        let raw = sign_transaction(&config(base), 16661, &to, &data, value, U256::from(90_000u64), U256::from(4_000_000_000u64), "addNode")
            .await
            .unwrap();
        super::super::check_signed_transaction(&raw, 16661, &from, &to, &data, value).unwrap();
    }

    #[tokio::test]
    async fn an_aborted_transaction_ends_the_wait() {
        let (base, _) = fordefi(|method, _, _| {
            if method == "POST" {
                json!({"id": "tx-3", "state": "waiting_for_approval"})
            } else {
                json!({"id": "tx-3", "state": "aborted"})
            }
        });
        let e = sign_message(&config(base), "StopApp:0x00:1", "StopApp", None).await.unwrap_err();
        assert!(e.to_string().contains("aborted"), "{e}");
    }

    /// A request signature not given before the server's deadline is of no use: the Fordefi
    /// transaction is aborted, so nobody approves it later, and the caller asks again.
    #[tokio::test]
    async fn past_the_deadline_the_request_is_aborted() {
        let (base, seen) = fordefi(|_, path, _| {
            if path.ends_with("/abort") {
                json!({})
            } else {
                json!({"id": "tx-4", "state": "waiting_for_approval"})
            }
        });
        let now = chrono::Utc::now().timestamp();
        let e = sign_message(&config(base), "StopApp:0x00:1", "StopApp", Some(now)).await.unwrap_err();
        assert!(e.downcast_ref::<super::super::Expired>().is_some(), "{e}");
        assert!(seen.lock().unwrap().contains(&"POST /api/v1/transactions/tx-4/abort".to_string()));
    }

    #[tokio::test]
    async fn a_refused_request_says_what_fordefi_said() {
        let (base, _) = fordefi(|_, _, _| json!({}));
        let mut bad = config(base);
        bad.token = "wrong".into();
        let e = sign_message(&bad, "StopApp:0x00:1", "StopApp", None).await.unwrap_err().to_string();
        assert!(e.contains("401") && e.contains("bad request signature"), "{e}");
    }
}
