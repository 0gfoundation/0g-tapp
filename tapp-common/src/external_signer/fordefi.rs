//! A Fordefi vault, for `--fordefi`, reached through 0g-fordefi-signer: the vault holding the
//! owner key signs once Fordefi's approval policy has run, and nothing is pasted.
//!
//! The Fordefi API user's credentials (its token and P-256 key) stay with the service; what
//! this machine holds is the service's address and a token that names this caller to it, and
//! which the service can revoke. The service also decides what the vault may sign — which
//! contracts, which messages — on top of Fordefi's own policy.
//!
//! | variable               |                                                              |
//! |------------------------|--------------------------------------------------------------|
//! | `FORDEFI_SIGNER_URL`   | the service, `https://…` (plain `http://` only on loopback)  |
//! | `FORDEFI_SIGNER_TOKEN` | this caller's token for it                                   |
//!
//! What comes back is never trusted as it is: a signature must recover to the signer, and a
//! transaction is signed only — handed back, checked, and broadcast from here exactly like a
//! Ledger's.

use std::sync::OnceLock;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use ethers::types::{Address, U256};
use serde_json::{json, Value};

/// How long a transaction may wait for approval and signing before it is aborted. A request
/// signature has a shorter limit of its own: the server's window.
const APPROVAL_WAIT: Duration = Duration::from_secs(30 * 60);

/// What a Fordefi state means for whoever is waiting. `approved` is where a request waits for
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

/// The service and this caller's token for it.
pub struct Config {
    base: String,
    token: String,
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
    /// From the environment (see the module documentation), checked here so a bad setting
    /// stops the command before anything is asked for.
    pub fn from_env() -> Result<Self> {
        let var = |name: &str| {
            std::env::var(name)
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        let url = var("FORDEFI_SIGNER_URL")
            .ok_or_else(|| anyhow!("FORDEFI_SIGNER_URL is not set (the 0g-fordefi-signer service)"))?;
        let token = var("FORDEFI_SIGNER_TOKEN")
            .ok_or_else(|| anyhow!("FORDEFI_SIGNER_TOKEN is not set (this caller's token for the service)"))?;
        Ok(Config {
            base: base_url(&url)?,
            token,
            poll: Duration::from_secs(2),
        })
    }

    /// The service, for showing where a signature is asked for.
    pub fn url(&self) -> &str {
        &self.base
    }
}

/// The service's base URL. The token travels on every call, so plain HTTP is taken only to
/// this machine (an SSH tunnel, say).
fn base_url(url: &str) -> Result<String> {
    let url = url.trim().trim_end_matches('/');
    let parsed = reqwest::Url::parse(url).map_err(|e| anyhow!("FORDEFI_SIGNER_URL {}: {}", url, e))?;
    let loopback = match parsed.host_str() {
        Some("localhost") => true,
        Some(host) => host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback()),
        None => false,
    };
    match parsed.scheme() {
        "https" => Ok(url.to_string()),
        "http" if loopback => Ok(url.to_string()),
        "http" => Err(anyhow!(
            "FORDEFI_SIGNER_URL {}: the token would cross the network in the clear; use https \
             (or an SSH tunnel to http://127.0.0.1)",
            url
        )),
        other => Err(anyhow!("FORDEFI_SIGNER_URL {}: {} is not http(s)", url, other)),
    }
}

/// A call the service answered with an error status.
#[derive(Debug)]
struct Refused {
    path: String,
    status: reqwest::StatusCode,
    text: String,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "fordefi signer {}: {} — {}", self.path, self.status, self.text)?;
        if self.status == reqwest::StatusCode::UNAUTHORIZED {
            write!(f, " (the service does not take FORDEFI_SIGNER_TOKEN)")?;
        }
        Ok(())
    }
}

impl std::error::Error for Refused {}

/// What the service said, in one line: its `error`, else the start of the text.
fn error_text(text: &str) -> String {
    if let Ok(v) = serde_json::from_str::<Value>(text) {
        for field in ["error", "detail", "title", "message"] {
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
            .timeout(Duration::from_secs(90))
            .build()
            .unwrap_or_default()
    });
    let mut request = client
        .request(method, format!("{}{}", config.base, path))
        .bearer_auth(&config.token);
    if let Some(body) = body {
        request = request.json(body);
    }
    let response = request.send().await.map_err(|e| anyhow!("fordefi signer {}: {}", path, e))?;
    let status = response.status();
    let text = response.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(Refused { path: path.to_string(), status, text: error_text(&text) }.into());
    }
    serde_json::from_str(&text).map_err(|e| anyhow!("fordefi signer {}: the answer is not JSON ({})", path, e))
}

/// A field of the service's answer about a request.
fn field<'a>(request: &'a Value, name: &str) -> &'a str {
    request.get(name).and_then(Value::as_str).unwrap_or("")
}

/// `0x…` from the service, decoded.
fn hex_field(request: &Value, name: &str) -> Result<Vec<u8>> {
    let s = field(request, name);
    let digits = s.strip_prefix("0x").ok_or_else(|| anyhow!("its {} is not 0x-hex", name))?;
    hex::decode(digits).map_err(|e| anyhow!("its {} is not hex: {}", name, e))
}

enum Waited<T> {
    Done(T),
    TimedOut,
}

/// Follow a request until it is signed, it fails, or `until` passes — then it is aborted, so
/// nobody approves something no longer waited for. `result` is the field that holds what was
/// asked for once `outcome` is `signed`.
async fn wait_for(config: &Config, created: Value, until: Instant, result: &str) -> Result<Waited<Vec<u8>>> {
    let id = field(&created, "id").to_string();
    if id.is_empty() {
        return Err(anyhow!("the service did not say which request it made"));
    }
    eprintln!("  Fordefi request {id}");
    let mut request = created;
    let mut shown = String::new();
    loop {
        let state = field(&request, "state").to_string();
        match field(&request, "outcome") {
            "signed" => {
                return hex_field(&request, result)
                    .map(Waited::Done)
                    .map_err(|e| anyhow!("Fordefi request {}: {}", id, e))
            }
            "failed" => return Err(anyhow!("Fordefi request {} ended {}", id, state)),
            _ => {}
        }
        if state != shown {
            eprintln!("  … {}", describe(&state));
            shown = state;
        }
        if Instant::now() >= until {
            let path = format!("/v1/requests/{id}/abort");
            if let Err(e) = call(config, reqwest::Method::POST, &path, None).await {
                eprintln!("  (aborting {id}: {e})");
            }
            return Ok(Waited::TimedOut);
        }
        tokio::time::sleep(config.poll).await;
        let path = format!("/v1/requests/{id}");
        match call(config, reqwest::Method::GET, &path, None).await {
            Ok(v) => request = v,
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

/// Have the vault `personal_sign` `message`. Returns the signature as it came; the caller
/// normalises it and checks who made it. Past `valid_until` the request is aborted and
/// [`super::Expired`] returned.
pub(super) async fn sign_message(
    config: &Config,
    message: &str,
    what: &str,
    valid_until: Option<i64>,
) -> Result<Vec<u8>> {
    let body = json!({ "message": message, "note": format!("tapp-cli: {what}") });
    let created = call(config, reqwest::Method::POST, "/v1/messages", Some(&body)).await?;
    match wait_for(config, created, deadline(valid_until), "signature").await? {
        Waited::Done(sig) => Ok(sig),
        Waited::TimedOut if valid_until.is_some() => Err(super::Expired.into()),
        Waited::TimedOut => Err(anyhow!(
            "not signed within {} min; the Fordefi request was aborted",
            APPROVAL_WAIT.as_secs() / 60
        )),
    }
}

/// The body asking the vault to sign, not send, a legacy contract call. Amounts are decimal
/// strings: wei does not fit the double a JSON number becomes.
#[allow(clippy::too_many_arguments)]
fn transaction_body(chain_id: u64, to: &Address, data: &[u8], value: U256, gas: U256, gas_price: U256, what: &str) -> Value {
    json!({
        "chain_id": chain_id,
        "to": format!("0x{:x}", to),
        "data": format!("0x{}", hex::encode(data)),
        "value": value.to_string(),
        "gas_limit": gas.to_string(),
        "gas_price": gas_price.to_string(),
        "note": format!("tapp-cli: {what}"),
    })
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
    let body = transaction_body(chain_id, to, data, value, gas, gas_price, what);
    let created = call(config, reqwest::Method::POST, "/v1/transactions", Some(&body))
        .await
        .map_err(|e| match e.downcast_ref::<Refused>() {
            // 502: Fordefi itself refused, most often over a chain it does not know.
            Some(r) if r.status == reqwest::StatusCode::BAD_GATEWAY => anyhow!(
                "{} (a chain Fordefi does not support out of the box — the 0G testnet, for one — \
                 must be added to the organisation: Settings > Chains > Add EVM chain)",
                e
            ),
            _ => e,
        })?;
    match wait_for(config, created, Instant::now() + APPROVAL_WAIT, "raw_transaction").await? {
        Waited::Done(raw) => Ok(raw),
        Waited::TimedOut => Err(anyhow!(
            "not signed within {} min; the Fordefi request was aborted",
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
    use std::io::{BufRead, BufReader, Read, Write};
    use std::sync::{Arc, Mutex};

    const WALLET: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

    fn config(base: String) -> Config {
        Config {
            base,
            token: "token".into(),
            poll: Duration::from_millis(10),
        }
    }

    /// A stand-in for the service on 127.0.0.1: refuses a call without the token, otherwise
    /// answers with `answer(method, path, body)` → (status, body). Returns its base URL and
    /// the calls it took, as "METHOD path".
    fn service(
        answer: impl Fn(&str, &str, &str) -> (u16, Value) + Send + 'static,
    ) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let mut parts = line.split_whitespace();
                let (method, path) = (parts.next().unwrap().to_string(), parts.next().unwrap().to_string());
                let (mut length, mut bearer) = (0, String::new());
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
                        "authorization" => bearer = value,
                        _ => {}
                    }
                }
                let mut body = vec![0u8; length];
                reader.read_exact(&mut body).unwrap();
                let body = String::from_utf8(body).unwrap();
                log.lock().unwrap().push(format!("{method} {path}"));
                let (status, reply) = if bearer != "Bearer token" {
                    (401, json!({"error": "a valid bearer token is required"}))
                } else {
                    answer(&method, &path, &body)
                };
                let reply = reply.to_string();
                write!(
                    stream,
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                    reply.len()
                )
                .unwrap();
            }
        });
        (base, seen)
    }

    /// What the service returns for a signed message: the wallet's signature, 0x-hex.
    fn signed_message(body: &str) -> Value {
        let request: Value = serde_json::from_str(body).unwrap();
        let message = request["message"].as_str().unwrap();
        let wallet: LocalWallet = WALLET.parse().unwrap();
        let sig = wallet.sign_hash(ethers::utils::hash_message(message)).unwrap();
        json!({"id": "r-1", "state": "signed", "outcome": "signed", "signature": format!("0x{}", hex::encode(sig.to_vec()))})
    }

    #[test]
    fn the_token_goes_only_over_tls_or_to_this_machine() {
        assert_eq!(base_url("https://signer.example/").unwrap(), "https://signer.example");
        assert_eq!(base_url("http://127.0.0.1:5000").unwrap(), "http://127.0.0.1:5000");
        assert_eq!(base_url("http://localhost:5000").unwrap(), "http://localhost:5000");
        assert_eq!(base_url("http://[::1]:5000").unwrap(), "http://[::1]:5000");
        assert!(base_url("http://10.0.0.5:5000").is_err());
        assert!(base_url("http://signer.example").is_err());
        assert!(base_url("ftp://signer.example").is_err());
        assert!(base_url("signer.example").is_err());
    }

    #[test]
    fn a_transaction_is_asked_for_in_decimal_strings() {
        let to: Address = "0x5f0d9c243048F5a55468472c6F090184E2E333c7".parse().unwrap();
        let body = transaction_body(
            16661,
            &to,
            &[0x81, 0x73],
            U256::from(10u64).pow(U256::from(21u64)),
            U256::from(120_000u64),
            U256::from(4_000_000_000u64),
            "addNode",
        );
        assert_eq!(
            body,
            json!({
                "chain_id": 16661,
                "to": "0x5f0d9c243048f5a55468472c6f090184e2e333c7",
                "data": "0x8173",
                "value": "1000000000000000000000",
                "gas_limit": "120000",
                "gas_price": "4000000000",
                "note": "tapp-cli: addNode",
            })
        );
    }

    /// Created waiting for approval, then signed: the request is followed to the end.
    #[tokio::test]
    async fn a_message_is_followed_until_the_vault_has_signed_it() {
        let created: Arc<Mutex<String>> = Arc::default();
        let reads = Arc::new(Mutex::new(0));
        let (c, r) = (created.clone(), reads.clone());
        let (base, seen) = service(move |method, _path, body| {
            if method == "POST" {
                *c.lock().unwrap() = body.to_string();
                return (200, json!({"id": "r-1", "state": "waiting_for_approval", "outcome": "pending"}));
            }
            let mut n = r.lock().unwrap();
            *n += 1;
            if *n < 2 {
                (200, json!({"id": "r-1", "state": "approved", "outcome": "pending"}))
            } else {
                (200, signed_message(&c.lock().unwrap()))
            }
        });
        let message = "StartApp:0x00ff:1791400000";
        let raw = sign_message(&config(base), message, "StartApp", None).await.unwrap();
        let sig = super::super::parse_signature(&hex::encode(raw)).unwrap();
        let wallet: LocalWallet = WALLET.parse().unwrap();
        assert_eq!(super::super::recover_personal(message, &sig).unwrap(), wallet.address());
        let sent: Value = serde_json::from_str(&created.lock().unwrap()).unwrap();
        assert_eq!(sent, json!({"message": message, "note": "tapp-cli: StartApp"}));
        let seen = seen.lock().unwrap();
        assert_eq!(seen[0], "POST /v1/messages");
        assert!(seen[1..].iter().all(|s| s == "GET /v1/requests/r-1"), "{seen:?}");
    }

    /// The vault signs a transaction it is asked for and hands it back unsent; what comes
    /// back passes the same check a Ledger's does.
    #[tokio::test]
    async fn a_transaction_comes_back_signed_and_unsent() {
        let (base, seen) = service(|_, _, body| {
            let d: Value = serde_json::from_str(body).unwrap();
            let wallet: LocalWallet = WALLET.parse::<LocalWallet>().unwrap().with_chain_id(16661u64);
            let tx: TypedTransaction = TransactionRequest::new()
                .from(wallet.address())
                .to(d["to"].as_str().unwrap().parse::<Address>().unwrap())
                .data(hex::decode(d["data"].as_str().unwrap().trim_start_matches("0x")).unwrap())
                .value(U256::from_dec_str(d["value"].as_str().unwrap()).unwrap())
                .gas(U256::from_dec_str(d["gas_limit"].as_str().unwrap()).unwrap())
                .gas_price(U256::from_dec_str(d["gas_price"].as_str().unwrap()).unwrap())
                .nonce(3)
                .chain_id(d["chain_id"].as_u64().unwrap())
                .into();
            let sig = wallet.sign_transaction_sync(&tx).unwrap();
            let raw = format!("0x{}", hex::encode(tx.rlp_signed(&sig)));
            (200, json!({"id": "r-2", "state": "signed", "outcome": "signed", "raw_transaction": raw}))
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
        assert_eq!(seen.lock().unwrap().as_slice(), ["POST /v1/transactions"]);
    }

    #[tokio::test]
    async fn an_aborted_request_ends_the_wait() {
        let (base, _) = service(|method, _, _| {
            if method == "POST" {
                (200, json!({"id": "r-3", "state": "waiting_for_approval", "outcome": "pending"}))
            } else {
                (200, json!({"id": "r-3", "state": "aborted", "outcome": "failed"}))
            }
        });
        let e = sign_message(&config(base), "StopApp:0x00:1", "StopApp", None).await.unwrap_err();
        assert!(e.to_string().contains("ended aborted"), "{e}");
    }

    /// A request signature not given before the server's deadline is of no use: the request
    /// is aborted, so nobody approves it later, and the caller asks again.
    #[tokio::test]
    async fn past_the_deadline_the_request_is_aborted() {
        let (base, seen) = service(|_, _, _| (200, json!({"id": "r-4", "state": "waiting_for_approval", "outcome": "pending"})));
        let now = chrono::Utc::now().timestamp();
        let e = sign_message(&config(base), "StopApp:0x00:1", "StopApp", Some(now)).await.unwrap_err();
        assert!(e.downcast_ref::<super::super::Expired>().is_some(), "{e}");
        assert!(seen.lock().unwrap().contains(&"POST /v1/requests/r-4/abort".to_string()));
    }

    #[tokio::test]
    async fn a_refusal_says_why() {
        let (base, _) = service(|_, _, _| (403, json!({"error": "0x5f0d… on chain 16661 is not one of tapp's contracts"})));
        let to: Address = "0x5f0d9c243048F5a55468472c6F090184E2E333c7".parse().unwrap();
        let one = U256::one();
        let e = sign_transaction(&config(base.clone()), 16661, &to, &[], one, one, one, "x").await.unwrap_err().to_string();
        assert!(e.contains("403") && e.contains("not one of tapp's contracts") && !e.contains("Add EVM chain"), "{e}");

        let (fordefi_refused, _) = service(|_, _, _| (502, json!({"error": "Fordefi …: 400 — Chain evm_16602 is not supported"})));
        let e = sign_transaction(&config(fordefi_refused), 16602, &to, &[], one, one, one, "x").await.unwrap_err().to_string();
        assert!(e.contains("502") && e.contains("evm_16602") && e.contains("Add EVM chain"), "{e}");

        let mut bad = config(base.clone());
        bad.token = "wrong".into();
        let e = sign_message(&bad, "StopApp:0x00:1", "StopApp", None).await.unwrap_err().to_string();
        assert!(e.contains("401") && e.contains("FORDEFI_SIGNER_TOKEN"), "{e}");
    }

    /// A signed answer without what was asked for is an error, not an empty signature.
    #[tokio::test]
    async fn a_signed_answer_must_carry_the_signature() {
        let (base, _) = service(|_, _, _| (200, json!({"id": "r-5", "state": "signed", "outcome": "signed"})));
        let e = sign_message(&config(base), "StopApp:0x00:1", "StopApp", None).await.unwrap_err().to_string();
        assert!(e.contains("r-5") && e.contains("signature"), "{e}");
    }
}
