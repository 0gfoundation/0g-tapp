//! A Fordefi vault, for `--fordefi`, reached through 0g-fordefi-signer: the vault holding the
//! owner key signs once Fordefi's approval policy has run, and nothing is pasted.
//!
//! The Fordefi API user's credentials (its token and P-256 key) stay with the service; what
//! this machine holds is the service's address and a token that names this caller to it, and
//! which the service can revoke. The service also decides what the vault may sign for this
//! caller — which contracts and functions, how much value, which messages — on top of
//! Fordefi's own policy.
//!
//! | variable               |                                                              |
//! |------------------------|--------------------------------------------------------------|
//! | `FORDEFI_SIGNER_URL`   | the service, `https://…` (plain `http://` only on loopback)  |
//! | `FORDEFI_SIGNER_TOKEN` | this caller's token for it                                   |
//!
//! What comes back is never trusted as it is: a signature must recover to the signer, and a
//! transaction is signed only — handed back, checked, and broadcast from here like a Ledger's,
//! with its gas, gas price and nonce checked too.

use std::sync::OnceLock;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use ethers::types::{Address, U256};
use serde_json::{json, Value};

/// How long a transaction may wait for approval and signing before it is aborted. A request
/// signature has a shorter limit of its own: the server's window.
const APPROVAL_WAIT: Duration = Duration::from_secs(30 * 60);

/// How long before the server's window closes a request signature stops being waited for: a
/// signature still has to reach the server inside the window.
const WINDOW_MARGIN: i64 = 15;

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
    client: reqwest::Client,
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
        Self::new(base_url(&url)?, token, Duration::from_secs(2))
    }

    fn new(base: String, token: String, poll: Duration) -> Result<Self> {
        // The service never redirects, and following one could carry the token to plain HTTP.
        let mut client = reqwest::Client::builder()
            .timeout(Duration::from_secs(90))
            .redirect(reqwest::redirect::Policy::none());
        // Plain HTTP goes only to this machine, so never through a proxy: HTTP_PROXY does not
        // exempt loopback by itself, and the proxy would read the token.
        if base.starts_with("http://") {
            client = client.no_proxy();
        }
        let client = client.build().map_err(|e| anyhow!("building the HTTP client: {}", e))?;
        Ok(Config { base, token, poll, client })
    }

    /// The service, for showing where a signature is asked for.
    pub fn url(&self) -> &str {
        &self.base
    }
}

/// The service's base URL. The token travels on every call, so plain HTTP is taken only to
/// this machine (an SSH tunnel, say).
fn base_url(url: &str) -> Result<String> {
    let url = url.trim();
    let parsed = reqwest::Url::parse(url).map_err(|e| anyhow!("FORDEFI_SIGNER_URL {}: {}", url, e))?;
    // A password would be printed with the URL, and a query would swallow every path after it.
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(anyhow!("FORDEFI_SIGNER_URL must not carry a user or password; the token is the credential"));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(anyhow!("FORDEFI_SIGNER_URL {}: no query or fragment, only the service's address", url));
    }
    let url = parsed.as_str().trim_end_matches('/');
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
    let mut request = config
        .client
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
    /// `until` passed. `late` is what was signed while the request was being aborted, and
    /// `aborted` whether the abort went through.
    TimedOut { late: Option<T>, aborted: bool },
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
    // A service that is down would otherwise fill the screen, one line per poll.
    let mut last_error = String::new();
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
        let read = format!("/v1/requests/{id}");
        if Instant::now() >= until {
            let abort = format!("/v1/requests/{id}/abort");
            let aborted = match call(config, reqwest::Method::POST, &abort, None).await {
                Ok(v) => {
                    request = v;
                    true
                }
                Err(e) => {
                    eprintln!("  (aborting {id}: {e})");
                    // Most likely it was signed in the meantime.
                    if let Ok(v) = call(config, reqwest::Method::GET, &read, None).await {
                        request = v;
                    }
                    false
                }
            };
            let late = match field(&request, "outcome") {
                "signed" => hex_field(&request, result).ok(),
                _ => None,
            };
            let aborted = aborted && late.is_none();
            if !aborted && late.is_none() {
                eprintln!("  ! Fordefi request {id} could not be aborted and may still be approved: abort it in Fordefi");
            }
            return Ok(Waited::TimedOut { late, aborted });
        }
        tokio::time::sleep(config.poll).await;
        match call(config, reqwest::Method::GET, &read, None).await {
            Ok(v) => {
                request = v;
                last_error.clear();
            }
            Err(e) => match e.downcast_ref::<Refused>() {
                // Asking again will not change the answer: a revoked token, a request the
                // service does not show this caller.
                Some(r)
                    if r.status.is_client_error()
                        && r.status != reqwest::StatusCode::REQUEST_TIMEOUT
                        && r.status != reqwest::StatusCode::TOO_MANY_REQUESTS =>
                {
                    return Err(anyhow!("following Fordefi request {}: {}", id, e))
                }
                _ => {
                    let error = e.to_string();
                    if error != last_error {
                        eprintln!("  (reading {id}: {error}; retrying)");
                        last_error = error;
                    }
                }
            },
        }
    }
}

/// Why a request was not signed in time, for the error.
fn timed_out(aborted: bool) -> anyhow::Error {
    anyhow!(
        "not signed within {} min; {}",
        APPROVAL_WAIT.as_secs() / 60,
        if aborted {
            "the Fordefi request was aborted"
        } else {
            "the Fordefi request could not be aborted — abort it in Fordefi"
        }
    )
}

/// When to stop waiting for a request signature: shortly before its deadline, as an instant.
fn deadline(valid_until: Option<i64>) -> Instant {
    match valid_until {
        Some(t) => {
            let left = t - WINDOW_MARGIN - chrono::Utc::now().timestamp();
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
        // A signature past the server's window would only be refused.
        Waited::TimedOut { .. } if valid_until.is_some() => Err(super::Expired.into()),
        Waited::TimedOut { late: Some(sig), .. } => Ok(sig),
        Waited::TimedOut { late: None, aborted } => Err(timed_out(aborted)),
    }
}

/// The body asking the vault to sign, not send, a legacy contract call. Amounts are decimal
/// strings: wei does not fit the double a JSON number becomes.
#[allow(clippy::too_many_arguments)]
fn transaction_body(
    chain_id: u64,
    to: &Address,
    data: &[u8],
    value: U256,
    gas: U256,
    gas_price: U256,
    nonce: U256,
    what: &str,
) -> Value {
    json!({
        "chain_id": chain_id,
        "to": format!("0x{:x}", to),
        "data": format!("0x{}", hex::encode(data)),
        "value": value.to_string(),
        "gas_limit": gas.to_string(),
        "gas_price": gas_price.to_string(),
        "nonce": nonce.to_string(),
        "note": format!("tapp-cli: {what}"),
    })
}

/// Have the vault sign, not send, a contract call with the account's next `nonce` — the one
/// read here, not one Fordefi picks: a transaction it signed earlier and nobody sent would
/// otherwise push every later one past a nonce the chain is still waiting for. Returns the
/// signed transaction for the caller to check and broadcast.
#[allow(clippy::too_many_arguments)]
pub(super) async fn sign_transaction(
    config: &Config,
    chain_id: u64,
    to: &Address,
    data: &[u8],
    value: U256,
    gas: U256,
    gas_price: U256,
    nonce: U256,
    what: &str,
) -> Result<Vec<u8>> {
    let body = transaction_body(chain_id, to, data, value, gas, gas_price, nonce, what);
    let created = call(config, reqwest::Method::POST, "/v1/transactions", Some(&body))
        .await
        .map_err(|e| match e.downcast_ref::<Refused>() {
            // 502 is anything Fordefi refused or failed at; a chain it does not know is common.
            Some(r) if r.status == reqwest::StatusCode::BAD_GATEWAY && r.text.to_lowercase().contains("chain") => anyhow!(
                "{} (a chain Fordefi does not support out of the box — the 0G testnet, for one — \
                 must be added to the organisation: Settings > Chains > Add EVM chain)",
                e
            ),
            _ => e,
        })?;
    match wait_for(config, created, Instant::now() + APPROVAL_WAIT, "raw_transaction").await? {
        Waited::Done(raw) => Ok(raw),
        // Signed after all: it is checked like any other, and a nonce or fee that no longer
        // fits stops it then.
        Waited::TimedOut { late: Some(raw), .. } => {
            eprintln!("  signed just as the wait ran out; going on with it");
            Ok(raw)
        }
        Waited::TimedOut { late: None, aborted } => Err(timed_out(aborted)),
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
        Config::new(base, "token".into(), Duration::from_millis(10)).unwrap()
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
        assert_eq!(base_url("HTTPS://Signer.Example/fordefi/").unwrap(), "https://signer.example/fordefi");
        assert!(base_url("http://10.0.0.5:5000").is_err());
        assert!(base_url("http://localhost.signer.example").is_err());
        assert!(base_url("http://127.0.0.1@signer.example").is_err());
        let e = base_url("https://user:secret@signer.example").unwrap_err().to_string();
        assert!(e.contains("user or password") && !e.contains("secret"), "{e}");
        assert!(base_url("https://signer.example/?x=1").is_err());
        assert!(base_url("https://signer.example/#x").is_err());
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
            U256::from(7u64),
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
                "nonce": "7",
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
                .nonce(U256::from_dec_str(d["nonce"].as_str().unwrap()).unwrap())
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
        let (gas, gas_price, nonce) = (U256::from(90_000u64), U256::from(4_000_000_000u64), U256::from(3u64));
        let raw = sign_transaction(&config(base), 16661, &to, &data, value, gas, gas_price, nonce, "addNode")
            .await
            .unwrap();
        super::super::check_signed_transaction(&raw, 16661, &from, &to, &data, value).unwrap();
        super::super::check_fordefi_terms(&raw, gas, gas_price, nonce).unwrap();
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
        let e = sign_transaction(&config(base.clone()), 16661, &to, &[], one, one, one, one, "x").await.unwrap_err().to_string();
        assert!(e.contains("403") && e.contains("not one of tapp's contracts") && !e.contains("Add EVM chain"), "{e}");

        let (fordefi_refused, _) = service(|_, _, _| (502, json!({"error": "Fordefi …: 400 — Chain evm_16602 is not supported"})));
        let e = sign_transaction(&config(fordefi_refused), 16602, &to, &[], one, one, one, one, "x").await.unwrap_err().to_string();
        assert!(e.contains("502") && e.contains("evm_16602") && e.contains("Add EVM chain"), "{e}");

        let (unreachable, _) = service(|_, _, _| (502, json!({"error": "Fordefi …: connection refused"})));
        let e = sign_transaction(&config(unreachable), 16661, &to, &[], one, one, one, one, "x").await.unwrap_err().to_string();
        assert!(e.contains("502") && !e.contains("Add EVM chain"), "{e}");

        let mut bad = config(base.clone());
        bad.token = "wrong".into();
        let e = sign_message(&bad, "StopApp:0x00:1", "StopApp", None).await.unwrap_err().to_string();
        assert!(e.contains("401") && e.contains("FORDEFI_SIGNER_TOKEN"), "{e}");
    }

    /// A refusal while following a request will not change on asking again; it ends the wait.
    #[tokio::test]
    async fn a_request_the_service_will_not_show_ends_the_wait() {
        let (base, seen) = service(|method, _, _| {
            if method == "POST" {
                (200, json!({"id": "r-6", "state": "waiting_for_approval", "outcome": "pending"}))
            } else {
                (404, json!({"error": "request r-6 was not made by tapp through this service"}))
            }
        });
        let e = sign_message(&config(base), "StopApp:0x00:1", "StopApp", None).await.unwrap_err().to_string();
        assert!(e.contains("r-6") && e.contains("404"), "{e}");
        assert_eq!(seen.lock().unwrap().as_slice(), ["POST /v1/messages", "GET /v1/requests/r-6"]);
    }

    /// A transaction signed just as its wait ran out, so the abort failed, is still used; one
    /// that could not be aborted and was not signed says so.
    #[tokio::test]
    async fn past_the_deadline_a_late_signature_is_kept() {
        let (base, _) = service(|method, path, _| match (method, path) {
            ("POST", "/v1/transactions") => (200, json!({"id": "r-7", "state": "waiting_for_approval", "outcome": "pending"})),
            ("POST", _) => (502, json!({"error": "Fordefi …: 400 — the transaction is already signed"})),
            _ => (200, json!({"id": "r-7", "state": "signed", "outcome": "signed", "raw_transaction": "0xf86b01"})),
        });
        let created = json!({"id": "r-7", "state": "waiting_for_approval", "outcome": "pending"});
        match wait_for(&config(base), created.clone(), Instant::now(), "raw_transaction").await.unwrap() {
            Waited::TimedOut { late: Some(raw), aborted: false } => assert_eq!(raw, vec![0xf8, 0x6b, 0x01]),
            _ => panic!("the late signature was dropped"),
        }

        let (stuck, _) = service(|method, _, _| match method {
            "POST" => (502, json!({"error": "Fordefi …: unreachable"})),
            _ => (200, json!({"id": "r-7", "state": "waiting_for_approval", "outcome": "pending"})),
        });
        match wait_for(&config(stuck), created, Instant::now(), "raw_transaction").await.unwrap() {
            Waited::TimedOut { late: None, aborted } => assert!(!aborted && timed_out(aborted).to_string().contains("could not be aborted")),
            _ => panic!("expected a timeout"),
        }
    }

    /// A signature has to reach the server inside its window, so the wait ends a little before.
    #[test]
    fn a_request_signature_is_waited_for_until_shortly_before_the_window_closes() {
        let now = chrono::Utc::now().timestamp();
        assert!(deadline(Some(now + WINDOW_MARGIN)) <= Instant::now());
        let d = deadline(Some(now + 600));
        assert!(d > Instant::now() + Duration::from_secs(580));
        assert!(d <= Instant::now() + Duration::from_secs(600 - WINDOW_MARGIN as u64));
    }

    /// A signed answer without what was asked for is an error, not an empty signature.
    #[tokio::test]
    async fn a_signed_answer_must_carry_the_signature() {
        let (base, _) = service(|_, _, _| (200, json!({"id": "r-5", "state": "signed", "outcome": "signed"})));
        let e = sign_message(&config(base), "StopApp:0x00:1", "StopApp", None).await.unwrap_err().to_string();
        assert!(e.contains("r-5") && e.contains("signature"), "{e}");
    }
}
