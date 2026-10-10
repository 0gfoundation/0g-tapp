//! Signing with a key that is not on this machine.
//!
//! The owner key may live in a hardware wallet or with an MPC/multisig custodian (Fordefi,
//! for one) that signs only after its own approval policy has run. Such a signer looks like
//! an ordinary address from outside and produces ordinary signatures, so nothing on the
//! server or the chain changes. What changes is who holds the key: the CLI shows what needs
//! signing, the holder signs it, and the result is pasted back and checked before use.
//!
//! Two things get signed:
//! - a tapp-server request: an EIP-191 `personal_sign` of one line of text, which every
//!   wallet signs as a "message";
//! - an on-chain call: a transaction, which the holder sends itself. Its hash is pasted back,
//!   and the transaction that landed is compared with the one asked for before the CLI goes
//!   on, so a command with several steps (`start-app --register-onchain`) runs to the end.
//!
//! Everywhere the CLI used to take a private key it takes `external:0x<address>` instead
//! (see [`Signer`]), so every command gets this without being changed one by one.
//!
//! How the signature is obtained is the [`Backend`]; everything around it — what is signed,
//! the checks on what comes back, broadcasting and waiting — is shared:
//! - [`Backend::Paste`]: printed, and the signature or the sent transaction's hash pasted
//!   back. Works with any wallet.
//! - [`Backend::Ledger`]: a Ledger on this machine's USB. The device shows the message or
//!   the transaction and signs on a button press; a transaction is signed only, checked,
//!   and broadcast here. Built with the `ledger` feature (on by default on macOS).
//! - [`Backend::Fordefi`]: Fordefi's API. The vault holding the address signs once its
//!   approval policy has run; a transaction is signed only, checked, and broadcast here, as
//!   with a Ledger. See [`fordefi`].

use std::io::{BufRead, Write};
use std::str::FromStr;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use ethers::providers::{Http, Middleware, Provider};
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::types::{Address, Signature, Transaction, TransactionReceipt, TxHash, U256};

/// Whether this build can talk to a Ledger.
pub const LEDGER_SUPPORTED: bool = cfg!(feature = "ledger");

/// How signatures are obtained from the key's holder.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Backend {
    /// Printed; the signature, or the hash of the sent transaction, pasted back.
    Paste,
    /// A Ledger on this machine's USB.
    Ledger,
    /// Fordefi's API, as the API user configured in the environment (see [`fordefi`]).
    Fordefi,
}

static BACKEND: OnceLock<Backend> = OnceLock::new();

/// Choose the backend for this process (once, before anything is signed). Fordefi's
/// settings are read and checked here, so a missing one stops the command before it starts
/// rather than at its first signature.
pub fn use_backend(backend: Backend) -> Result<()> {
    if backend == Backend::Ledger && !LEDGER_SUPPORTED {
        return Err(anyhow!(
            "this tapp-cli was built without Ledger support. It is built in on macOS; \
             elsewhere build with `cargo build --release -p tapp-cli --features ledger`"
        ));
    }
    if backend == Backend::Fordefi {
        fordefi::configure(fordefi::Config::from_env()?)?;
    }
    BACKEND
        .set(backend)
        .map_err(|_| anyhow!("the signing backend was already chosen"))
}

fn backend() -> Backend {
    *BACKEND.get().unwrap_or(&Backend::Paste)
}

/// Run a future to completion from synchronous code inside the CLI's (multi-threaded) runtime.
fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(f))
}

/// What stands in for a private key when the key is held elsewhere.
pub const PREFIX: &str = "external:";

/// How long to wait for a pasted transaction hash to be mined.
const MINING_WAIT: Duration = Duration::from_secs(600);

/// A signature came back after the server would accept it. The caller makes a new message
/// for the same request and asks again; nothing has been sent.
#[derive(Debug, thiserror::Error)]
#[error("the signature came after its deadline")]
pub struct Expired;

/// The signer behind the CLI's `-k` value.
#[derive(Debug, Clone, PartialEq)]
pub enum Signer {
    /// A private key on this machine, hex.
    Key(String),
    /// A key held elsewhere, known here only by its address.
    External(Address),
}

impl Signer {
    pub fn parse(value: &str) -> Result<Self> {
        match value.strip_prefix(PREFIX) {
            Some(addr) => Address::from_str(addr.trim())
                .map(Signer::External)
                .map_err(|_| anyhow!("external signer {:?} is not a 0x… address", addr)),
            None => Ok(Signer::Key(value.to_string())),
        }
    }
}

/// The `-k` value that stands for an external signer.
pub fn as_key_value(address: &Address) -> String {
    format!("{}0x{:x}", PREFIX, address)
}

/// A pasted signature as 65 bytes r‖s‖v with v in {27, 28} and s in the lower half. Wallets
/// differ in how they return v (0/1 or 27/28) and whether they prefix 0x, and a signer that
/// does not normalise s (some MPC ones) can return the high-s twin, which the server's
/// recovery refuses; all of those are accepted and brought to the one spelling.
pub fn parse_signature(pasted: &str) -> Result<[u8; 65]> {
    let hex_str = pasted.trim().trim_start_matches("0x").trim_start_matches("0X");
    let bytes = hex::decode(hex_str).map_err(|_| anyhow!("not hex"))?;
    let mut sig: [u8; 65] = bytes
        .try_into()
        .map_err(|b: Vec<u8>| anyhow!("{} bytes, not 65", b.len()))?;
    if sig[64] < 27 {
        sig[64] += 27;
    }
    if sig[64] != 27 && sig[64] != 28 {
        return Err(anyhow!("recovery byte v = {} is neither 0/1 nor 27/28", sig[64]));
    }
    let rs = k256::ecdsa::Signature::from_slice(&sig[..64]).map_err(|e| anyhow!("{}", e))?;
    if let Some(low) = rs.normalize_s() {
        // (r, n - s) is the same signature with the other recovery parity.
        sig[..64].copy_from_slice(&low.to_bytes());
        sig[64] = if sig[64] == 27 { 28 } else { 27 };
    }
    Ok(sig)
}

/// The address that signed `message` with EIP-191 `personal_sign`.
pub fn recover_personal(message: &str, sig: &[u8; 65]) -> Result<Address> {
    let signature = Signature::try_from(&sig[..]).map_err(|e| anyhow!("{}", e))?;
    signature
        .recover(message)
        .map_err(|e| anyhow!("cannot recover a signer: {}", e))
}

/// Ask the holder of `address` to sign `message` and read the signature back, asking again
/// until it is one `address` made. `what` says what the signature is for; `valid_until` is
/// the unix time after which the server will refuse it.
pub fn request_signature(
    address: &Address,
    message: &str,
    what: &str,
    valid_until: Option<i64>,
) -> Result<[u8; 65]> {
    match backend() {
        Backend::Paste => paste_signature(address, message, what, valid_until),
        Backend::Ledger => ledger_signature(address, message, what, valid_until),
        Backend::Fordefi => fordefi_signature(address, message, what, valid_until),
    }
}

fn print_deadline(valid_until: Option<i64>) {
    if let Some(t) = valid_until {
        eprintln!(
            "  deadline {} (the server refuses it after that)",
            chrono::DateTime::from_timestamp(t, 0)
                .map(|d| d.format("%H:%M:%S UTC").to_string())
                .unwrap_or_else(|| t.to_string())
        );
    }
}

fn ledger_signature(
    address: &Address,
    message: &str,
    what: &str,
    valid_until: Option<i64>,
) -> Result<[u8; 65]> {
    eprintln!();
    eprintln!("──── confirm on the Ledger: {what} ────");
    eprintln!("  signer   0x{:x}", address);
    print_deadline(valid_until);
    eprintln!("  the device shows this text; approve it only if it matches:");
    eprintln!();
    eprintln!("{message}");
    eprintln!();
    let signature = block_on(ledger::sign_message(address, message))?;
    if let Some(t) = valid_until {
        if chrono::Utc::now().timestamp() > t {
            return Err(Expired.into());
        }
    }
    let sig: [u8; 65] = signature
        .to_vec()
        .try_into()
        .map_err(|_| anyhow!("the device returned a malformed signature"))?;
    let sig = parse_signature(&hex::encode(sig))?;
    let who = recover_personal(message, &sig)?;
    if who != *address {
        return Err(anyhow!("the device signed as 0x{:x}, not 0x{:x}", who, address));
    }
    eprintln!("  ✓ signed by 0x{:x}", who);
    Ok(sig)
}

fn fordefi_signature(
    address: &Address,
    message: &str,
    what: &str,
    valid_until: Option<i64>,
) -> Result<[u8; 65]> {
    let config = fordefi::config()?;
    eprintln!();
    eprintln!("──── signing in Fordefi: {what} ────");
    eprintln!("  signer   0x{:x}  (vault {})", address, config.vault_id());
    print_deadline(valid_until);
    eprintln!("  message (personal_sign):");
    eprintln!();
    eprintln!("{message}");
    eprintln!();
    let raw = block_on(fordefi::sign_message(config, message, what, valid_until))?;
    if let Some(t) = valid_until {
        if chrono::Utc::now().timestamp() > t {
            return Err(Expired.into());
        }
    }
    let sig = parse_signature(&hex::encode(raw))
        .map_err(|e| anyhow!("Fordefi returned a malformed signature: {}", e))?;
    let who = recover_personal(message, &sig)?;
    if who != *address {
        return Err(anyhow!(
            "Fordefi vault {} signed as 0x{:x}, not 0x{:x} — FORDEFI_EVM_VAULT_ID names another vault",
            config.vault_id(),
            who,
            address
        ));
    }
    eprintln!("  ✓ signed by 0x{:x}", who);
    Ok(sig)
}

fn paste_signature(
    address: &Address,
    message: &str,
    what: &str,
    valid_until: Option<i64>,
) -> Result<[u8; 65]> {
    eprintln!();
    eprintln!("──── signature needed: {what} ────");
    eprintln!("  signer   0x{:x}", address);
    print_deadline(valid_until);
    eprintln!("  sign this text as a message (personal_sign / EIP-191):");
    eprintln!();
    eprintln!("{message}");
    eprintln!();
    loop {
        let pasted = prompt("signature (0x…, 65 bytes)")?;
        if let Some(t) = valid_until {
            if chrono::Utc::now().timestamp() > t {
                return Err(Expired.into());
            }
        }
        match parse_signature(&pasted).and_then(|s| Ok((s, recover_personal(message, &s)?))) {
            Ok((sig, who)) if who == *address => return Ok(sig),
            Ok((_, who)) => eprintln!(
                "  ✗ that is a signature by 0x{:x}, not by 0x{:x} — of this exact text? Paste again.",
                who, address
            ),
            Err(e) => eprintln!("  ✗ {e}. Paste again."),
        }
    }
}

/// The transaction that landed is the one that was asked for: same sender, contract, data
/// and value, it succeeded, and it was mined after block `asked_at`, the chain head when it
/// was asked for — an identical call made before (an earlier run, say) is not this one.
/// Kept separate from the waiting so it can be tested.
#[allow(clippy::too_many_arguments)]
pub fn check_transaction(
    tx: &Transaction,
    status: Option<u64>,
    mined_in: Option<u64>,
    asked_at: u64,
    from: &Address,
    to: &Address,
    data: &[u8],
    value: U256,
) -> Result<()> {
    match mined_in {
        Some(b) if b > asked_at => {}
        Some(b) => {
            return Err(anyhow!(
                "it was mined in block {b}, before it was asked for (head was block {asked_at}) \
                 — an earlier, identical call"
            ))
        }
        None => return Err(anyhow!("its receipt has no block number")),
    }
    if tx.from != *from {
        return Err(anyhow!("it was sent by 0x{:x}, not by 0x{:x}", tx.from, from));
    }
    if tx.to != Some(*to) {
        return Err(anyhow!("it calls {:?}, not 0x{:x}", tx.to, to));
    }
    if tx.input.as_ref() != data {
        return Err(anyhow!("its data is not the data asked for"));
    }
    if tx.value != value {
        return Err(anyhow!("it carries {} wei, not {}", tx.value, value));
    }
    match status {
        Some(1) => Ok(()),
        Some(_) => Err(anyhow!("it reverted")),
        None => Err(anyhow!("its receipt has no status")),
    }
}

/// A signed raw transaction is the one asked for, before it is broadcast: signed by `from`
/// for this chain, calling `to` with `data` and `value`. Returns its hash.
pub fn check_signed_transaction(
    raw: &[u8],
    chain_id: u64,
    from: &Address,
    to: &Address,
    data: &[u8],
    value: U256,
) -> Result<TxHash> {
    let (tx, sig) = TypedTransaction::decode_signed(&ethers::utils::rlp::Rlp::new(raw))
        .map_err(|e| anyhow!("not a signed transaction: {}", e))?;
    let signer = sig
        .recover(tx.sighash())
        .map_err(|e| anyhow!("cannot recover its signer: {}", e))?;
    if signer != *from {
        return Err(anyhow!("it is signed by 0x{:x}, not by 0x{:x}", signer, from));
    }
    // No chain id would make it valid on every chain.
    if tx.chain_id().map(|c| c.as_u64()) != Some(chain_id) {
        return Err(anyhow!("it is for chain {:?}, not {}", tx.chain_id(), chain_id));
    }
    if tx.to().and_then(|t| t.as_address()) != Some(to) {
        return Err(anyhow!("it calls {:?}, not 0x{:x}", tx.to(), to));
    }
    if tx.data().map(|d| d.as_ref()).unwrap_or(&[]) != data {
        return Err(anyhow!("its data is not the data asked for"));
    }
    if tx.value().copied().unwrap_or_default() != value {
        return Err(anyhow!("it carries {:?} wei, not {}", tx.value(), value));
    }
    Ok(TxHash::from(ethers::utils::keccak256(raw)))
}

/// Wait for `hash` to be mined, retrying through RPC errors: once a transaction is out, an
/// RPC hiccup must not end the command half-way. `None` if it is not mined in time.
async fn wait_mined(
    provider: &Provider<Http>,
    hash: TxHash,
) -> Option<(TransactionReceipt, Transaction)> {
    let started = Instant::now();
    loop {
        let found = match provider.get_transaction_receipt(hash).await {
            Ok(Some(r)) => match provider.get_transaction(hash).await {
                Ok(Some(tx)) => Some((r, tx)),
                Ok(None) => None,
                Err(e) => {
                    eprintln!("  (reading the transaction: {e}; retrying)");
                    None
                }
            },
            Ok(None) => None,
            Err(e) => {
                eprintln!("  (reading the receipt: {e}; retrying)");
                None
            }
        };
        match found {
            Some(m) => return Some(m),
            None if started.elapsed() < MINING_WAIT => {
                tokio::time::sleep(Duration::from_secs(3)).await
            }
            None => return None,
        }
    }
}

/// Have the holder of `from` sign and send a contract call, and wait until it has been mined
/// and checked (see [`check_transaction`]). `what` names the call.
pub async fn request_transaction(
    provider: &Provider<Http>,
    chain_id: u64,
    from: &Address,
    to: &Address,
    data: &[u8],
    value: U256,
    what: &str,
) -> Result<TxHash> {
    match backend() {
        Backend::Paste => paste_transaction(provider, chain_id, from, to, data, value, what).await,
        Backend::Ledger => ledger_transaction(provider, chain_id, from, to, data, value, what).await,
        Backend::Fordefi => fordefi_transaction(provider, chain_id, from, to, data, value, what).await,
    }
}

/// A legacy transaction for the call, with nonce, gas price and a gas limit 20% over the
/// estimate. Estimating also catches a call that would revert (not the app's owner, say)
/// before anyone is asked to sign it.
async fn prepare_call(
    provider: &Provider<Http>,
    chain_id: u64,
    from: &Address,
    to: &Address,
    data: &[u8],
    value: U256,
) -> Result<ethers::types::TransactionRequest> {
    use ethers::types::{BlockNumber, TransactionRequest};

    let nonce = provider
        .get_transaction_count(*from, Some(BlockNumber::Pending.into()))
        .await
        .map_err(|e| anyhow!("reading the nonce: {}", e))?;
    let gas_price = provider
        .get_gas_price()
        .await
        .map_err(|e| anyhow!("reading the gas price: {}", e))?;
    let request = TransactionRequest::new()
        .from(*from)
        .to(*to)
        .data(data.to_vec())
        .value(value)
        .nonce(nonce)
        .gas_price(gas_price)
        .chain_id(chain_id);
    let gas = provider
        .estimate_gas(&request.clone().into(), None)
        .await
        .map_err(|e| anyhow!("the call would fail: {}", e))?;
    Ok(request.gas(gas * 12 / 10))
}

fn print_call(chain_id: u64, from: &Address, to: &Address, data: &[u8], value: U256) {
    eprintln!("  from     0x{:x}  (chain {chain_id})", from);
    eprintln!("  to       0x{:x}", to);
    eprintln!("  value    {} wei ({} OG)", value, ethers::utils::format_ether(value));
    eprintln!("  data     0x{}", hex::encode(data));
}

/// The Ledger signs only; the transaction is checked here and broadcast from here.
async fn ledger_transaction(
    provider: &Provider<Http>,
    chain_id: u64,
    from: &Address,
    to: &Address,
    data: &[u8],
    value: U256,
    what: &str,
) -> Result<TxHash> {
    let tx: TypedTransaction = prepare_call(provider, chain_id, from, to, data, value).await?.into();

    eprintln!();
    eprintln!("──── confirm on the Ledger: {what} ────");
    print_call(chain_id, from, to, data, value);
    eprintln!("  (a contract call needs Blind signing enabled in the device's Ethereum app)");
    let signature = ledger::sign_tx(from, chain_id, &tx).await?;
    let raw = tx.rlp_signed(&signature);
    let hash = check_signed_transaction(&raw, chain_id, from, to, data, value)
        .map_err(|e| anyhow!("the device returned a transaction that is not the one asked for: {}", e))?;
    broadcast_checked(provider, raw.to_vec(), hash, from, to, data, value).await
}

/// Fordefi signs only (push_mode manual); the transaction is checked here and broadcast
/// from here, as a Ledger's is. Fordefi picks the nonce; the gas is set here.
async fn fordefi_transaction(
    provider: &Provider<Http>,
    chain_id: u64,
    from: &Address,
    to: &Address,
    data: &[u8],
    value: U256,
    what: &str,
) -> Result<TxHash> {
    let config = fordefi::config()?;
    let call = prepare_call(provider, chain_id, from, to, data, value).await?;
    let (Some(gas), Some(gas_price)) = (call.gas, call.gas_price) else {
        return Err(anyhow!("no gas estimate for the call"));
    };

    eprintln!();
    eprintln!("──── signing in Fordefi: {what} ────");
    eprintln!("  vault    {}", config.vault_id());
    print_call(chain_id, from, to, data, value);
    let raw = fordefi::sign_transaction(config, chain_id, to, data, value, gas, gas_price, what).await?;
    let hash = check_signed_transaction(&raw, chain_id, from, to, data, value)
        .map_err(|e| anyhow!("Fordefi returned a transaction that is not the one asked for: {}", e))?;
    broadcast_checked(provider, raw, hash, from, to, data, value).await
}

/// Broadcast a signed transaction that [`check_signed_transaction`] passed, wait for it to
/// be mined, and check what landed (see [`check_transaction`]).
async fn broadcast_checked(
    provider: &Provider<Http>,
    raw: Vec<u8>,
    hash: TxHash,
    from: &Address,
    to: &Address,
    data: &[u8],
    value: U256,
) -> Result<TxHash> {
    let asked_at = provider
        .get_block_number()
        .await
        .map_err(|e| anyhow!("reading the chain head: {}", e))?
        .as_u64();
    if let Err(e) = provider.send_raw_transaction(raw.into()).await {
        // The answer can be lost after the node took it (a timeout, say); it is out if the
        // node knows it, and stopping here would leave a sent transaction unaccounted for.
        if !matches!(provider.get_transaction(hash).await, Ok(Some(_))) {
            return Err(anyhow!("broadcasting 0x{:x}: {}", hash, e));
        }
    }
    eprintln!("  sent 0x{:x}; waiting for it to be mined…", hash);
    let Some((receipt, mined)) = wait_mined(provider, hash).await else {
        return Err(anyhow!(
            "0x{:x} was sent but not mined within {}s; check it before running the command again",
            hash,
            MINING_WAIT.as_secs()
        ));
    };
    check_transaction(
        &mined,
        receipt.status.map(|s| s.as_u64()),
        receipt.block_number.map(|b| b.as_u64()),
        asked_at,
        from,
        to,
        data,
        value,
    )?;
    eprintln!("  ✓ mined in block {}", receipt.block_number.unwrap_or_default());
    Ok(hash)
}

async fn paste_transaction(
    provider: &Provider<Http>,
    chain_id: u64,
    from: &Address,
    to: &Address,
    data: &[u8],
    value: U256,
    what: &str,
) -> Result<TxHash> {
    // Anything mined up to this block is not the transaction about to be asked for.
    let asked_at = provider
        .get_block_number()
        .await
        .map_err(|e| anyhow!("reading the chain head: {}", e))?
        .as_u64();
    eprintln!();
    eprintln!("──── transaction needed: {what} ────");
    print_call(chain_id, from, to, data, value);
    eprintln!();
    loop {
        let pasted = prompt("hash of the sent transaction (0x…, 32 bytes)")?;
        let hash = match TxHash::from_str(pasted.trim()) {
            Ok(h) => h,
            Err(_) => {
                eprintln!("  ✗ not a 32-byte hash. Paste again.");
                continue;
            }
        };
        eprintln!("  waiting for 0x{:x} to be mined…", hash);
        let Some((receipt, tx)) = wait_mined(provider, hash).await else {
            eprintln!("  ✗ not mined within {}s. Paste the hash again once it is.", MINING_WAIT.as_secs());
            continue;
        };
        match check_transaction(
            &tx,
            receipt.status.map(|s| s.as_u64()),
            receipt.block_number.map(|b| b.as_u64()),
            asked_at,
            from,
            to,
            data,
            value,
        ) {
            Ok(()) => {
                eprintln!("  ✓ mined in block {}", receipt.block_number.unwrap_or_default());
                return Ok(hash);
            }
            Err(e) => eprintln!("  ✗ 0x{:x} is not the transaction asked for: {e}. Paste the right one.", hash),
        }
    }
}

/// One line from the terminal. Prompts go to stderr so stdout can still be piped.
fn prompt(label: &str) -> Result<String> {
    eprint!("{label}: ");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    let n = std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| anyhow!("reading the answer: {}", e))?;
    if n == 0 {
        return Err(anyhow!("no answer (end of input)"));
    }
    Ok(line.trim().to_string())
}

pub mod fordefi;

/// The Ledger itself. The account is found by the address the operator gave, not by a
/// derivation index they have to know, across the three path styles wallets use.
#[cfg(feature = "ledger")]
mod ledger {
    use super::*;
    use ethers::signers::{HDPath, Ledger};

    /// How many accounts of each path style are searched for the address.
    const SEARCH: usize = 10;
    static PATH: OnceLock<HDPath> = OnceLock::new();

    fn device_error(e: impl std::fmt::Display) -> anyhow::Error {
        let e = e.to_string();
        anyhow!("Ledger: {}", explain(&e).unwrap_or(&e))
    }

    /// What a device answer means for the operator. The codes are the Ethereum app's; the
    /// raw text is kept when none applies.
    pub(super) fn explain(e: &str) -> Option<&'static str> {
        Some(if e.contains("CONDITIONS_NOT_SATISFIED") {
            "rejected on the device"
        } else if e.contains("APDU_CODE_INVALID_DATA") || e.contains("DATA_INVALID") {
            "the device refused the contract call — enable Blind signing in the Ethereum app's \
             settings and run the command again"
        } else if e.contains("UNLOCK_DEVICE") {
            "the device is locked — unlock it and run the command again"
        } else if e.contains("CLA_NOT_SUPPORTED") || e.contains("INS_NOT_SUPPORTED") {
            "the Ethereum app is not open on the device"
        } else if e.contains("device not found") {
            "no Ledger found — connect and unlock it, and open the Ethereum app"
        } else if e.contains("Error opening device") {
            "the Ledger cannot be opened — close Ledger Live (only one program can use the \
             device at a time); on Linux, also check Ledger's udev rules"
        } else {
            return None;
        })
    }

    /// The path styles, per account index: Ledger Live, BIP44 standard (MetaMask's "BIP44
    /// Standard", most software wallets) and legacy (MEW/MyCrypto). Index 0 of the first
    /// two is the same path, so it is tried once.
    fn paths(i: usize) -> Vec<HDPath> {
        let mut out = vec![HDPath::LedgerLive(i)];
        if i > 0 {
            out.push(HDPath::Other(format!("m/44'/60'/0'/0/{i}")));
        }
        out.push(HDPath::Legacy(i));
        out
    }

    /// Open the device at `path`. A handle that was just dropped releases the device from its
    /// own thread a moment later, and macOS opens it exclusively, so an open straight after one
    /// (the search, then the account found) can find it still taken; that is waited out.
    async fn connect(path: &HDPath, chain_id: u64) -> Result<Ledger> {
        let mut tries = 0;
        loop {
            match Ledger::new(path.clone(), chain_id).await {
                Ok(device) => return Ok(device),
                Err(e) if tries < 10 && e.to_string().contains("Error opening device") => {
                    tries += 1;
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                Err(e) => return Err(device_error(e)),
            }
        }
    }

    async fn open(address: &Address, chain_id: u64) -> Result<Ledger> {
        if let Some(path) = PATH.get() {
            return connect(path, chain_id).await;
        }
        let probe = connect(&HDPath::LedgerLive(0), chain_id).await?;
        let mut seen = Vec::new();
        for i in 0..SEARCH {
            for path in paths(i) {
                let found = probe.get_address_with_path(&path).await.map_err(device_error)?;
                if found == *address {
                    drop(probe);
                    let _ = PATH.set(path.clone());
                    eprintln!("  (Ledger account {path})");
                    return connect(&path, chain_id).await;
                }
                seen.push(format!("{path} → 0x{found:x}"));
            }
        }
        Err(anyhow!(
            "0x{:x} is not among the first {SEARCH} accounts of this Ledger (Ledger Live, BIP44 \
             and legacy paths): {}",
            address,
            seen.join(", ")
        ))
    }

    pub async fn sign_message(address: &Address, message: &str) -> Result<Signature> {
        // A personal message is not tied to a chain; the id only parameterises the handle.
        let device = open(address, 1).await?;
        device.sign_message(message).await.map_err(device_error)
    }

    pub async fn sign_tx(address: &Address, chain_id: u64, tx: &TypedTransaction) -> Result<Signature> {
        let device = open(address, chain_id).await?;
        device.sign_tx(tx).await.map_err(device_error)
    }
}

/// Stand-in when built without Ledger support; `use_backend` refuses Ledger then, so these
/// are never reached.
#[cfg(not(feature = "ledger"))]
mod ledger {
    use super::*;

    pub async fn sign_message(_: &Address, _: &str) -> Result<Signature> {
        Err(anyhow!("built without Ledger support"))
    }

    pub async fn sign_tx(_: &Address, _: u64, _: &TypedTransaction) -> Result<Signature> {
        Err(anyhow!("built without Ledger support"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::signers::{LocalWallet, Signer as _};
    use ethers::types::Bytes;

    const KEY: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

    #[test]
    fn a_key_and_an_external_address_are_told_apart() {
        assert_eq!(Signer::parse(KEY).unwrap(), Signer::Key(KEY.into()));
        let a: Address = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".parse().unwrap();
        assert_eq!(Signer::parse(&as_key_value(&a)).unwrap(), Signer::External(a));
        assert!(Signer::parse("external:not-an-address").is_err());
    }

    #[tokio::test]
    async fn a_pasted_signature_is_checked_against_the_signer() {
        let wallet: LocalWallet = KEY.parse().unwrap();
        let message = "StartApp:0x00ff:1791400000";
        let sig = wallet.sign_message(message).await.unwrap().to_vec();
        let pasted = format!("0x{}", hex::encode(&sig));
        let parsed = parse_signature(&pasted).unwrap();
        assert_eq!(recover_personal(message, &parsed).unwrap(), wallet.address());
        // The same signature over different text names someone else.
        assert_ne!(recover_personal("StartApp:0x00fe:1791400000", &parsed).unwrap(), wallet.address());
    }

    /// A signer that does not normalise s returns (r, n - s) with the other parity. The server
    /// refuses that spelling, so it is turned into the low-s one, which names the same signer.
    #[tokio::test]
    async fn a_high_s_signature_is_brought_to_low_s() {
        let wallet: LocalWallet = KEY.parse().unwrap();
        let message = "StopApp:0x00ff:1791400000";
        let low = wallet.sign_message(message).await.unwrap().to_vec();
        let rs = k256::ecdsa::Signature::from_slice(&low[..64]).unwrap();
        let n_minus_s = -*rs.s();
        let high_rs = k256::ecdsa::Signature::from_scalars(*rs.r(), n_minus_s).unwrap();
        let mut high = high_rs.to_bytes().to_vec();
        high.push(if low[64] == 27 { 28 } else { 27 });
        // What the server does (src/signature_auth.rs): k256 recovery, which refuses high s.
        let server_recovers = |sig: &[u8]| {
            let rs = k256::ecdsa::Signature::from_slice(&sig[..64]).unwrap();
            let id = k256::ecdsa::RecoveryId::try_from(sig[64] - 27).unwrap();
            k256::ecdsa::VerifyingKey::recover_from_prehash(ethers::utils::hash_message(message).as_bytes(), &rs, id).is_ok()
        };
        assert!(server_recovers(&low));
        assert!(!server_recovers(&high), "the server would refuse the high-s spelling");

        let parsed = parse_signature(&hex::encode(&high)).unwrap();
        assert_eq!(parsed.to_vec(), low);
        assert_eq!(recover_personal(message, &parsed).unwrap(), wallet.address());
    }

    #[test]
    fn wallets_that_return_v_as_0_or_1_are_accepted() {
        let mut sig = [1u8; 65];
        sig[64] = 1;
        assert_eq!(parse_signature(&hex::encode(sig)).unwrap()[64], 28);
        sig[64] = 27;
        assert_eq!(parse_signature(&format!("0x{}", hex::encode(sig))).unwrap()[64], 27);
        sig[64] = 5;
        assert!(parse_signature(&hex::encode(sig)).is_err());
        assert!(parse_signature("0x1234").is_err());
        assert!(parse_signature("zz").is_err());
    }

    /// What a Ledger (or any wallet signing without broadcasting) returns is checked before it
    /// is sent: signer, chain, contract, data, value. 0G's chain ids are large, so the EIP-155
    /// v value is too.
    #[tokio::test]
    async fn a_signed_transaction_is_checked_before_it_is_sent() {
        use ethers::types::TransactionRequest;
        let wallet: LocalWallet = KEY.parse::<LocalWallet>().unwrap().with_chain_id(16661u64);
        let to: Address = "0x5f0d9c243048F5a55468472c6F090184E2E333c7".parse().unwrap();
        let data = vec![0x81, 0x73, 0x0e, 0xad, 1, 2, 3];
        let value = U256::from(1_000_000_000_000_000u64);
        let tx: TypedTransaction = TransactionRequest::new()
            .from(wallet.address())
            .to(to)
            .data(data.clone())
            .value(value)
            .nonce(7)
            .gas(100_000)
            .gas_price(3_000_000_000u64)
            .chain_id(16661u64)
            .into();
        let sig = wallet.sign_transaction(&tx).await.unwrap();
        let raw = tx.rlp_signed(&sig);
        let from = wallet.address();

        let hash = check_signed_transaction(&raw, 16661, &from, &to, &data, value).unwrap();
        assert_eq!(hash, TxHash::from(ethers::utils::keccak256(&raw)));
        let other: Address = "0x3333333333333333333333333333333333333333".parse().unwrap();
        assert!(check_signed_transaction(&raw, 16602, &from, &to, &data, value).is_err(), "other chain");
        assert!(check_signed_transaction(&raw, 16661, &other, &to, &data, value).is_err(), "other signer");
        assert!(check_signed_transaction(&raw, 16661, &from, &other, &data, value).is_err(), "other contract");
        assert!(check_signed_transaction(&raw, 16661, &from, &to, &[9], value).is_err(), "other data");
        assert!(check_signed_transaction(&raw, 16661, &from, &to, &data, U256::zero()).is_err(), "other value");
        assert!(check_signed_transaction(&[0xde, 0xad], 16661, &from, &to, &data, value).is_err(), "garbage");
    }

    /// A device answer is told to the operator as what to do, not as a connection problem.
    #[cfg(feature = "ledger")]
    #[test]
    fn device_answers_say_what_to_do() {
        let says = |raw: &str| super::ledger::explain(raw).unwrap_or("");
        assert!(says("[APDU_CODE_CONDITIONS_NOT_SATISFIED] Conditions of use not satisfied").contains("rejected"));
        assert!(says("[APDU_CODE_INVALID_DATA] The parameters in the data field are incorrect").contains("Blind signing"));
        assert!(says("[APDU_CODE_UNLOCK_DEVICE_ERROR] Device is locked").contains("locked"));
        assert!(says("[APDU_CODE_CLA_NOT_SUPPORTED] Class not supported").contains("Ethereum app"));
        assert!(says("Ledger device not found").contains("connect"));
        assert!(says("Error opening device. hidapi error. Hint: This usually means that the device is already in use by another transport instance.").contains("Ledger Live"));
        assert_eq!(super::ledger::explain("something else"), None);
    }

    /// The device is driven from synchronous code (a request's signature) inside the CLI's
    /// runtime, whose main future runs on the thread that called `Runtime::block_on`, not on
    /// a worker. Bridging back into async there must not panic.
    #[test]
    fn async_device_calls_can_be_made_from_the_clis_main_future() {
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
        let got = rt.block_on(async {
            // As add_signature_metadata does: plain sync code, then the bridge.
            fn sync_caller() -> u32 {
                block_on(async {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    7
                })
            }
            sync_caller()
        });
        assert_eq!(got, 7);
    }

    #[test]
    fn a_ledger_is_refused_when_the_build_cannot_drive_one() {
        if !LEDGER_SUPPORTED {
            assert!(use_backend(Backend::Ledger).is_err());
        }
    }

    #[test]
    fn only_the_transaction_asked_for_is_accepted() {
        let from: Address = "0x1111111111111111111111111111111111111111".parse().unwrap();
        let to: Address = "0x2222222222222222222222222222222222222222".parse().unwrap();
        let data = vec![1u8, 2, 3];
        let value = U256::from(1000);
        let tx = Transaction {
            from,
            to: Some(to),
            input: Bytes::from(data.clone()),
            value,
            ..Default::default()
        };
        let ok = |status, block, from: &Address, to: &Address, data: &[u8], value| {
            check_transaction(&tx, status, block, 100, from, to, data, value).is_ok()
        };
        assert!(ok(Some(1), Some(101), &from, &to, &data, value));
        assert!(ok(Some(1), Some(105), &from, &to, &data, value));
        assert!(!ok(Some(0), Some(105), &from, &to, &data, value), "reverted");
        let other: Address = "0x3333333333333333333333333333333333333333".parse().unwrap();
        assert!(!ok(Some(1), Some(105), &other, &to, &data, value), "another sender");
        assert!(!ok(Some(1), Some(105), &from, &other, &data, value), "another contract");
        assert!(!ok(Some(1), Some(105), &from, &to, &[9], value), "other data");
        assert!(!ok(Some(1), Some(105), &from, &to, &data, U256::zero()), "other value");
        // The same call, made before it was asked for: an earlier run's transaction.
        assert!(!ok(Some(1), Some(99), &from, &to, &data, value), "mined before it was asked for");
        assert!(!ok(Some(1), Some(100), &from, &to, &data, value), "mined in the head block when asked");
        assert!(!ok(Some(1), None, &from, &to, &data, value), "no block number");
    }
}
