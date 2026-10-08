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

use std::io::{BufRead, Write};
use std::str::FromStr;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use ethers::providers::{Http, Middleware, Provider};
use ethers::types::{Address, Signature, Transaction, TxHash, U256};

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

/// A pasted signature as 65 bytes r‖s‖v with v in {27, 28}. Wallets differ in how they
/// return v (0/1 or 27/28) and whether they prefix 0x; all of those are accepted.
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
    eprintln!();
    eprintln!("──── signature needed: {what} ────");
    eprintln!("  signer   0x{:x}", address);
    if let Some(t) = valid_until {
        eprintln!(
            "  deadline {} (the server refuses it after that)",
            chrono::DateTime::from_timestamp(t, 0)
                .map(|d| d.format("%H:%M:%S UTC").to_string())
                .unwrap_or_else(|| t.to_string())
        );
    }
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
/// and value, it succeeded, and it was mined no earlier than `asked_at` — an identical call
/// made before (an earlier run, say) is not this one. Kept separate from the waiting so it
/// can be tested.
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
        Some(b) if b >= asked_at => {}
        Some(b) => {
            return Err(anyhow!(
                "it was mined in block {b}, before it was asked for (block {asked_at}) — an \
                 earlier, identical call"
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

/// Ask the holder of `from` to send a contract call, and wait until the one it sent has
/// been mined and checked (see [`check_transaction`]). `what` names the call.
pub async fn request_transaction(
    provider: &Provider<Http>,
    chain_id: u64,
    from: &Address,
    to: &Address,
    data: &[u8],
    value: U256,
    what: &str,
) -> Result<TxHash> {
    eprintln!();
    eprintln!("──── transaction needed: {what} ────");
    eprintln!("  from     0x{:x}  (chain {chain_id})", from);
    eprintln!("  to       0x{:x}", to);
    eprintln!("  value    {} wei", value);
    eprintln!("  data     0x{}", hex::encode(data));
    eprintln!();
    // Anything mined before this point is not the transaction being asked for.
    let asked_at = provider
        .get_block_number()
        .await
        .map_err(|e| anyhow!("reading the chain head: {}", e))?
        .as_u64();
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
        // The transaction is out of our hands once sent, so an RPC hiccup must not end the
        // command half-way: keep asking until it is mined (or the wait runs out).
        let started = Instant::now();
        let mined = loop {
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
                Some(m) => break Some(m),
                None if started.elapsed() < MINING_WAIT => {
                    tokio::time::sleep(Duration::from_secs(3)).await
                }
                None => break None,
            }
        };
        let Some((receipt, tx)) = mined else {
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
        assert!(ok(Some(1), Some(100), &from, &to, &data, value));
        assert!(ok(Some(1), Some(105), &from, &to, &data, value));
        assert!(!ok(Some(0), Some(105), &from, &to, &data, value), "reverted");
        let other: Address = "0x3333333333333333333333333333333333333333".parse().unwrap();
        assert!(!ok(Some(1), Some(105), &other, &to, &data, value), "another sender");
        assert!(!ok(Some(1), Some(105), &from, &other, &data, value), "another contract");
        assert!(!ok(Some(1), Some(105), &from, &to, &[9], value), "other data");
        assert!(!ok(Some(1), Some(105), &from, &to, &data, U256::zero()), "other value");
        // The same call, made before it was asked for: an earlier run's transaction.
        assert!(!ok(Some(1), Some(99), &from, &to, &data, value), "mined before it was asked for");
        assert!(!ok(Some(1), None, &from, &to, &data, value), "no block number");
    }
}
