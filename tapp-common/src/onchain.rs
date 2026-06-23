use anyhow::{anyhow, Result};
use ethers::{
    abi::{decode, encode, ParamType, Token},
    prelude::*,
    providers::{Http, Provider},
    types::{Address, Bytes, TransactionRequest, U256},
    utils::keccak256,
};
use std::str::FromStr;

// ─── ABI helpers ─────────────────────────────────────────────────────────────

fn selector(sig: &str) -> [u8; 4] {
    let h = keccak256(sig.as_bytes());
    [h[0], h[1], h[2], h[3]]
}

fn calldata(sig: &str, tokens: Vec<Token>) -> Vec<u8> {
    let mut data = selector(sig).to_vec();
    data.extend_from_slice(&encode(&tokens));
    data
}

// ─── Reads ──────────────────────────────────────────────────────────────────

/// Read the app-level default (composeHash, volumesHash) via getAppInfo(string).
/// Used to decide whether a node needs a per-node override (differs from default)
/// or should inherit (equals default → store empty).
pub async fn get_app_default_hashes(
    rpc_url: &str,
    contract: &str,
    app_id: &str,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let provider =
        Provider::<Http>::try_from(rpc_url).map_err(|e| anyhow!("Invalid RPC URL: {}", e))?;
    let to = Address::from_str(contract).map_err(|_| anyhow!("Invalid contract address"))?;
    let data = calldata("getAppInfo(string)", vec![Token::String(app_id.to_owned())]);
    let tx = TransactionRequest::new().to(to).data(Bytes::from(data));
    let out = provider
        .call(&tx.into(), None)
        .await
        .map_err(|e| anyhow!("getAppInfo call failed: {}", e))?;

    // AppInfo = (bytes composeHash, bytes volumesHash, bytes[] imageHashes, address owner, uint256 registeredAt)
    let tuple = ParamType::Tuple(vec![
        ParamType::Bytes,
        ParamType::Bytes,
        ParamType::Array(Box::new(ParamType::Bytes)),
        ParamType::Address,
        ParamType::Uint(256),
    ]);
    let tokens = decode(&[tuple], &out).map_err(|e| anyhow!("decode getAppInfo: {}", e))?;
    if let Some(Token::Tuple(fields)) = tokens.into_iter().next() {
        let compose = match &fields[0] {
            Token::Bytes(b) => b.clone(),
            _ => vec![],
        };
        let volumes = match &fields[1] {
            Token::Bytes(b) => b.clone(),
            _ => vec![],
        };
        Ok((compose, volumes))
    } else {
        Err(anyhow!("unexpected getAppInfo return shape"))
    }
}

/// Low-level eth_call helper returning raw return bytes.
async fn call_raw(rpc_url: &str, contract: &str, data: Vec<u8>) -> Result<Vec<u8>> {
    let provider =
        Provider::<Http>::try_from(rpc_url).map_err(|e| anyhow!("Invalid RPC URL: {}", e))?;
    let to = Address::from_str(contract).map_err(|_| anyhow!("Invalid contract address"))?;
    let tx = TransactionRequest::new().to(to).data(Bytes::from(data));
    provider
        .call(&tx.into(), None)
        .await
        .map(|b| b.to_vec())
        .map_err(|e| anyhow!("eth_call failed: {}", e))
}

/// App-level shared image digests (each is the on-chain bytes, e.g. b"sha256:...").
pub async fn get_app_image_hashes(
    rpc_url: &str,
    contract: &str,
    app_id: &str,
) -> Result<Vec<Vec<u8>>> {
    let data = calldata("getAppInfo(string)", vec![Token::String(app_id.to_owned())]);
    let out = call_raw(rpc_url, contract, data).await?;
    let tuple = ParamType::Tuple(vec![
        ParamType::Bytes,
        ParamType::Bytes,
        ParamType::Array(Box::new(ParamType::Bytes)),
        ParamType::Address,
        ParamType::Uint(256),
    ]);
    let tokens = decode(&[tuple], &out).map_err(|e| anyhow!("decode getAppInfo: {}", e))?;
    if let Some(Token::Tuple(fields)) = tokens.into_iter().next() {
        if let Token::Array(arr) = &fields[2] {
            return Ok(arr
                .iter()
                .filter_map(|t| match t {
                    Token::Bytes(b) => Some(b.clone()),
                    _ => None,
                })
                .collect());
        }
    }
    Err(anyhow!("unexpected getAppInfo return shape"))
}

/// Registered node signer addresses for an app (getNodeList).
pub async fn get_node_list(rpc_url: &str, contract: &str, app_id: &str) -> Result<Vec<Address>> {
    let data = calldata("getNodeList(string)", vec![Token::String(app_id.to_owned())]);
    let out = call_raw(rpc_url, contract, data).await?;
    let tokens = decode(&[ParamType::Array(Box::new(ParamType::Address))], &out)
        .map_err(|e| anyhow!("decode getNodeList: {}", e))?;
    if let Some(Token::Array(arr)) = tokens.into_iter().next() {
        return Ok(arr
            .into_iter()
            .filter_map(|t| match t {
                Token::Address(a) => Some(a),
                _ => None,
            })
            .collect());
    }
    Err(anyhow!("unexpected getNodeList return shape"))
}

/// A node's teeUrl and EFFECTIVE compose/volumes (getNode resolves inherit→default).
pub async fn get_node(
    rpc_url: &str,
    contract: &str,
    app_id: &str,
    signer: Address,
) -> Result<(String, Vec<u8>, Vec<u8>)> {
    let data = calldata(
        "getNode(string,address)",
        vec![Token::String(app_id.to_owned()), Token::Address(signer)],
    );
    let out = call_raw(rpc_url, contract, data).await?;
    // NodeInfo = (string teeUrl, uint256 addedAt, uint256 stakeAmount, bytes composeHash, bytes volumesHash)
    let tuple = ParamType::Tuple(vec![
        ParamType::String,
        ParamType::Uint(256),
        ParamType::Uint(256),
        ParamType::Bytes,
        ParamType::Bytes,
    ]);
    let tokens = decode(&[tuple], &out).map_err(|e| anyhow!("decode getNode: {}", e))?;
    if let Some(Token::Tuple(f)) = tokens.into_iter().next() {
        let tee_url = match &f[0] {
            Token::String(s) => s.clone(),
            _ => String::new(),
        };
        let compose = match &f[3] {
            Token::Bytes(b) => b.clone(),
            _ => vec![],
        };
        let volumes = match &f[4] {
            Token::Bytes(b) => b.clone(),
            _ => vec![],
        };
        return Ok((tee_url, compose, volumes));
    }
    Err(anyhow!("unexpected getNode return shape"))
}

// ─── Transaction sender ───────────────────────────────────────────────────────

async fn send_tx(
    rpc_url: &str,
    private_key_hex: &str,
    contract: Address,
    data: Vec<u8>,
    value: U256,
) -> Result<TxHash> {
    let provider = Provider::<Http>::try_from(rpc_url)
        .map_err(|e| anyhow!("Invalid RPC URL: {}", e))?;

    let chain_id = provider
        .get_chainid()
        .await
        .map_err(|e| anyhow!("Failed to get chain ID: {}", e))?
        .as_u64();

    let key_bytes = hex::decode(private_key_hex.trim_start_matches("0x"))
        .map_err(|e| anyhow!("Invalid private key: {}", e))?;
    let wallet = LocalWallet::from_bytes(&key_bytes)
        .map_err(|e| anyhow!("Invalid private key: {}", e))?
        .with_chain_id(chain_id);

    let from = wallet.address();

    let gas_price = provider
        .get_gas_price()
        .await
        .map_err(|e| anyhow!("Failed to get gas price: {}", e))?;

    let nonce = provider
        .get_transaction_count(from, None)
        .await
        .map_err(|e| anyhow!("Failed to get nonce: {}", e))?;

    let tx = TransactionRequest::new()
        .from(from)
        .to(contract)
        .data(Bytes::from(data.clone()))
        .value(value)
        .gas_price(gas_price)
        .nonce(nonce);

    // Estimate gas
    let gas = provider
        .estimate_gas(&tx.clone().into(), None)
        .await
        .map_err(|e| anyhow!("Failed to estimate gas: {}", e))?;

    let tx = tx.gas(gas * 12 / 10); // 20% buffer

    let signature = wallet
        .sign_transaction(&tx.clone().into())
        .await
        .map_err(|e| anyhow!("Failed to sign transaction: {}", e))?;

    let signed = tx.rlp_signed(&signature);
    let receipt = provider
        .send_raw_transaction(signed)
        .await
        .map_err(|e| anyhow!("Failed to send transaction: {}", e))?
        .await
        .map_err(|e| anyhow!("Failed to get receipt: {}", e))?
        .ok_or_else(|| anyhow!("Transaction dropped from mempool"))?;

    Ok(receipt.transaction_hash)
}

// ─── Hash conversions ─────────────────────────────────────────────────────────

/// Decode a hex string (with or without 0x prefix) to bytes.
pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>> {
    hex::decode(hex.trim_start_matches("0x"))
        .map_err(|e| anyhow!("Invalid hex string '{}': {}", hex, e))
}

/// Combine a sorted map of (key, hex-value) pairs into a single deterministic bytes blob.
/// Encoding: for each entry sorted by key, append "<key>:<value_bytes>\n".
pub fn combine_map_hashes(map: &std::collections::HashMap<String, String>) -> Vec<u8> {
    let mut pairs: Vec<_> = map.iter().collect();
    pairs.sort_by_key(|(k, _)| k.as_str());

    let mut combined = Vec::new();
    for (key, val) in pairs {
        combined.extend_from_slice(key.as_bytes());
        combined.push(b':');
        // val is a hex string; store raw bytes
        if let Ok(b) = hex_to_bytes(val) {
            combined.extend_from_slice(&b);
        } else {
            combined.extend_from_slice(val.as_bytes());
        }
        combined.push(b'\n');
    }
    combined
}

/// Convert a sorted map of (service, digest) to a Vec<bytes> (one entry per service).
pub fn map_to_bytes_array(map: &std::collections::HashMap<String, String>) -> Vec<Vec<u8>> {
    let mut pairs: Vec<_> = map.iter().collect();
    pairs.sort_by_key(|(k, _)| k.as_str());
    pairs
        .into_iter()
        .map(|(_, v)| v.as_bytes().to_vec())
        .collect()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_hex_to_bytes_with_prefix() {
        let result = hex_to_bytes("0xdeadbeef").unwrap();
        assert_eq!(result, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_hex_to_bytes_without_prefix() {
        let result = hex_to_bytes("cafebabe").unwrap();
        assert_eq!(result, vec![0xca, 0xfe, 0xba, 0xbe]);
    }

    #[test]
    fn test_hex_to_bytes_invalid() {
        assert!(hex_to_bytes("0xzzzz").is_err());
    }

    #[test]
    fn test_map_to_bytes_array_empty() {
        let map = HashMap::new();
        let result = map_to_bytes_array(&map);
        assert!(result.is_empty());
    }
}

// ─── Contract calls ───────────────────────────────────────────────────────────

pub struct OnchainParams {
    pub rpc_url: String,
    pub contract: String,
    pub private_key: String,
}

impl OnchainParams {
    fn contract_address(&self) -> Result<Address> {
        Address::from_str(&self.contract).map_err(|_| anyhow!("Invalid contract address"))
    }
}

/// registerApp(string,bytes,bytes,bytes[],address,string)
/// compose/volumes are the app-level shared defaults; the first node inherits them.
pub async fn register_app(
    params: &OnchainParams,
    app_id: &str,
    compose_hash: Vec<u8>,
    volumes_hash: Vec<u8>,
    image_hashes: Vec<Vec<u8>>,
    signer_address: Address,
    tee_url: &str,
    stake_wei: U256,
) -> Result<TxHash> {
    let data = calldata(
        "registerApp(string,bytes,bytes,bytes[],address,string)",
        vec![
            Token::String(app_id.to_owned()),
            Token::Bytes(compose_hash),
            Token::Bytes(volumes_hash),
            Token::Array(image_hashes.into_iter().map(Token::Bytes).collect()),
            Token::Address(signer_address),
            Token::String(tee_url.to_owned()),
        ],
    );
    send_tx(&params.rpc_url, &params.private_key, params.contract_address()?, data, stake_wei).await
}

/// updateApp(string,bytes,bytes,bytes[]) — updates the app-level shared defaults.
/// Per-node overrides are updated via update_node.
pub async fn update_app(
    params: &OnchainParams,
    app_id: &str,
    compose_hash: Vec<u8>,
    volumes_hash: Vec<u8>,
    image_hashes: Vec<Vec<u8>>,
) -> Result<TxHash> {
    let data = calldata(
        "updateApp(string,bytes,bytes,bytes[])",
        vec![
            Token::String(app_id.to_owned()),
            Token::Bytes(compose_hash),
            Token::Bytes(volumes_hash),
            Token::Array(image_hashes.into_iter().map(Token::Bytes).collect()),
        ],
    );
    send_tx(&params.rpc_url, &params.private_key, params.contract_address()?, data, U256::zero()).await
}

/// addNode(string,address,string,bytes,bytes)
pub async fn add_node(
    params: &OnchainParams,
    app_id: &str,
    signer_address: Address,
    tee_url: &str,
    compose_hash: Vec<u8>,
    volumes_hash: Vec<u8>,
    stake_wei: U256,
) -> Result<TxHash> {
    let data = calldata(
        "addNode(string,address,string,bytes,bytes)",
        vec![
            Token::String(app_id.to_owned()),
            Token::Address(signer_address),
            Token::String(tee_url.to_owned()),
            Token::Bytes(compose_hash),
            Token::Bytes(volumes_hash),
        ],
    );
    send_tx(&params.rpc_url, &params.private_key, params.contract_address()?, data, stake_wei).await
}

/// updateNode(string,address,address,string,bytes,bytes)
pub async fn update_node(
    params: &OnchainParams,
    app_id: &str,
    old_signer: Address,
    new_signer: Address,
    tee_url: String,
    compose_hash: Vec<u8>,
    volumes_hash: Vec<u8>,
) -> Result<TxHash> {
    let data = calldata(
        "updateNode(string,address,address,string,bytes,bytes)",
        vec![
            Token::String(app_id.to_owned()),
            Token::Address(old_signer),
            Token::Address(new_signer),
            Token::String(tee_url),
            Token::Bytes(compose_hash),
            Token::Bytes(volumes_hash),
        ],
    );
    send_tx(&params.rpc_url, &params.private_key, params.contract_address()?, data, U256::zero()).await
}

/// withdraw()
pub async fn withdraw(params: &OnchainParams) -> Result<TxHash> {
    let data = selector("withdraw()").to_vec();
    send_tx(&params.rpc_url, &params.private_key, params.contract_address()?, data, U256::zero()).await
}

/// removeNode(string,address)
pub async fn remove_node(
    params: &OnchainParams,
    app_id: &str,
    signer_address: Address,
) -> Result<TxHash> {
    let data = calldata(
        "removeNode(string,address)",
        vec![
            Token::String(app_id.to_owned()),
            Token::Address(signer_address),
        ],
    );
    send_tx(&params.rpc_url, &params.private_key, params.contract_address()?, data, U256::zero()).await
}

/// authorizeInvalidator(string,address)
pub async fn authorize_invalidator(
    params: &OnchainParams,
    app_id: &str,
    invalidator: Address,
) -> Result<TxHash> {
    let data = calldata(
        "authorizeInvalidator(string,address)",
        vec![
            Token::String(app_id.to_owned()),
            Token::Address(invalidator),
        ],
    );
    send_tx(&params.rpc_url, &params.private_key, params.contract_address()?, data, U256::zero()).await
}

/// revokeInvalidator(string,address)
pub async fn revoke_invalidator(
    params: &OnchainParams,
    app_id: &str,
    invalidator: Address,
) -> Result<TxHash> {
    let data = calldata(
        "revokeInvalidator(string,address)",
        vec![
            Token::String(app_id.to_owned()),
            Token::Address(invalidator),
        ],
    );
    send_tx(&params.rpc_url, &params.private_key, params.contract_address()?, data, U256::zero()).await
}

