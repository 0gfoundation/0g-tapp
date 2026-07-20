#!/bin/bash

# Claim this tapp: set owner + runtime config in one measured step.
# The signer becomes the tapp owner; chain and KBS config are applied
# immediately. The full config is extended into the runtime measurement
# (claim_config event) so verifiers see it in the evidence.
#
# Usage:
#   export TAPP_OWNER_PRIVATE_KEY="0x..."
#   ./claim_owner.sh [--host HOST] [--port PORT] [--private-key KEY] \
#     [--chain-rpc-url URL] [--chain-contract 0x...] [--kbs-urls "url1,url2"]
#
# Tip: prefer `tapp-cli claim-config` — it also verifies the claim end-to-end.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

TARGET_HOST="localhost"
TARGET_PORT="50051"
PRIVATE_KEY="${TAPP_OWNER_PRIVATE_KEY:-}"
CHAIN_RPC_URL=""
CHAIN_CONTRACT=""
KBS_URLS=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --host) TARGET_HOST="$2"; shift 2 ;;
    --port) TARGET_PORT="$2"; shift 2 ;;
    --private-key) PRIVATE_KEY="$2"; shift 2 ;;
    --chain-rpc-url) CHAIN_RPC_URL="$2"; shift 2 ;;
    --chain-contract) CHAIN_CONTRACT="$2"; shift 2 ;;
    --kbs-urls) KBS_URLS="$2"; shift 2 ;;
    --help|-h)
      echo "Usage: $0 [--host HOST] [--port PORT] [--private-key KEY]"
      echo "         [--chain-rpc-url URL] [--chain-contract 0x...] [--kbs-urls url1,url2]"
      echo "Claims this tapp (owner + runtime config); the signer becomes owner."
      echo "Private key from --private-key or TAPP_OWNER_PRIVATE_KEY env var."
      exit 0
      ;;
    *) echo "Unknown option: $1 (use --help)"; exit 1 ;;
  esac
done

if [ -z "$PRIVATE_KEY" ]; then
  echo "Error: private key required (--private-key or TAPP_OWNER_PRIVATE_KEY)"
  exit 1
fi

for dep in python3 jq grpcurl; do
  command -v "$dep" >/dev/null || { echo "Missing dependency: $dep"; exit 1; }
done

TARGET_ADDRESS="$TARGET_HOST:$TARGET_PORT"

echo "Generating signature..."
SIGN_OUTPUT=$(python3 "$SCRIPT_DIR/sign_message.py" "ClaimOwner" "$PRIVATE_KEY")
SIGNATURE=$(echo "$SIGN_OUTPUT" | cut -d',' -f1)
TIMESTAMP=$(echo "$SIGN_OUTPUT" | cut -d',' -f2)
SIGNER_ADDRESS=$(echo "$SIGN_OUTPUT" | cut -d',' -f3)

echo "Claiming config of $TARGET_ADDRESS as $SIGNER_ADDRESS ..."
KBS_ARRAY=$(echo "$KBS_URLS" | tr ',' '\n' | jq -R . | jq -s .)
request=$(jq -n \
  --arg chain_rpc_url "$CHAIN_RPC_URL" \
  --arg chain_contract_address "$CHAIN_CONTRACT" \
  --argjson kbs_node_urls "$KBS_ARRAY" \
  '{chain_rpc_url:$chain_rpc_url,chain_contract_address:$chain_contract_address,kbs_node_urls:$kbs_node_urls}')

response=$(echo "$request" | grpcurl -plaintext \
  -H "x-signature: $SIGNATURE" \
  -H "x-timestamp: $TIMESTAMP" \
  -import-path "$SCRIPT_DIR/../proto" \
  -proto tapp_service.proto \
  -d @ \
  "$TARGET_ADDRESS" \
  tapp_service.TappService/ClaimConfig)

echo "$response"

if echo "$response" | jq -e '.success == true' > /dev/null 2>&1; then
  echo "✅ Config claimed by $(echo "$response" | jq -r '.ownerAddress')"
else
  echo "❌ Claim failed"
  exit 1
fi
