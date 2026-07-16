#!/bin/bash

# Claim ownership of an UNCLAIMED tapp (first-come-first-served).
# The signer becomes the tapp owner; the claim is extended into the runtime
# measurement (claim_owner event) so verifiers see it in the evidence.
#
# Usage:
#   export TAPP_OWNER_PRIVATE_KEY="0x..."
#   ./claim_owner.sh [--host HOST] [--port PORT] [--private-key KEY]
#
# Tip: prefer `tapp-cli claim-owner` — it also verifies the claim end-to-end.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

TARGET_HOST="localhost"
TARGET_PORT="50051"
PRIVATE_KEY="${TAPP_OWNER_PRIVATE_KEY:-}"

while [[ $# -gt 0 ]]; do
  case $1 in
    --host) TARGET_HOST="$2"; shift 2 ;;
    --port) TARGET_PORT="$2"; shift 2 ;;
    --private-key) PRIVATE_KEY="$2"; shift 2 ;;
    --help|-h)
      echo "Usage: $0 [--host HOST] [--port PORT] [--private-key KEY]"
      echo "Claims ownership of an unclaimed tapp; the signer becomes owner."
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

echo "Claiming ownership of $TARGET_ADDRESS as $SIGNER_ADDRESS ..."
response=$(grpcurl -plaintext \
  -H "x-signature: $SIGNATURE" \
  -H "x-timestamp: $TIMESTAMP" \
  -import-path "$SCRIPT_DIR/../proto" \
  -proto tapp_service.proto \
  -d '{}' \
  "$TARGET_ADDRESS" \
  tapp_service.TappService/ClaimOwner)

echo "$response"

if echo "$response" | jq -e '.success == true' > /dev/null 2>&1; then
  echo "✅ Ownership claimed by $(echo "$response" | jq -r '.ownerAddress')"
else
  echo "❌ Claim failed"
  exit 1
fi
