#!/bin/bash

# Claim this tapp: set owner + runtime config in one measured step.
# The signer becomes the tapp owner; the KBS config is applied
# immediately. The full config is extended into the runtime measurement
# (claim_config event) so verifiers see it in the evidence.
#
# Usage:
#   export TAPP_OWNER_PRIVATE_KEY="0x..."
#   ./claim_owner.sh [--host HOST] [--port PORT] [--private-key KEY] \
#     [--kbs-urls "url1,url2"]
#
# Tip: prefer `tapp-cli claim-config` — it also verifies the claim end-to-end.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

TARGET_HOST="localhost"
TARGET_PORT="50051"
PRIVATE_KEY="${TAPP_OWNER_PRIVATE_KEY:-}"
KBS_URLS=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --host) TARGET_HOST="$2"; shift 2 ;;
    --port) TARGET_PORT="$2"; shift 2 ;;
    --private-key) PRIVATE_KEY="$2"; shift 2 ;;
    --kbs-urls) KBS_URLS="$2"; shift 2 ;;
    --help|-h)
      echo "Usage: $0 [--host HOST] [--port PORT] [--private-key KEY]"
      echo "         [--kbs-urls url1,url2]"
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

# The signature below is body-bound, which only tapp-server >= 0.9.0 can read. An
# older server recovers some unrelated address from it — and ClaimConfig accepts
# any signer, so it would record THAT as the owner, leaving the node unmanageable
# until the VM is reset. So the version is checked first, and anything older (or
# unreadable) is refused rather than sent.
SERVER_VERSION=$(grpcurl -plaintext -import-path "$SCRIPT_DIR/../proto" -proto tapp_service.proto \
  "$TARGET_ADDRESS" tapp_service.TappService/GetTappInfo 2>/dev/null | jq -r '.version // empty')
if ! [[ "$SERVER_VERSION" =~ ^v?([0-9]+)\.([0-9]+) ]] \
   || { [ "${BASH_REMATCH[1]}" -eq 0 ] && [ "${BASH_REMATCH[2]}" -lt 9 ]; }; then
  echo "Error: tapp-server reports version '${SERVER_VERSION:-unknown}'. This script signs for" >&2
  echo "tapp-server >= 0.9.0; an older one would record an unrelated address as the owner." >&2
  echo "Claim it with: tapp-cli --legacy-sign claim-config" >&2
  exit 1
fi

KBS_ARRAY=$(echo "$KBS_URLS" | tr ',' '\n' | grep -v '^$' | jq -R . | jq -s .)
request=$(jq -n --argjson kbs_node_urls "$KBS_ARRAY" '{kbs_node_urls:$kbs_node_urls}')

# Sign the exact request: the signer becomes the owner, so the signature must
# be over the method the server checks (ClaimConfig) and the body it receives.
echo "Generating signature..."
SIGN_OUTPUT=$(printf "%s" "$request" | python3 "$SCRIPT_DIR/sign_message.py" "ClaimConfig" "$PRIVATE_KEY" -)
SIGNATURE=$(echo "$SIGN_OUTPUT" | cut -d',' -f1)
TIMESTAMP=$(echo "$SIGN_OUTPUT" | cut -d',' -f2)
SIGNER_ADDRESS=$(echo "$SIGN_OUTPUT" | cut -d',' -f3)

echo "Claiming config of $TARGET_ADDRESS as $SIGNER_ADDRESS ..."

response=$(echo "$request" | grpcurl -plaintext \
  -H "x-signature: $SIGNATURE" \
  -H "x-timestamp: $TIMESTAMP" \
  -H "x-signature-version: 2" \
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
