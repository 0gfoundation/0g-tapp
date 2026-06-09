#!/bin/bash

# Withdraw all balance from app address to owner
# Usage:
#   ./withdraw_balance.sh [OPTIONS]
#
# Examples:
#   ./withdraw_balance.sh --host 39.97.63.199 --app-id test-app --rpc-url https://evmrpc-testnet.0g.ai --chain-id 16602 --use-whitelist
#
# Security Warning:
#   This command will transfer ALL balance from the app's address.
#   Only run this from a secure, trusted environment.

set -e

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Default configuration
DEFAULT_HOST="localhost"
DEFAULT_PORT="50051"
DEFAULT_APP_ID=""
DEFAULT_RPC_URL=""
DEFAULT_CHAIN_ID=""
DEFAULT_RECIPIENT=""

# Pre-configured addresses (for reference only)
OWNER_ADDRESS="0xYourOwnerAddressHere"
WHITELIST_ADDRESS="0xYourWhitelistAddressHere"

# Private keys from environment variables (recommended for security)
# Set these in your environment:
#   export TAPP_OWNER_PRIVATE_KEY="0x..."
#   export TAPP_WHITELIST_PRIVATE_KEY="0x..."
OWNER_PRIVATE_KEY="${TAPP_OWNER_PRIVATE_KEY:-}"
WHITELIST_PRIVATE_KEY="${TAPP_WHITELIST_PRIVATE_KEY:-}"

# Parse command line arguments
TARGET_HOST="$DEFAULT_HOST"
TARGET_PORT="$DEFAULT_PORT"
APP_ID=""
RPC_URL=""
CHAIN_ID=""
RECIPIENT=""
PRIVATE_KEY=""
USE_OWNER=false
USE_WHITELIST=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --host)
            TARGET_HOST="$2"
            shift 2
            ;;
        --port)
            TARGET_PORT="$2"
            shift 2
            ;;
        --app-id)
            APP_ID="$2"
            shift 2
            ;;
        --rpc-url)
            RPC_URL="$2"
            shift 2
            ;;
        --chain-id)
            CHAIN_ID="$2"
            shift 2
            ;;
        --recipient)
            RECIPIENT="$2"
            shift 2
            ;;
        --private-key)
            PRIVATE_KEY="$2"
            shift 2
            ;;
        --use-owner)
            USE_OWNER=true
            shift
            ;;
        --use-whitelist)
            USE_WHITELIST=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --host HOST              TAPP server host (default: localhost)"
            echo "  --port PORT              TAPP server port (default: 50051)"
            echo "  --app-id APP_ID          Application identifier (required)"
            echo "  --rpc-url RPC_URL        Chain RPC endpoint URL (required)"
            echo "  --chain-id CHAIN_ID      Chain ID (required, e.g., 1 for mainnet, 16602 for Testnet)"
            echo "  --recipient ADDRESS      Custom recipient address (optional, defaults to TAPP owner)"
            echo "  --private-key KEY        Private key for signing (hex with or without 0x prefix)"
            echo "  --use-owner              Use pre-configured owner credentials"
            echo "  --use-whitelist          Use pre-configured whitelist user credentials"
            echo "  --help, -h               Show this help message"
            echo ""
            echo "Examples:"
            echo "  # Withdraw to owner (Sepolia testnet)"
            echo "  export TAPP_OWNER_PRIVATE_KEY=\"0x...\""
            echo "  $0 --host localhost --app-id my-app \\"
            echo "     --rpc-url https://evmrpc-testnet.0g.ai \\"
            echo "     --chain-id 16602 --use-owner"
            echo ""
            echo "  # Withdraw to custom address (Ethereum mainnet)"
            echo "  $0 --host localhost --app-id my-app \\"
            echo "     --rpc-url https://evmrpc-testnet.0g.ai \\"
            echo "     --chain-id 16602 --recipient 0x1234... --private-key 0xabcd..."
            echo ""
            echo "Common Chain IDs:"
            echo "  16602     - Testnet"
            echo "  16601     - Mainnet"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Determine which credentials to use
if [ "$USE_OWNER" = true ]; then
    if [ -z "$OWNER_PRIVATE_KEY" ]; then
        echo "Error: Owner private key not found"
        echo "Please set the TAPP_OWNER_PRIVATE_KEY environment variable:"
        echo "  export TAPP_OWNER_PRIVATE_KEY=\"0x...\""
        exit 1
    fi
    PRIVATE_KEY="$OWNER_PRIVATE_KEY"
    echo "Using owner credentials: $OWNER_ADDRESS"
elif [ "$USE_WHITELIST" = true ]; then
    if [ -z "$WHITELIST_PRIVATE_KEY" ]; then
        echo "Error: Whitelist private key not found"
        echo "Please set the TAPP_WHITELIST_PRIVATE_KEY environment variable:"
        echo "  export TAPP_WHITELIST_PRIVATE_KEY=\"0x...\""
        exit 1
    fi
    PRIVATE_KEY="$WHITELIST_PRIVATE_KEY"
    echo "Using whitelist user credentials: $WHITELIST_ADDRESS"
elif [ -z "$PRIVATE_KEY" ]; then
    echo "Error: Private key is required"
    echo ""
    echo "Options:"
    echo "  1. Use --private-key KEY"
    echo "  2. Use --use-owner with TAPP_OWNER_PRIVATE_KEY env var"
    echo "  3. Use --use-whitelist with TAPP_WHITELIST_PRIVATE_KEY env var"
    exit 1
fi

TARGET_ADDRESS="$TARGET_HOST:$TARGET_PORT"

# Validate required parameters
if [ -z "$APP_ID" ]; then
    echo "Error: Application ID is required"
    echo "Use --app-id APP_ID or --help for more information"
    exit 1
fi

if [ -z "$RPC_URL" ]; then
    echo "Error: RPC URL is required"
    echo "Use --rpc-url RPC_URL or --help for more information"
    exit 1
fi

if [ -z "$CHAIN_ID" ]; then
    echo "Error: Chain ID is required"
    echo "Use --chain-id CHAIN_ID or --help for more information"
    exit 1
fi

echo "Checking dependencies..."
echo "========================================"

# Track if all dependencies are met
deps_ok=true
missing_deps=()

# Check Python 3
if ! command -v python3 &> /dev/null; then
    echo "✗ python3: Not found"
    deps_ok=false
    missing_deps+=("python3")
else
    py_version=$(python3 --version 2>&1 | awk '{print $2}')
    echo "✓ python3: $py_version"
fi

# Check eth-account
if ! python3 -c "import eth_account" 2>/dev/null; then
    echo "✗ eth-account: Not installed"
    deps_ok=false
    missing_deps+=("eth-account")
else
    echo "✓ eth-account: installed"
fi

# Check jq
if ! command -v jq &> /dev/null; then
    echo "✗ jq: Not found"
    deps_ok=false
    missing_deps+=("jq")
else
    jq_version=$(jq --version 2>&1)
    echo "✓ jq: $jq_version"
fi

# Check grpcurl
if ! command -v grpcurl &> /dev/null; then
    echo "✗ grpcurl: Not found"
    deps_ok=false
    missing_deps+=("grpcurl")
else
    grpcurl_version=$(grpcurl -version 2>&1 | head -1)
    echo "✓ grpcurl: $grpcurl_version"
fi

# Check proto file
proto_file="$SCRIPT_DIR/../proto/tapp_service.proto"
if [ ! -f "$proto_file" ]; then
    echo "✗ proto file: Not found at $proto_file"
    deps_ok=false
    missing_deps+=("tapp_service.proto")
else
    echo "✓ proto file: found"
fi

# Check if sign_message.py exists
sign_script="$SCRIPT_DIR/sign_message.py"
if [ ! -f "$sign_script" ]; then
    echo "✗ sign_message.py: Not found at $sign_script"
    deps_ok=false
    missing_deps+=("sign_message.py")
else
    echo "✓ sign_message.py: found"
fi

echo "========================================"

# Exit if dependencies are missing
if [ "$deps_ok" = false ]; then
    echo ""
    echo "❌ Missing dependencies: ${missing_deps[*]}"
    exit 1
fi

echo "✅ All dependencies satisfied"
echo ""

echo "Withdrawal Configuration:"
echo "======================================"
echo "TAPP Server: $TARGET_ADDRESS"
echo "App ID: $APP_ID"
echo "RPC URL: ${RPC_URL:0:50}..."
echo "Chain ID: $CHAIN_ID"
if [ -n "$RECIPIENT" ]; then
    echo "Recipient: $RECIPIENT (custom)"
else
    echo "Recipient: (TAPP owner - will be set automatically)"
fi
echo "======================================"
echo ""

# Sign the message
echo "Generating signature..."
METHOD_NAME="WithdrawBalance"

# Call Python signing script
SIGN_OUTPUT=$(python3 "$sign_script" "$METHOD_NAME" "$PRIVATE_KEY" 2>&1)

if [ $? -ne 0 ]; then
    echo "Error: Signature generation failed"
    echo "$SIGN_OUTPUT"
    exit 1
fi

SIGNATURE=$(echo "$SIGN_OUTPUT" | cut -d',' -f1)
TIMESTAMP=$(echo "$SIGN_OUTPUT" | cut -d',' -f2)
SIGNER_ADDRESS=$(echo "$SIGN_OUTPUT" | cut -d',' -f3)

echo "Signer: $SIGNER_ADDRESS"
echo "Signature: ${SIGNATURE:0:20}...${SIGNATURE: -20}"
echo "Timestamp: $TIMESTAMP"
echo "======================================"
echo ""

# Create request JSON
request_json=$(jq -n \
    --arg app_id "$APP_ID" \
    --arg rpc_url "$RPC_URL" \
    --argjson chain_id "$CHAIN_ID" \
    --arg recipient "$RECIPIENT" \
    '{
        app_id: $app_id,
        rpc_url: $rpc_url,
        chain_id: $chain_id,
        recipient: $recipient
    }')

echo "Request:"
echo "--------------------------------------"
echo "$request_json"
echo "--------------------------------------"
echo ""

echo "⚠️  WARNING: This will transfer ALL balance from the app's address!"
echo "Press Ctrl+C to cancel, or Enter to continue..."
read -r

echo "Sending WithdrawBalance request..."
echo ""

# Send request with signature headers and capture both stdout and stderr
set +e  # Don't exit on error
response=$(printf "%s" "$request_json" | tr -d '\n' | \
    grpcurl -plaintext \
        -H "x-signature: $SIGNATURE" \
        -H "x-timestamp: $TIMESTAMP" \
        -import-path "$SCRIPT_DIR/../proto" \
        -proto tapp_service.proto \
        -d @ \
        "$TARGET_ADDRESS" \
        tapp_service.TappService/WithdrawBalance 2>&1)
exit_code=$?
set -e

echo "Response:"
echo "--------------------------------------"
echo "$response"
echo "--------------------------------------"
echo ""