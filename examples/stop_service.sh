#!/bin/bash

# Stop a specific service within an application with Ethereum signature authentication
# Usage:
#   ./stop_service.sh [OPTIONS]
#
# Examples:
#   ./stop_service.sh --host 39.97.63.199 --app-id test-nginx-app --service web --use-owner
#   ./stop_service.sh --app-id my-app --service database --use-owner

set -e

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Default configuration
DEFAULT_HOST="localhost"
DEFAULT_PORT="50051"

# Pre-configured addresses (for reference only)
OWNER_ADDRESS="0xYourOwnerAddressHere"

# Private keys from environment variables (recommended for security)
OWNER_PRIVATE_KEY="${TAPP_OWNER_PRIVATE_KEY:-}"

# Parse command line arguments
TARGET_HOST="$DEFAULT_HOST"
TARGET_PORT="$DEFAULT_PORT"
APP_ID=""
SERVICE_NAME=""
PRIVATE_KEY=""
USE_OWNER=false

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
        --service)
            SERVICE_NAME="$2"
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
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Stop a specific service within an application"
            echo ""
            echo "Options:"
            echo "  --host HOST             gRPC server host (default: $DEFAULT_HOST)"
            echo "  --port PORT             gRPC server port (default: $DEFAULT_PORT)"
            echo "  --app-id APP_ID         Application ID (required)"
            echo "  --service SERVICE       Service name from docker-compose.yml (required)"
            echo "  --private-key KEY       Private key for signing (required unless using --use-owner)"
            echo "  --use-owner             Use pre-configured owner credentials (requires TAPP_OWNER_PRIVATE_KEY env var)"
            echo "  --help, -h              Show this help message"
            echo ""
            echo "Environment variables:"
            echo "  TAPP_OWNER_PRIVATE_KEY       Private key for owner account"
            echo ""
            echo "Examples:"
            echo "  $0 --app-id test-nginx-app --service web --use-owner"
            echo "  $0 --host 39.97.63.199 --app-id my-app --service database --use-owner"
            echo ""
            echo "Pre-configured user:"
            echo "  Owner: $OWNER_ADDRESS"
            echo ""
            echo "Note: This operation requires Owner permission"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

TARGET_ADDRESS="$TARGET_HOST:$TARGET_PORT"

# Validate required parameters
if [ -z "$APP_ID" ]; then
    echo "❌ Error: --app-id is required"
    echo "Use --help for usage information"
    exit 1
fi

if [ -z "$SERVICE_NAME" ]; then
    echo "❌ Error: --service is required"
    echo "Use --help for usage information"
    exit 1
fi

# Determine which private key to use
if [ "$USE_OWNER" = true ]; then
    if [ -z "$OWNER_PRIVATE_KEY" ]; then
        echo "❌ Error: TAPP_OWNER_PRIVATE_KEY environment variable is not set"
        echo "Please set it with: export TAPP_OWNER_PRIVATE_KEY='0x...'"
        exit 1
    fi
    PRIVATE_KEY="$OWNER_PRIVATE_KEY"
    SIGNER_ADDRESS="$OWNER_ADDRESS"
elif [ -z "$PRIVATE_KEY" ]; then
    echo "❌ Error: No private key provided"
    echo "Use --private-key or --use-owner"
    exit 1
fi

# Quick dependency check
missing_deps=()

if ! command -v grpcurl &> /dev/null; then
    missing_deps+=("grpcurl")
fi

if ! command -v jq &> /dev/null; then
    missing_deps+=("jq")
fi

# Check proto file
proto_file="$SCRIPT_DIR/../proto/tapp_service.proto"
if [ ! -f "$proto_file" ]; then
    missing_deps+=("tapp_service.proto")
fi

if [ ${#missing_deps[@]} -gt 0 ]; then
    echo "❌ Missing dependencies: ${missing_deps[*]}"
    exit 1
fi

# Check sign_message.py
sign_script="$SCRIPT_DIR/sign_message.py"
if [ ! -f "$sign_script" ]; then
  echo "✗ sign_message.py: Not found at $sign_script"
  exit 1
else
  echo "✓ sign_message.py: found"
fi

# Display configuration
echo "======================================"
echo "StopService Request"
echo "======================================"
echo "Target:             $TARGET_ADDRESS"
echo "App ID:             $APP_ID"
echo "Service:            $SERVICE_NAME"
echo "Signer:             $SIGNER_ADDRESS"
echo "======================================"
echo ""

# Build request JSON
request_json=$(jq -n \
    --arg app_id "$APP_ID" \
    --arg service_name "$SERVICE_NAME" \
    '{
        app_id: $app_id,
        service_name: $service_name
    }')

echo "Request:"
echo "--------------------------------------"
echo "$request_json" | jq '.'
echo "--------------------------------------"
echo ""

# Sign message with private key
echo "Generating signature..."
SIGN_OUTPUT=$(python3 "$sign_script" "StopService" "$PRIVATE_KEY" 2>&1)
if [ $? -ne 0 ]; then
  echo "Error generating signature: $SIGN_OUTPUT"
  exit 1
fi

SIGNATURE=$(echo "$SIGN_OUTPUT" | cut -d',' -f1)
TIMESTAMP=$(echo "$SIGN_OUTPUT" | cut -d',' -f2)
SIGNER_ADDRESS=$(echo "$SIGN_OUTPUT" | cut -d',' -f3)

echo "Signer: $SIGNER_ADDRESS"
echo "Signature: ${SIGNATURE:0:20}...${SIGNATURE: -20}"
echo "Timestamp: $TIMESTAMP"
echo "========================================"
echo ""

# Call gRPC service with signature headers
set +e  # Don't exit on error
response=$(printf "%s" "$request_json" | tr -d '\n' | grpcurl -plaintext \
    -H "x-signature: $SIGNATURE" \
    -H "x-timestamp: $TIMESTAMP" \
    -import-path "$SCRIPT_DIR/../proto" \
    -proto tapp_service.proto \
    -d @ \
    "$TARGET_ADDRESS" \
    tapp_service.TappService/StopService 2>&1)
exit_code=$?
set -e

echo "Response:"
echo "--------------------------------------"
echo "$response"
echo "--------------------------------------"