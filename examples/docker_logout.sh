#!/bin/bash

# Docker logout from registry with Ethereum signature authentication
# Usage:
#   ./docker_logout.sh [OPTIONS]
#
# Examples:
#   ./docker_logout.sh --host 39.97.63.199 --registry eliza-registry-vpc.ap-southeast-1.cr.aliyuncs.com --use-owner
#   ./docker_logout.sh --registry docker.io --use-whitelist
#   ./docker_logout.sh --use-owner  # Docker Hub

set -e

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Default configuration
DEFAULT_HOST="localhost"
DEFAULT_PORT="50051"

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
REGISTRY=""
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
        --registry)
            REGISTRY="$2"
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
            echo "Docker logout from registry"
            echo ""
            echo "Options:"
            echo "  --host HOST             gRPC server host (default: $DEFAULT_HOST)"
            echo "  --port PORT             gRPC server port (default: $DEFAULT_PORT)"
            echo "  --registry REGISTRY     Docker registry URL (default: docker.io)"
            echo "                          Examples: docker.io, eliza-registry-vpc.ap-southeast-1.cr.aliyuncs.com"
            echo "  --private-key KEY       Private key for signing (required unless using presets)"
            echo "  --use-owner             Use pre-configured owner credentials (requires TAPP_OWNER_PRIVATE_KEY env var)"
            echo "  --use-whitelist         Use pre-configured whitelist user credentials (requires TAPP_WHITELIST_PRIVATE_KEY env var)"
            echo "  --help, -h              Show this help message"
            echo ""
            echo "Environment variables:"
            echo "  TAPP_OWNER_PRIVATE_KEY       Private key for owner account"
            echo "  TAPP_WHITELIST_PRIVATE_KEY   Private key for whitelist account"
            echo ""
            echo "Examples:"
            echo "  # Logout from Aliyun registry"
            echo "  $0 --host 39.97.63.199 --registry eliza-registry-vpc.ap-southeast-1.cr.aliyuncs.com --use-owner"
            echo ""
            echo "  # Logout from Docker Hub"
            echo "  $0 --use-owner"
            echo ""
            echo "Pre-configured users:"
            echo "  Owner: $OWNER_ADDRESS"
            echo "  Whitelist: $WHITELIST_ADDRESS"
            echo ""
            echo "Note: This operation requires Owner or Whitelist permission"
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

# Determine which private key to use
if [ "$USE_OWNER" = true ]; then
    if [ -z "$OWNER_PRIVATE_KEY" ]; then
        echo "❌ Error: TAPP_OWNER_PRIVATE_KEY environment variable is not set"
        echo "Please set it with: export TAPP_OWNER_PRIVATE_KEY='0x...'"
        exit 1
    fi
    PRIVATE_KEY="$OWNER_PRIVATE_KEY"
    SIGNER_ADDRESS="$OWNER_ADDRESS"
elif [ "$USE_WHITELIST" = true ]; then
    if [ -z "$WHITELIST_PRIVATE_KEY" ]; then
        echo "❌ Error: TAPP_WHITELIST_PRIVATE_KEY environment variable is not set"
        echo "Please set it with: export TAPP_WHITELIST_PRIVATE_KEY='0x...'"
        exit 1
    fi
    PRIVATE_KEY="$WHITELIST_PRIVATE_KEY"
    SIGNER_ADDRESS="$WHITELIST_ADDRESS"
elif [ -z "$PRIVATE_KEY" ]; then
    echo "❌ Error: No private key provided"
    echo "Use --private-key, --use-owner, or --use-whitelist"
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
    echo ""
    for dep in "${missing_deps[@]}"; do
        case "$dep" in
            "grpcurl")
                echo "• grpcurl: https://github.com/fullstorydev/grpcurl/releases"
                ;;
            "jq")
                echo "• jq: https://stedolan.github.io/jq/download/"
                ;;
            "tapp_service.proto")
                echo "• proto file not found at: $proto_file"
                ;;
        esac
    done
    exit 1
fi

# Check sign_message.py
sign_script="$SCRIPT_DIR/sign_message.py"
if [ ! -f "$sign_script" ]; then
  echo "✗ sign_message.py: Not found at $sign_script"
  deps_ok=false
  missing_deps+=("sign_message.py")
else
  echo "✓ sign_message.py: found"
fi

# Display configuration
REGISTRY_DISPLAY="${REGISTRY:-docker.io (default)}"
echo "======================================"
echo "DockerLogout Request"
echo "======================================"
echo "Target:             $TARGET_ADDRESS"
echo "Registry:           $REGISTRY_DISPLAY"
echo "Signer:             $SIGNER_ADDRESS"
echo "======================================"
echo ""

# Generate timestamp (unix timestamp in seconds)
TIMESTAMP=$(date +%s)

# Build request JSON
request_json=$(jq -n \
    --arg registry "$REGISTRY" \
    '{
        registry: $registry
    }')

echo "Request:"
echo "--------------------------------------"
echo "$request_json" | jq '.'
echo "--------------------------------------"
echo ""

# Sign message with private key
echo "Generating signature..."
SIGN_OUTPUT=$(python3 "$sign_script" "DockerLogout" "$PRIVATE_KEY" 2>&1)
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
    tapp_service.TappService/DockerLogout 2>&1)
exit_code=$?
set -e

echo "Response:"
echo "--------------------------------------"
echo "$response"
echo "--------------------------------------"
