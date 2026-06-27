#!/bin/bash

# Get application key from TAPP service
# Usage:
#   ./get_app_key.sh [OPTIONS]
#
# Examples:
#   ./get_app_key.sh --host 39.97.63.199 --app-id test-nginx-app
#   ./get_app_key.sh --host 39.97.63.199 --app-id test-nginx-app --key-type ethereum

set -e

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Default configuration
DEFAULT_HOST="localhost"
DEFAULT_PORT="50051"
DEFAULT_APP_ID="test-nginx-app"
DEFAULT_KEY_TYPE="ethereum"
DEFAULT_X25519="true"
# Parse command line arguments
TARGET_HOST="$DEFAULT_HOST"
TARGET_PORT="$DEFAULT_PORT"
SOCKET_PATH=""
APP_ID=""
KEY_TYPE=""

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
        --socket)
            SOCKET_PATH="$2"
            shift 2
            ;;
        --app-id)
            APP_ID="$2"
            shift 2
            ;;
        --key-type)
            KEY_TYPE="$2"
            shift 2
            ;;
        --x25519)
            X25519="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --host HOST             gRPC server host (default: $DEFAULT_HOST)"
            echo "  --port PORT             gRPC server port (default: $DEFAULT_PORT)"
            echo "  --socket PATH           Unix socket path (overrides host/port)"
            echo "  --app-id APP_ID         Application ID (default: $DEFAULT_APP_ID)"
            echo "  --key-type KEY_TYPE     Key type (default: $DEFAULT_KEY_TYPE)"
            echo "  --x25519 X25519         X25519 key type (default: true)"
            echo "  --help, -h              Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0 --host 39.97.63.199 --app-id test-nginx-app"
            echo "  $0 --host 39.97.63.199 --app-id test-nginx-app --key-type ethereum"
            echo ""
            echo "Legacy positional format also supported:"
            echo "  $0 HOST PORT APP_ID KEY_TYPE"
            exit 0
            ;;
        *)
            # Support legacy positional arguments for backward compatibility
            # Original order: HOST PORT APP_ID KEY_TYPE
            if [ "$TARGET_HOST" = "$DEFAULT_HOST" ]; then
                TARGET_HOST="$1"
            elif [ "$TARGET_PORT" = "$DEFAULT_PORT" ]; then
                TARGET_PORT="$1"
            elif [ -z "$APP_ID" ]; then
                APP_ID="$1"
            elif [ -z "$KEY_TYPE" ]; then
                KEY_TYPE="$1"
            else
                echo "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
            fi
            shift
            ;;
    esac
done

if [ -n "$SOCKET_PATH" ]; then
    TARGET_ADDRESS="$SOCKET_PATH"
    GRPCURL_TRANSPORT=(-unix -plaintext "$SOCKET_PATH")
else
    TARGET_ADDRESS="$TARGET_HOST:$TARGET_PORT"
    GRPCURL_TRANSPORT=(-plaintext "$TARGET_ADDRESS")
fi

# Apply defaults
if [ -z "$APP_ID" ]; then
    APP_ID="$DEFAULT_APP_ID"
fi

if [ -z "$KEY_TYPE" ]; then
    KEY_TYPE="$DEFAULT_KEY_TYPE"
fi

if [ -z "$X25519" ]; then
    X25519="$DEFAULT_X25519"
fi

# Validate app ID
if [ -z "$APP_ID" ]; then
    echo "Error: Application ID cannot be empty"
    echo ""
    echo "Usage: $0 --host HOST --port PORT --app-id APP_ID"
    echo "Use --help for more information"
    exit 1
fi

# Quick dependency check
missing_deps=()

if ! command -v grpcurl &> /dev/null; then
    missing_deps+=("grpcurl")
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
            "tapp_service.proto")
                echo "• proto file not found at: $proto_file"
                ;;
        esac
    done
    exit 1
fi

# Display configuration
echo "======================================"
echo "GetAppKey Request"
echo "======================================"
echo "Target:        $TARGET_ADDRESS"
echo "App ID:        $APP_ID"
echo "Key Type:      $KEY_TYPE"
echo "X25519:        $X25519"
echo "======================================"
echo ""

echo "Querying app key..."
echo ""

# Call gRPC service
response=$(grpcurl "${GRPCURL_TRANSPORT[@]}" \
    -import-path "$SCRIPT_DIR/../proto" \
    -proto tapp_service.proto \
    -d "{
        \"app_id\": \"$APP_ID\",
        \"key_type\": \"$KEY_TYPE\",
        \"x25519\": \"$X25519\"
    }" \
    tapp_service.TappService/GetAppKey 2>&1)

# Check if request was successful
if echo "$response" | grep -q "Code:"; then
    echo "❌ Request failed:"
    echo "--------------------------------------"
    echo "$response"
    echo "--------------------------------------"
    exit 1
fi

echo "Response:"
echo "--------------------------------------"
echo "$response"
echo "--------------------------------------"