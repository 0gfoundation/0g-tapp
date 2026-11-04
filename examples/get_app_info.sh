#!/bin/bash

# Get application information from TAPP service
# Usage:
#   ./get_app_info.sh [OPTIONS]
#
# Examples:
#   ./get_app_info.sh --host 39.97.63.199 --port 50051 --app-id test-nginx-app
#   ./get_app_info.sh --host 39.97.63.199 --app-id my-app
#   APP_ID=my-app ./get_app_info.sh --host 39.97.63.199

set -e

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Default configuration
DEFAULT_HOST="localhost"
DEFAULT_PORT="50051"
DEFAULT_APP_ID="test-nginx-app"

# Parse command line arguments
TARGET_HOST="$DEFAULT_HOST"
TARGET_PORT="$DEFAULT_PORT"
APP_ID=""

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
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --host HOST             gRPC server host (default: $DEFAULT_HOST)"
            echo "  --port PORT             gRPC server port (default: $DEFAULT_PORT)"
            echo "  --app-id APP_ID         Application ID to query (default: $DEFAULT_APP_ID)"
            echo "  --help, -h              Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0 --host 39.97.63.199 --port 50051 --app-id test-nginx-app"
            echo "  $0 --host 39.97.63.199 --app-id my-app"
            echo ""
            echo "Environment variable:"
            echo "  APP_ID=my-app $0 --host 39.97.63.199"
            echo ""
            echo "Legacy positional format also supported:"
            echo "  $0 test-nginx-app 39.97.63.199 50051"
            exit 0
            ;;
        *)
            # Support legacy positional arguments for backward compatibility
            # Original order was: APP_ID HOST PORT
            if [ -z "$APP_ID" ]; then
                APP_ID="$1"
            elif [ "$TARGET_HOST" = "$DEFAULT_HOST" ]; then
                TARGET_HOST="$1"
            elif [ "$TARGET_PORT" = "$DEFAULT_PORT" ]; then
                TARGET_PORT="$1"
            else
                echo "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
            fi
            shift
            ;;
    esac
done

TARGET_ADDRESS="$TARGET_HOST:$TARGET_PORT"

# App ID priority: command line arg > environment variable > default
if [ -z "$APP_ID" ] && [ -n "$APP_ID_ENV" ]; then
    APP_ID="$APP_ID_ENV"
elif [ -z "$APP_ID" ]; then
    APP_ID="$DEFAULT_APP_ID"
fi

# Validate app ID (not empty)
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

# Display configuration
echo "======================================"
echo "GetAppInfo Request"
echo "======================================"
echo "Target:             $TARGET_ADDRESS"
echo "App ID:             $APP_ID"
echo "======================================"
echo ""

echo "Querying app info..."
echo ""

# Call gRPC service and capture both stdout and stderr
set +e  # Don't exit on error
response=$(grpcurl -plaintext \
    -import-path "$SCRIPT_DIR/../proto" \
    -proto tapp_service.proto \
    -d "{
        \"app_id\": \"$APP_ID\"
    }" \
    "$TARGET_ADDRESS" \
    tapp_service.TappService/GetAppInfo 2>&1)
exit_code=$?
set -e

echo "Debug: grpcurl exit code = $exit_code"
echo "Debug: response length = ${#response} bytes"
echo ""

# Check exit code
if [ $exit_code -ne 0 ]; then
    echo "❌ grpcurl failed with exit code: $exit_code"
    echo "--------------------------------------"
    echo "$response"
    echo "--------------------------------------"
    exit 1
fi

# Check if response is empty
if [ -z "$response" ] || [ ${#response} -lt 3 ]; then
    echo "⚠️  Empty or very short response received from server"
    echo "Raw response: '$response'"
    echo ""
    echo "This could mean:"
    echo "  • The application '$APP_ID' does not exist"
    echo "  • The server returned an empty response"
    echo "  • Network/connection issue"
    exit 0
fi

# Check if request failed with gRPC error
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