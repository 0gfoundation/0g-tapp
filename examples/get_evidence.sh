#!/bin/bash

# Get attestation evidence from TAPP service
# Usage:
#   ./get_evidence.sh [OPTIONS]
#
# Examples:
#   ./get_evidence.sh --host 39.97.63.199 --port 50051 --app-id my-app
#   ./get_evidence.sh --app-id my-app

set -e

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Default configuration
DEFAULT_HOST="localhost"
DEFAULT_PORT="50051"

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
            echo "  --app-id APP_ID         Application ID (required)"
            echo "                         The EVM address (owner) of the app will be automatically used as report_data"
            echo "  --help, -h              Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0 --host 39.97.63.199 --port 50051 --app-id my-app"
            echo "  $0 --app-id my-app"
            echo ""
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

# Validate app_id
if [ -z "$APP_ID" ]; then
    echo "Error: --app-id is required"
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

if ! command -v base64 &> /dev/null; then
    missing_deps+=("base64")
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
            "base64")
                echo "• base64: Usually included in coreutils package"
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
echo "GetEvidence Request"
echo "======================================"
echo "Target:             $TARGET_ADDRESS"
echo "App ID:             $APP_ID"
echo "Note:               The EVM address (owner) of the app will be used as report_data"
echo "======================================"
echo ""

echo "Requesting attestation evidence..."
echo ""

# Call gRPC service
response=$(grpcurl -plaintext \
  -import-path "$SCRIPT_DIR/../proto" \
  -proto tapp_service.proto \
  -d "{
    \"app_id\": \"$APP_ID\"
  }" \
  "$TARGET_ADDRESS" \
  tapp_service.TappService/GetEvidence 2>&1)

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
echo "$response" | jq . 2>/dev/null || echo "$response"
echo "--------------------------------------"
echo ""

# Check if evidence was returned
if echo "$response" | jq -e '.evidence' &>/dev/null; then
    echo "✅ Evidence retrieved successfully!"
    echo ""
    
    # Extract evidence size
    evidence=$(echo "$response" | jq -r '.evidence // empty' 2>/dev/null)
    if [ -n "$evidence" ]; then
        evidence_size=${#evidence}
        echo "Evidence size: $evidence_size bytes (base64)"
        
        # Optionally save to file
        echo "$evidence" | base64 -d > /tmp/evidence.bin 2>/dev/null && \
            echo "Binary evidence saved to: /tmp/evidence.bin"
    fi
else
    echo "⚠️  No evidence found in response"
fi