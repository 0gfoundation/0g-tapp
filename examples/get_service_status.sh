#!/bin/bash

# Get TAPP service status from systemd/journalctl
# Usage:
#   ./get_service_status.sh [OPTIONS]
#
# Examples:
#   ./get_service_status.sh --host 39.97.63.199 --port 50051
#   ./get_service_status.sh --host localhost --log-lines 100
#   ./get_service_status.sh --log-lines 20

set -e

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Default configuration
DEFAULT_HOST="localhost"
DEFAULT_PORT="50051"
DEFAULT_LOG_LINES="50"

# Parse command line arguments
TARGET_HOST="$DEFAULT_HOST"
TARGET_PORT="$DEFAULT_PORT"
LOG_LINES=""

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
        --log-lines)
            LOG_LINES="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Get TAPP service status and recent logs from systemd/journalctl"
            echo ""
            echo "Options:"
            echo "  --host HOST             gRPC server host (default: $DEFAULT_HOST)"
            echo "  --port PORT             gRPC server port (default: $DEFAULT_PORT)"
            echo "  --log-lines LINES       Number of recent log lines (default: $DEFAULT_LOG_LINES)"
            echo "  --help, -h              Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0 --host 39.97.63.199 --port 50051"
            echo "  $0 --host localhost --log-lines 100"
            echo "  $0 --log-lines 20"
            echo ""
            echo "This is a public endpoint (no authentication required)"
            echo ""
            echo "The service uses 'systemctl show' and 'journalctl -u <unit> -n <lines>'"
            echo "to retrieve service status and logs."
            exit 0
            ;;
        *)
            # Support legacy positional arguments
            if [ "$TARGET_HOST" = "$DEFAULT_HOST" ]; then
                TARGET_HOST="$1"
            elif [ "$TARGET_PORT" = "$DEFAULT_PORT" ]; then
                TARGET_PORT="$1"
            elif [ -z "$LOG_LINES" ]; then
                LOG_LINES="$1"
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

# Set default log lines if not specified
if [ -z "$LOG_LINES" ]; then
    LOG_LINES="$DEFAULT_LOG_LINES"
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
echo "GetServiceStatus Request"
echo "======================================"
echo "Target:             $TARGET_ADDRESS"
echo "Log Lines:          $LOG_LINES"
echo "======================================"
echo ""

echo "Querying service status..."
echo ""

# Call gRPC service
set +e  # Don't exit on error
response=$(grpcurl -plaintext \
    -import-path "$SCRIPT_DIR/../proto" \
    -proto tapp_service.proto \
    -d "{
        \"logLines\": $LOG_LINES
    }" \
    "$TARGET_ADDRESS" \
    tapp_service.TappService/GetServiceStatus 2>&1)
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

echo "✅ Service Status Retrieved Successfully"
echo "======================================"
echo ""

echo "$response"

echo ""
echo "======================================"
