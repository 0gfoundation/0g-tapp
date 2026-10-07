#!/bin/bash

# Get TAPP service configuration information
# Usage:
#   ./get_tapp_info.sh [OPTIONS]
#
# Examples:
#   ./get_tapp_info.sh --host 39.97.63.199 --port 50051
#   ./get_tapp_info.sh --host localhost

set -e

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Default configuration
DEFAULT_HOST="localhost"
DEFAULT_PORT="50051"

# Parse command line arguments
TARGET_HOST="$DEFAULT_HOST"
TARGET_PORT="$DEFAULT_PORT"

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
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Get TAPP service configuration information (logging, server, boot, KBS config)"
            echo ""
            echo "Options:"
            echo "  --host HOST             gRPC server host (default: $DEFAULT_HOST)"
            echo "  --port PORT             gRPC server port (default: $DEFAULT_PORT)"
            echo "  --help, -h              Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0 --host 39.97.63.199 --port 50051"
            echo "  $0 --host localhost"
            echo ""
            echo "This is a public endpoint (no authentication required)"
            exit 0
            ;;
        *)
            # Support legacy positional arguments for backward compatibility
            if [ "$TARGET_HOST" = "$DEFAULT_HOST" ]; then
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
echo "GetTappInfo Request"
echo "======================================"
echo "Target:             $TARGET_ADDRESS"
echo "======================================"
echo ""

echo "Querying TAPP configuration..."
echo ""

# Call gRPC service
set +e  # Don't exit on error
response=$(grpcurl -plaintext \
    -import-path "$SCRIPT_DIR/../proto" \
    -proto tapp_service.proto \
    -d '{}' \
    "$TARGET_ADDRESS" \
    tapp_service.TappService/GetTappInfo 2>&1)
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

echo "✅ TAPP Configuration Retrieved Successfully"
echo "======================================"
echo ""

# Parse and display configuration using jq
if command -v jq &> /dev/null; then
    echo "$response" | jq -r '
    if .success then
        "Version: " + (.version // "N/A") + "\n" +
        "\n📝 Logging Configuration:" +
        "\n  Level:           " + (.config.logging.level // "N/A") +
        "\n  Format:          " + (.config.logging.format // "N/A") +
        "\n  File Path:       " + (.config.logging.filePath // "stdout") +
        "\n\n🌐 Server Configuration:" +
        "\n  Bind Address:    " + (.config.server.bindAddress // "N/A") +
        "\n  Max Connections: " + ((.config.server.maxConnections | tostring) // "N/A") +
        "\n  Timeout:         " + ((.config.server.requestTimeoutSeconds | tostring) // "N/A") + "s" +
        "\n  TLS Enabled:     " + ((.config.server.tlsEnabled | tostring) // "false") +
        "\n  TLS Configured:  " + ((.config.server.tlsCertConfigured | tostring) // "false") +
        "\n  Permission:      " + ((.config.server.permissionEnabled | tostring) // "false") +
        (if .config.server.permissionEnabled then "\n  Owner Address:   " + (.config.server.ownerAddress // "N/A") else "" end) +
        "\n\n🐳 Boot Configuration:" +
        "\n  AA Config:       " + (.config.boot.aaConfigPath // "N/A") +
        (if .config.kbsEnabled then
            "\n\n🔑 KBS Configuration:" +
            "\n  Endpoint:        " + (.config.kbs.endpoint // "N/A") +
            "\n  Timeout:         " + ((.config.kbs.timeoutSeconds | tostring) // "N/A") + "s" +
            "\n  Cert Configured: " + ((.config.kbs.certConfigured | tostring) // "false") +
            "\n  Max Retries:     " + ((.config.kbs.retry.maxRetries | tostring) // "N/A") +
            "\n  Initial Delay:   " + ((.config.kbs.retry.initialDelayMs | tostring) // "N/A") + "ms" +
            "\n  Max Delay:       " + ((.config.kbs.retry.maxDelayMs | tostring) // "N/A") + "ms" +
            "\n  Supported Keys:  " + ((.config.kbs.supportedKeyTypes | join(", ")) // "N/A")
        else
            "\n\n🔑 KBS Configuration: Disabled"
        end)
    else
        "❌ Error: " + (.message // "Unknown error")
    end
    '
else
    echo "Raw JSON response:"
    echo "$response"
fi

echo ""
echo "======================================"
