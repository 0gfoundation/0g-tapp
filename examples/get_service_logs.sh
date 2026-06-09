#!/bin/bash

# Get service logs from TAPP service with Ethereum signature authentication
# Usage:
#   ./get_service_logs.sh [OPTIONS]
#
# Examples:
#   ./get_service_logs.sh --host 39.97.63.199 --use-owner                    # List all log files
#   ./get_service_logs.sh --host 39.97.63.199 --file app.log --use-owner     # Get last 100 lines
#   ./get_service_logs.sh --host 39.97.63.199 --file app.log --lines 200 --use-whitelist

set -e

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Default configuration
DEFAULT_HOST="localhost"
DEFAULT_PORT="50051"
DEFAULT_LINES="100"
DEFAULT_FILE_NAME=""

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
FILE_NAME=""
LINES=""
PRIVATE_KEY=""
USE_OWNER=false
USE_WHITELIST=false
DOWNLOAD_FULL=false

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
        --file)
            FILE_NAME="$2"
            shift 2
            ;;
        --lines)
            LINES="$2"
            shift 2
            ;;
        --download-full)
            DOWNLOAD_FULL=true
            shift
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
            echo "  --host HOST             gRPC server host (default: $DEFAULT_HOST)"
            echo "  --port PORT             gRPC server port (default: $DEFAULT_PORT)"
            echo "  --file FILE_NAME        Log file name (empty = list all files)"
            echo "  --lines LINES           Number of log lines to retrieve (default: $DEFAULT_LINES, ignored if --download-full)"
            echo "  --download-full         Download complete log file (ignores --lines)"
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
            echo "  $0 --host 39.97.63.199 --use-owner"
            echo "  $0 --host 39.97.63.199 --file app.log --use-owner"
            echo "  $0 --host 39.97.63.199 --file app.log --lines 200 --use-whitelist"
            echo "  $0 --host 39.97.63.199 --file app.log --download-full --use-owner"
            echo ""
            echo "Pre-configured users:"
            echo "  Owner: $OWNER_ADDRESS"
            echo "  Whitelist: $WHITELIST_ADDRESS"
            exit 0
            ;;
        *)
            # Support legacy positional arguments for backward compatibility
            # Original order: HOST PORT FILE_NAME LINES
            if [ "$TARGET_HOST" = "$DEFAULT_HOST" ]; then
                TARGET_HOST="$1"
            elif [ "$TARGET_PORT" = "$DEFAULT_PORT" ]; then
                TARGET_PORT="$1"
            elif [ -z "$FILE_NAME" ]; then
                FILE_NAME="$1"
            elif [ -z "$LINES" ]; then
                LINES="$1"
            else
                echo "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
            fi
            shift
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

# Apply defaults
if [ -z "$LINES" ]; then
    LINES="$DEFAULT_LINES"
fi

# Validate lines (must be a positive integer)
if ! [[ "$LINES" =~ ^[0-9]+$ ]] || [ "$LINES" -le 0 ]; then
    echo "Error: Lines must be a positive integer"
    echo "Got: $LINES"
    exit 1
fi

echo "Checking dependencies..."
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
    py_major=$(echo "$py_version" | cut -d. -f1)
    py_minor=$(echo "$py_version" | cut -d. -f2)
    if [ "$py_major" -lt 3 ] || ([ "$py_major" -eq 3 ] && [ "$py_minor" -lt 6 ]); then
        echo "✗ python3: Version $py_version (requires >= 3.6)"
        deps_ok=false
        missing_deps+=("python3 (>= 3.6)")
    else
        echo "✓ python3: $py_version"
    fi
fi

# Check eth-account Python package
if command -v python3 &> /dev/null; then
    if python3 -c "import eth_account" 2>/dev/null; then
        eth_version=$(python3 -c "import eth_account; print(eth_account.__version__)" 2>/dev/null || echo "unknown")
        echo "✓ eth-account: $eth_version"
    else
        echo "✗ eth-account: Not installed"
        deps_ok=false
        missing_deps+=("eth-account")
    fi
fi

# Check jq
if ! command -v jq &> /dev/null; then
    echo "✗ jq: Not found"
    deps_ok=false
    missing_deps+=("jq")
else
    jq_version=$(jq --version 2>&1 | sed 's/jq-//')
    echo "✓ jq: $jq_version"
fi

# Check grpcurl
if ! command -v grpcurl &> /dev/null; then
    echo "✗ grpcurl: Not found"
    deps_ok=false
    missing_deps+=("grpcurl")
else
    grpcurl_version=$(grpcurl --version 2>&1 | head -1 | awk '{print $2}')
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

echo "========================================"

# Exit if dependencies are missing
if [ "$deps_ok" = false ]; then
    echo ""
    echo "❌ Missing dependencies: ${missing_deps[*]}"
    echo ""
    echo "Installation guide:"
    echo ""
    for dep in "${missing_deps[@]}"; do
        case "$dep" in
            "python3"*)
                echo "• Python 3.6+:"
                echo "  CentOS/RHEL: yum install python3"
                echo "  Ubuntu/Debian: apt-get install python3"
                echo "  macOS: brew install python3"
                ;;
            "eth-account")
                echo "• eth-account:"
                echo "  pip3 install eth-account"
                ;;
            "jq")
                echo "• jq:"
                echo "  https://stedolan.github.io/jq/download/"
                ;;
            "grpcurl")
                echo "• grpcurl:"
                echo "  https://github.com/fullstorydev/grpcurl/releases"
                ;;
            "tapp_service.proto")
                echo "• proto file not found at: $proto_file"
                ;;
            "sign_message.py")
                echo "• sign_message.py:"
                echo "  The signature utility script is missing"
                echo "  Expected location: $sign_script"
                ;;
        esac
        echo ""
    done
    exit 1
fi

echo "✅ All dependencies satisfied"
echo ""

echo "======================================"
echo "GetServiceLogs Request"
echo "======================================"
echo "Target:        $TARGET_ADDRESS"
if [ -z "$FILE_NAME" ]; then
    echo "Mode:          List all log files"
else
    echo "File:          $FILE_NAME"
    echo "Lines:         $LINES"
fi
echo "======================================"
echo ""

# Generate signature
echo "Generating signature..."
SIGN_OUTPUT=$(python3 "$sign_script" "GetServiceLogs" "$PRIVATE_KEY" 2>&1)
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
echo "======================================"
echo ""

# Build request JSON
request_json=$(jq -n \
    --arg file_name "$FILE_NAME" \
    --argjson lines "$LINES" \
    --argjson download_full "$DOWNLOAD_FULL" \
    '{
        file_name: $file_name,
        lines: $lines,
        download_full: $download_full
    }')

echo "Request:"
echo "--------------------------------------"
echo "$request_json"
echo "--------------------------------------"
echo ""

echo "Sending GetServiceLogs request..."
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
    tapp_service.TappService/GetServiceLogs 2>&1)
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
echo ""

# Check if successful and parse response
success=$(echo "$response" | jq -r '.success // empty' 2>/dev/null)

if [ "$success" = "true" ]; then
    if [ -z "$FILE_NAME" ]; then
        echo "======================================"
        echo "Available log files:"
        echo "======================================"
        echo "$response" | jq -r '.availableFiles[]? | "\(.fileName) - \(.sizeBytes) bytes - Modified: \(.modifiedTime)"' 2>/dev/null
    else
        echo "======================================"
        echo "✅ Log content retrieved successfully"
        echo "======================================"
    fi
else
    echo "======================================"
    echo "⚠️  Request may have failed"
    echo "Please check the response above"
    echo "======================================"
fi