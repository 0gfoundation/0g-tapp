#!/bin/bash
# Enhanced script with Ethereum signature-based authentication
# Usage:
#   ./prune_images.sh --host HOST --port PORT [OPTIONS]
#
# Example:
#   ./prune_images.sh --host localhost --port 50051 --all --use-owner
#
# Pre-configured users:
#   Owner: Address=0xYourOwnerAddressHere
#   Whitelist: Address=0xYourWhitelistAddressHere

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
ALL=false
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
    --all)
      ALL=true
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
      echo "Prune unused Docker images"
      echo ""
      echo "Options:"
      echo "  --host HOST          gRPC server host (default: $DEFAULT_HOST)"
      echo "  --port PORT          gRPC server port (default: $DEFAULT_PORT)"
      echo "  --all                Remove all unused images, not just dangling ones (default: false)"
      echo "  --private-key KEY    Private key for signing (required unless using presets)"
      echo "  --use-owner          Use pre-configured owner credentials (requires TAPP_OWNER_PRIVATE_KEY env var)"
      echo "  --use-whitelist      Use pre-configured whitelist user credentials (requires TAPP_WHITELIST_PRIVATE_KEY env var)"
      echo "  --help, -h           Show this help message"
      echo ""
      echo "Environment variables:"
      echo "  TAPP_OWNER_PRIVATE_KEY       Private key for owner account"
      echo "  TAPP_WHITELIST_PRIVATE_KEY   Private key for whitelist account"
      echo ""
      echo "Security best practice:"
      echo "  Store private keys in environment variables instead of command line arguments"
      echo ""
      echo "Examples:"
      echo "  # Prune dangling images only"
      echo "  export TAPP_OWNER_PRIVATE_KEY=\"0x...\""
      echo "  $0 --host localhost --port 50051 --use-owner"
      echo ""
      echo "  # Prune all unused images"
      echo "  $0 --all --use-owner"
      echo ""
      echo "  # Prune images older than 24 hours"
      echo "  $0 --filter \"until=24h\" --use-owner"
      echo ""
      echo "  # Dry run to see what would be deleted"
      echo "  $0 --all --dry-run --use-owner"
      echo ""
      echo "Pre-configured users:"
      echo "  Owner: $OWNER_ADDRESS"
      echo "  Whitelist: $WHITELIST_ADDRESS"
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

# Check sign_message.py
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
        echo "  CentOS/RHEL: yum install jq"
        echo "  Ubuntu/Debian: apt-get install jq"
        echo "  macOS: brew install jq"
        ;;
      "grpcurl")
        echo "• grpcurl:"
        echo "  Download from: https://github.com/fullstorydev/grpcurl/releases"
        echo "  Or install via:"
        echo "    macOS: brew install grpcurl"
        echo "    Go: go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest"
        ;;
      "tapp_service.proto")
        echo "• tapp_service.proto:"
        echo "  Make sure you're running the script from the examples directory"
        echo "  Expected location: $proto_file"
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

echo "========================================"
echo "0G TAPP Prune Images"
echo "========================================"
echo "Target: $TARGET_ADDRESS"
echo "All: $ALL"
echo "========================================"
echo ""

# Generate signature using shared sign_message.py
echo "Generating signature..."
SIGN_OUTPUT=$(python3 "$sign_script" "PruneImages" "$PRIVATE_KEY" 2>&1)
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

echo "Generating JSON request..."

# Build request JSON
request_json=$(jq -n \
--argjson all "$ALL" \
'{
    all: $all,
}')

echo "Sending PruneImages request with signature authentication..."
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
    tapp_service.TappService/PruneImages 2>&1)
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
  exit 1
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
echo ""

# Extract information from response
images_deleted=$(echo "$response" | jq -r '.imagesDeleted // .images_deleted // 0' 2>/dev/null || echo "0")
space_reclaimed=$(echo "$response" | jq -r '.spaceReclaimed // .space_reclaimed // 0' 2>/dev/null || echo "0")

# Convert bytes to human-readable format
if [ "$space_reclaimed" != "0" ] && [ "$space_reclaimed" != "null" ]; then
  space_gb=$(echo "scale=2; $space_reclaimed / 1024 / 1024 / 1024" | bc 2>/dev/null || echo "0")
  space_mb=$(echo "scale=2; $space_reclaimed / 1024 / 1024" | bc 2>/dev/null || echo "0")
  
  if [ -n "$space_gb" ] && [ "$(echo "$space_gb >= 1" | bc 2>/dev/null || echo "0")" = "1" ]; then
    space_display="${space_gb} GB"
  else
    space_display="${space_mb} MB"
  fi
else
  space_display="0 bytes"
fi

echo "========================================"
echo "Prune Results:"
echo "========================================"
echo "✓ Images deleted: $images_deleted"
echo "✓ Space reclaimed: $space_display ($space_reclaimed bytes)"
echo ""

if [ "$DRY_RUN" = true ]; then
  echo "⚠️  This was a dry run - no images were actually deleted"
else
  echo "✅ Images pruned successfully"
fi

echo "========================================"
