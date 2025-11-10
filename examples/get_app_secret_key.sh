!/bin/bash

# Usage:
#   ./get_app_secret_key.sh [OPTIONS]
#
# Options:
#   -h, --host HOST              Target host (default: 127.0.0.1)
#   -p, --port PORT              Target port (default: 50051)
#   -a, --app-id APP_ID          Application ID (required)
#   -d, --deployer-key KEY       Deployer private key (required)
#                                Supports: Hex (64 chars), Base64, or PEM format
#
# Positional arguments (deprecated, use options instead):
#   ./get_app_secret_key.sh [HOST] [PORT] [APP_ID] [DEPLOYER_KEY]
#
# Examples:
#   # Using hex format deployer key
#   ./get_app_secret_key.sh --app-id my-app --deployer-key 0x1234...abcd
#
#   # Using PEM format deployer key from file
#   ./get_app_secret_key.sh -a my-app -d "$(cat deployer_key.pem)"
#
#   # Remote server
#   ./get_app_secret_key.sh -a test-nginx-app-xxx -h 127.0.0.1 -p 50051 -d 0x00...00

# Default configuration
DEFAULT_HOST="127.0.0.1"
DEFAULT_PORT="50051"

# Initialize variables
TARGET_HOST=""
TARGET_PORT=""
APP_ID=""
DEPLOYER_KEY=""

# Parse command line arguments
if [[ "$1" =~ ^- ]]; then
    # Option-based parsing
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--host)
                TARGET_HOST="$2"
                shift 2
                ;;
            -p|--port)
                TARGET_PORT="$2"
                shift 2
                ;;
            -a|--app-id)
                APP_ID="$2"
                shift 2
                ;;
            -d|--deployer-key)
                DEPLOYER_KEY="$2"
                shift 2
                ;;
            --help)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  -h, --host HOST              Target host (default: $DEFAULT_HOST)"
                echo "  -p, --port PORT              Target port (default: $DEFAULT_PORT)"
                echo "  -a, --app-id APP_ID          Application ID (required)"
                echo "  -d, --deployer-key KEY       Deployer private key (required)"
                echo "                               Supports: Hex (64 chars), Base64, or PEM format"
                echo ""
                echo "Examples:"
                echo "  # Using hex format deployer key"
                echo "  $0 --app-id my-app --deployer-key 0x1234...abcd"
                echo ""
                echo "  # Using PEM format deployer key from file"
                echo "  $0 -a my-app -d \"\$(cat deployer_key.pem)\""
                echo ""
                echo "Security Note:"
                echo "  This command can ONLY be run from localhost or same-host containers."
                echo "  Private keys will NEVER be sent over the network."
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done
else
    # Positional parsing (backward compatibility)
    TARGET_HOST=${1:-}
    TARGET_PORT=${2:-}
    APP_ID=${3:-}
    DEPLOYER_KEY=${4:-}
fi

# Apply defaults
TARGET_HOST=${TARGET_HOST:-$DEFAULT_HOST}
TARGET_PORT=${TARGET_PORT:-$DEFAULT_PORT}

# Validate required parameters
if [ -z "$APP_ID" ]; then
    echo "Error: APP_ID is required"
    echo ""
    echo "Usage: $0 --app-id <APP_ID> --deployer-key <KEY> [OPTIONS]"
    echo "   or: $0 <HOST> <PORT> <APP_ID> <DEPLOYER_KEY>"
    echo ""
    echo "Use --help for more information"
    exit 1
fi

if [ -z "$DEPLOYER_KEY" ]; then
    echo "Error: DEPLOYER_KEY is required"
    echo ""
    echo "Usage: $0 --app-id <APP_ID> --deployer-key <KEY> [OPTIONS]"
    echo ""
    echo "The deployer private key can be provided in the following formats:"
    echo "  - Hex: 64 hex characters (with or without 0x prefix)"
    echo "  - Base64: 44 characters (32 bytes encoded)"
    echo "  - PEM: -----BEGIN PRIVATE KEY----- or -----BEGIN EC PRIVATE KEY-----"
    echo ""
    echo "Use --help for more information"
    exit 1
fi

TARGET_ADDRESS="http://$TARGET_HOST:$TARGET_PORT"

# Display configuration
echo "======================================"
echo "GetAppSecretKey Request Configuration"
echo "======================================"
echo "Target:        $TARGET_ADDRESS"
echo "App ID:        $APP_ID"
echo "Key Format:    $(echo "$DEPLOYER_KEY" | head -c 50)..."
echo "======================================"
echo ""

# Check if tapp-cli exists
if ! command -v tapp-cli &> /dev/null; then
    echo "Error: tapp-cli not found in PATH"
    echo ""
    echo "Please build and install tapp-cli first:"
    echo "  cargo build --release --bin tapp-cli"
    echo "  sudo cp target/release/tapp-cli /usr/local/bin/"
    echo ""
    echo "Or run from the project directory:"
    echo "  cargo run --bin tapp-cli -- get-app-secret-key --server \"$TARGET_ADDRESS\" --app-id \"$APP_ID\" --deployer-private-key \"$DEPLOYER_KEY\""
    exit 1
fi

# Call tapp-cli to get secret key
# The CLI will handle:
# - Parsing the deployer key (hex/base64/PEM)
# - Generating nonce and timestamp
# - Signing the request
# - Making the gRPC call
tapp-cli --server "$TARGET_ADDRESS" get-app-secret-key \
    --app-id "$APP_ID" \
    --deployer-private-key "$DEPLOYER_KEY"