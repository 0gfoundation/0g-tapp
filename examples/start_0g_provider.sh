#!/bin/bash

# Usage:
#   ./start_0g_provider.sh [HOST] [PORT] [APP_ID] [DEPLOYER_HEX] [COMPOSE_FILE] [CONFIG_FILE]
#
# Examples:
#   ./start_0g_provider.sh
#   ./start_0g_provider.sh 39.97.63.199 50051 my-app
#   ./start_0g_provider.sh 39.97.63.199 50051 my-app 0x123...abc ./custom-compose.yml ./custom-config.yml

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Default configuration
DEFAULT_HOST="39.97.63.199"
DEFAULT_PORT="50051"
DEFAULT_APP_ID="test-broker-app"
DEFAULT_DEPLOYER_HEX="0x0000000000000000000000000000000000000000000000000000000000000000"
DEFAULT_COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"
DEFAULT_CONFIG_FILE="$SCRIPT_DIR/config.yml"

# Parse arguments
TARGET_HOST=${1:-$DEFAULT_HOST}
TARGET_PORT=${2:-$DEFAULT_PORT}
APP_ID=${3:-$DEFAULT_APP_ID}
DEPLOYER_HEX=${4:-$DEFAULT_DEPLOYER_HEX}
COMPOSE_FILE=${5:-$DEFAULT_COMPOSE_FILE}
CONFIG_FILE=${6:-$DEFAULT_CONFIG_FILE}

TARGET_ADDRESS="$TARGET_HOST:$TARGET_PORT"

# Remove 0x prefix if present
DEPLOYER_HEX=${DEPLOYER_HEX#0x}
DEPLOYER_HEX=${DEPLOYER_HEX#0X}

# Check if config files exist
if [ ! -f "$COMPOSE_FILE" ]; then
    echo "Error: Docker Compose file not found: $COMPOSE_FILE"
    echo ""
    echo "Please create the file or specify a custom path:"
    echo "  $0 $TARGET_HOST $TARGET_PORT $APP_ID $DEPLOYER_HEX <COMPOSE_FILE> <CONFIG_FILE>"
    exit 1
fi

if [ ! -f "$CONFIG_FILE" ]; then
    echo "Error: Config file not found: $CONFIG_FILE"
    echo ""
    echo "Please create the file or specify a custom path:"
    echo "  $0 $TARGET_HOST $TARGET_PORT $APP_ID $DEPLOYER_HEX <COMPOSE_FILE> <CONFIG_FILE>"
    exit 1
fi

echo "========================================"
echo "0G Serving Provider Deployment"
echo "========================================"
echo "Target:        $TARGET_ADDRESS"
echo "App ID:        $APP_ID"
echo "Compose File:  $COMPOSE_FILE"
echo "Config File:   $CONFIG_FILE"
echo "========================================"
echo ""

# Convert deployer hex to base64
if [ -n "$DEPLOYER_HEX" ]; then
    DEPLOYER_BASE64=$(echo -n "$DEPLOYER_HEX" | xxd -r -p | base64)
else
    DEPLOYER_BASE64=""
fi

echo "Reading configuration files..."
# Read compose file content
COMPOSE_CONTENT=$(cat "$COMPOSE_FILE")

# Read and base64 encode config file
CONFIG_BASE64=$(base64 < "$CONFIG_FILE" | tr -d '\n')

echo "Generating JSON request..."
# Use jq to properly encode the compose content and output compact JSON
request_json=$(jq -n \
  --arg compose "$COMPOSE_CONTENT" \
  --arg app_id "$APP_ID" \
  --arg config "$CONFIG_BASE64" \
  --arg deployer "$DEPLOYER_BASE64" \
  '{
    compose_content: $compose,
    app_id: $app_id,
    mount_files: [
      {
        source_path: "./config.yml",
        content: $config,
        mode: "0644"
      }
    ],
    deployer: $deployer
  }')

echo "Request JSON:"
echo "--------------------------------------"
echo "$request_json"
echo "--------------------------------------"

echo "Calling gRPC service..."
response=$(grpcurl -plaintext \
  -import-path ./proto \
  -proto tapp_service.proto \
  -d @ \
  "$TARGET_ADDRESS" \
  tapp_service.TappService/StartApp)

echo "Response:"
echo "--------------------------------------"
echo "$response"
echo "--------------------------------------"
