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
DEFAULT_DEPLOYER_HEX="0xbae5046287f1b3fe2540d13160778c459d0f4038f1dcda0651679f5cb8a21f0ef1550b51ab5e6ae5a8e531512b1a06a97dfbb992c5e6f3aa36b04e1dd928d269"
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
echo "Deployer:      $DEPLOYER_HEX"
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
    deployer: $deployer,
    mount_files: [
      {
        source_path: "./config.yml",
        content: $config,
        mode: "0644"
      }
    ]
  }')

echo "Request JSON:"
echo "--------------------------------------"
echo "$request_json"
echo "--------------------------------------"
echo ""

echo "Sending StartApp request..."
echo ""

# Add pipe to pass request_json to grpcurl
response=$(printf "%s" "$request_json" | tr -d '\n' | grpcurl -plaintext \
  -import-path ./proto \
  -proto tapp_service.proto \
  -d @ \
  "$TARGET_ADDRESS" \
  tapp_service.TappService/StartApp 2>&1)

echo "Response:"
echo "--------------------------------------"
echo "$response"
echo "--------------------------------------"
echo ""

# Extract task_id from response
task_id=$(echo "$response" | jq -r '.taskId // .task_id // empty' 2>/dev/null)

echo "========================================"
echo "Next Steps:"
echo "========================================"
echo "✓ App is starting asynchronously"
echo ""

if [ -n "$task_id" ]; then
    echo "📋 Task ID: $task_id"
    echo ""
    echo "To check task status, run:"
    echo "  sh examples/get_task_status.sh $task_id $TARGET_HOST $TARGET_PORT"
    echo ""
    echo "Or use this one-liner to monitor until completion:"
    echo "  while true; do sh examples/get_task_status.sh $task_id $TARGET_HOST $TARGET_PORT && break || sleep 2; done"
else
    echo "⚠️  Could not extract task_id from response."
    echo "Please copy the task_id from the response above and run:"
    echo "  sh examples/get_task_status.sh <TASK_ID> $TARGET_HOST $TARGET_PORT"
fi

echo ""
echo "Once completed, you can get evidence:"
echo "  sh examples/get_evidence.sh $TARGET_HOST $TARGET_PORT"
echo "========================================"