#!/bin/bash

# Usage:
#   ./stop_app.sh [APP_ID] [HOST] [PORT] [API_KEY]
#
# Examples:
#   ./stop_app.sh
#   ./stop_app.sh test-nginx-app
#   ./stop_app.sh test-nginx-app 39.97.63.199 50051
#   ./stop_app.sh test-nginx-app 39.97.63.199 50051 my-secret-api-key-12345
#
# Or use environment variable:
#   export TAPP_API_KEY="my-secret-api-key-12345"
#   ./stop_app.sh test-nginx-app

# Default configuration
DEFAULT_APP_ID="test-nginx-app"
DEFAULT_HOST="39.97.63.199"
DEFAULT_PORT="50051"

# Parse command line arguments
APP_ID=${1:-$DEFAULT_APP_ID}
TARGET_HOST=${2:-$DEFAULT_HOST}
TARGET_PORT=${3:-$DEFAULT_PORT}
API_KEY=${4:-$TAPP_API_KEY}  # From argument or environment variable
TARGET_ADDRESS="$TARGET_HOST:$TARGET_PORT"

echo "======================================"
echo "StopApp Request Configuration"
echo "======================================"
echo "Target:        $TARGET_ADDRESS"
echo "App ID:        $APP_ID"
if [ -n "$API_KEY" ]; then
    echo "API Key:       ${API_KEY:0:8}... (configured)"
else
    echo "API Key:       (not set)"
fi
echo "======================================"
echo ""

# Create request JSON
request_json=$(jq -n \
  --arg app_id "$APP_ID" \
  '{
    app_id: $app_id
  }')

echo "Sending StopApp request..."
echo ""

echo "Request:"
echo "--------------------------------------"
echo "$request_json"
echo "--------------------------------------"
echo ""

# Build grpcurl command with optional API key
GRPCURL_CMD="grpcurl -plaintext"

# Add API key header if provided
if [ -n "$API_KEY" ]; then
    GRPCURL_CMD="$GRPCURL_CMD -H \"x-api-key: $API_KEY\""
fi

GRPCURL_CMD="$GRPCURL_CMD -import-path ./proto -proto tapp_service.proto -d @ \"$TARGET_ADDRESS\" tapp_service.TappService/StopApp"

response=$(printf "%s" "$request_json" | tr -d '\n' | eval $GRPCURL_CMD 2>&1)

echo "Response:"
echo "--------------------------------------"
echo "$response"
echo "--------------------------------------"
echo ""

# Check if successful
success=$(echo "$response" | jq -r '.success // empty' 2>/dev/null)

echo "======================================"
if [ "$success" = "true" ]; then
    echo "✓ Application stopped successfully"
else
    echo "⚠️  Stop operation may have failed"
    echo "Please check the response above"
fi
echo "======================================"
