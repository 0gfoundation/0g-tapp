#!/bin/bash

# Usage:
#   ./get_app_logs.sh [HOST] [PORT] [APP_ID] [LINES] [SERVICE_NAME] [API_KEY]
#
# Examples:
#   # Get last 100 lines from all services
#   ./get_app_logs.sh localhost 50051 test-broker-app
#
#   # Get last 50 lines from all services
#   ./get_app_logs.sh localhost 50051 test-broker-app 50
#
#   # Get logs from specific service (e.g., "broker")
#   ./get_app_logs.sh localhost 50051 test-broker-app 100 broker
#
#   # With API key
#   ./get_app_logs.sh localhost 50051 test-broker-app 100 broker my-api-key

# Default configuration
DEFAULT_HOST="localhost"
DEFAULT_PORT="50051"
DEFAULT_APP_ID="test-broker-app"
DEFAULT_LINES="100"
DEFAULT_SERVICE_NAME=""  # Empty means all services

# Parse command line arguments
TARGET_HOST=${1:-$DEFAULT_HOST}
TARGET_PORT=${2:-$DEFAULT_PORT}
APP_ID=${3:-$DEFAULT_APP_ID}
LINES=${4:-$DEFAULT_LINES}
SERVICE_NAME=${5:-$DEFAULT_SERVICE_NAME}
API_KEY=${6:-$TAPP_API_KEY}  # From argument or environment variable
TARGET_ADDRESS="$TARGET_HOST:$TARGET_PORT"

echo "======================================"
echo "GetAppLogs Request"
echo "======================================"
echo "Target:        $TARGET_ADDRESS"
echo "App ID:        $APP_ID"
echo "Lines:         $LINES"
if [ -n "$SERVICE_NAME" ]; then
    echo "Service:       $SERVICE_NAME"
else
    echo "Service:       (all services)"
fi
if [ -n "$API_KEY" ]; then
    echo "API Key:       ${API_KEY:0:8}... (configured)"
fi
echo "======================================"
echo ""

# Build request JSON
request_json=$(jq -n \
    --arg app_id "$APP_ID" \
    --argjson lines "$LINES" \
    --arg service_name "$SERVICE_NAME" \
    '{
        app_id: $app_id,
        lines: $lines,
        service_name: $service_name
    }')

echo "Request:"
echo "--------------------------------------"
echo "$request_json"
echo "--------------------------------------"
echo ""

# Build grpcurl command
GRPCURL_CMD="grpcurl -plaintext"

# Add API key header if provided
if [ -n "$API_KEY" ]; then
    GRPCURL_CMD="$GRPCURL_CMD -H \"x-api-key: $API_KEY\""
fi

GRPCURL_CMD="$GRPCURL_CMD -import-path ./proto -proto tapp_service.proto -d @ \"$TARGET_ADDRESS\" tapp_service.TappService/GetAppLogs"

echo "Sending GetAppLogs request..."
echo ""

response=$(printf "%s" "$request_json" | tr -d '\n' | eval $GRPCURL_CMD 2>&1)

echo "Response:"
echo "--------------------------------------"
echo "$response"
echo "--------------------------------------"
echo ""

# Parse and display logs
total_lines=$(echo "$response" | jq -r '.totalLines' 2>/dev/null || echo "0")
echo "======================================"
echo "App Logs ($total_lines lines)"
echo "======================================"
echo ""
echo "$response" | jq -r '.content' 2>/dev/null || echo "Failed to parse logs"
echo ""

