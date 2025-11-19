#!/bin/bash

# Usage:
#   ./get_app_info.sh [HOST] [PORT] [APP_ID]
#
# Examples:
#   ./get_app_info.sh your-cvm-instance-host 50051 test-nginx-app

# Default configuration
DEFAULT_HOST="your-cvm-instance-host"
DEFAULT_PORT="50051"
DEFAULT_APP_ID="test-nginx-app"

# Parse command line arguments
APP_ID=${1:-$DEFAULT_APP_ID}
TARGET_HOST=${2:-$DEFAULT_HOST}
TARGET_PORT=${3:-$DEFAULT_PORT}
TARGET_ADDRESS="$TARGET_HOST:$TARGET_PORT"

request_json=$(jq -n \
  --arg app_id "$APP_ID" \
  '{
    app_id: $app_id
  }')

echo "Querying app info..."
echo ""

echo "Request:"
echo "--------------------------------------"
echo "$request_json"
echo "--------------------------------------"

response=$(printf "%s" "$request_json" | tr -d '\n' | grpcurl -plaintext \
  -import-path ./proto \
  -proto tapp_service.proto \
  -d @ \
  "$TARGET_ADDRESS" \
  tapp_service.TappService/GetAppInfo 2>&1)

echo "Response:"
echo "--------------------------------------"
echo "$response"
echo "--------------------------------------"