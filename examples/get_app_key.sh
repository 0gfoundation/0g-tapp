#!/bin/bash

# Usage:
#   ./get_app_key.sh [HOST] [PORT] [APP_ID] [KEY_TYPE]
#
# Examples:
#   ./get_app_key.sh
#   ./get_app_key.sh your-cvm-instance-host 50051
#   ./get_app_key.sh your-cvm-instance-host 50051 test-nginx-app
#   ./get_app_key.sh your-cvm-instance-host 50051 test-nginx-app ethereum

# Default configuration
DEFAULT_HOST="your-cvm-instance-host"
DEFAULT_PORT="50051"
DEFAULT_APP_ID="test-nginx-app"
DEFAULT_KEY_TYPE="ethereum"

# Parse command line arguments
TARGET_HOST=${1:-$DEFAULT_HOST}
TARGET_PORT=${2:-$DEFAULT_PORT}
APP_ID=${3:-$DEFAULT_APP_ID}
KEY_TYPE=${4:-$DEFAULT_KEY_TYPE}

TARGET_ADDRESS="$TARGET_HOST:$TARGET_PORT"

# Display configuration
echo "======================================"
echo "GetAppKey Request Configuration"
echo "======================================"
echo "Target:        $TARGET_ADDRESS"
echo "App ID:        $APP_ID"
echo "Key Type:      $KEY_TYPE"
echo "======================================"
echo ""

# Call gRPC service
grpcurl -plaintext -import-path ./proto -proto tapp_service.proto \
  -d "{
    \"app_id\": \"$APP_ID\",
    \"key_type\": \"$KEY_TYPE\"
  }" \
  "$TARGET_ADDRESS" \
  tapp_service.TappService/GetAppKey
