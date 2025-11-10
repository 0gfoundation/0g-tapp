#!/bin/bash

# Usage:
#   ./list_app_measurements.sh [HOST] [PORT] [DEPLOYER_FILTER]
#
# Examples:
#   ./list_app_measurements.sh
#   ./list_app_measurements.sh 39.97.63.199 50051
#   ./list_app_measurements.sh 39.97.63.199 50051 0x1234...

# Default configuration
DEFAULT_HOST="39.97.63.199"
DEFAULT_PORT="50051"

# Parse command line arguments
TARGET_HOST=${1:-$DEFAULT_HOST}
TARGET_PORT=${2:-$DEFAULT_PORT}
DEPLOYER_FILTER=${3:-""}
TARGET_ADDRESS="$TARGET_HOST:$TARGET_PORT"

echo "======================================"
echo "ListAppMeasurements Request"
echo "======================================"
echo "Target:        $TARGET_ADDRESS"
if [ -n "$DEPLOYER_FILTER" ]; then
    echo "Filter:        Deployer = $DEPLOYER_FILTER"
else
    echo "Filter:        None (list all)"
fi
echo "======================================"
echo ""

request_json=$(jq -n \
  --arg deployer_filter "$DEPLOYER_FILTER" \
  '{
    deployer_filter: $deployer_filter
  }')

echo "Querying app measurements..."
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
  tapp_service.TappService/ListAppMeasurements 2>&1)

echo "$response"
echo ""

echo "Response:"
echo "--------------------------------------"
echo "$response"
echo "--------------------------------------"
