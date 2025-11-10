#!/bin/bash

# Usage:
#   ./get_task_status.sh [TASK_ID] [HOST] [PORT]
#
# Examples:
#   ./get_task_status.sh abc123-def456-789
#   ./get_task_status.sh abc123-def456-789 39.97.63.199 50051

# Default configuration
DEFAULT_HOST="39.97.63.199"
DEFAULT_PORT="50051"

# Parse command line arguments
TASK_ID=${1}
TARGET_HOST=${2:-$DEFAULT_HOST}
TARGET_PORT=${3:-$DEFAULT_PORT}
TARGET_ADDRESS="$TARGET_HOST:$TARGET_PORT"

# Check if task ID is provided
if [ -z "$TASK_ID" ]; then
    echo "Error: Task ID is required"
    echo ""
    echo "Usage:"
    echo "  $0 TASK_ID [HOST] [PORT]"
    echo ""
    echo "Examples:"
    echo "  $0 abc123-def456-789"
    echo "  $0 abc123-def456-789 39.97.61.175 50051"
    exit 1
fi

echo "======================================"
echo "GetTaskStatus Request Configuration"
echo "======================================"
echo "Target:        $TARGET_ADDRESS"
echo "Task ID:       $TASK_ID"
echo "======================================"
echo ""

request_json=$(jq -n \
  --arg task_id "$TASK_ID" \
  '{
    task_id: $task_id
  }')

echo "Querying task status..."
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
  tapp_service.TappService/GetTaskStatus 2>&1)

echo "Response:"
echo "--------------------------------------"
echo "$response"
echo "--------------------------------------"
echo ""