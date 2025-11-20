#!/bin/bash

# Usage:
#   ./get_service_logs.sh [HOST] [PORT] [FILE_NAME] [LINES]
#
# Examples:
#   ./get_service_logs.sh                                    # List all log files (default host)
#   ./get_service_logs.sh 39.97.249.15                      # List all log files
#   ./get_service_logs.sh 39.97.249.15 50051                # List all log files
#   ./get_service_logs.sh 39.97.249.15 50051 app.log        # Get last 100 lines of app.log
#   ./get_service_logs.sh 39.97.249.15 50051 app.log 200    # Get last 200 lines

# Default configuration
DEFAULT_HOST="your-cvm-instance-host"
DEFAULT_PORT="50051"
DEFAULT_LINES=100

# Parse command line arguments
TARGET_HOST=${1:-$DEFAULT_HOST}
TARGET_PORT=${2:-$DEFAULT_PORT}
FILE_NAME=${3:-""}
LINES=${4:-$DEFAULT_LINES}
TARGET_ADDRESS="$TARGET_HOST:$TARGET_PORT"

echo "======================================"
echo "GetServiceLogs Request Configuration"
echo "======================================"
echo "Target:        $TARGET_ADDRESS"
if [ -z "$FILE_NAME" ]; then
    echo "Mode:          List all log files"
else
    echo "File:          $FILE_NAME"
    echo "Lines:         $LINES"
fi
echo "======================================"
echo ""

# Create request JSON
request_json=$(jq -n \
  --arg file_name "$FILE_NAME" \
  --argjson lines "$LINES" \
  '{
    file_name: $file_name,
    lines: $lines
  }')

echo "Sending GetServiceLogs request..."
echo ""

echo "Request:"
echo "--------------------------------------"
echo "$request_json"
echo "--------------------------------------"
echo ""

response=$(printf "%s" "$request_json" | tr -d '\n' | grpcurl -plaintext \
  -import-path ./proto \
  -proto tapp_service.proto \
  -d @ \
  "$TARGET_ADDRESS" \
  tapp_service.TappService/GetServiceLogs 2>&1)

echo "Response:"
echo "--------------------------------------"
echo "$response"
echo "--------------------------------------"
echo ""

# Check if successful
success=$(echo "$response" | jq -r '.success // empty' 2>/dev/null)

if [ "$success" = "true" ]; then
    if [ -z "$FILE_NAME" ]; then
        echo "======================================"
        echo "Available log files:"
        echo "======================================"
        echo "$response" | jq -r '.availableFiles[] | "\(.fileName) - \(.sizeBytes) bytes - Modified: \(.modifiedTime)"' 2>/dev/null
    else
        echo "======================================"
        echo "Log content retrieved successfully"
        echo "======================================"
    fi
else
    echo "======================================"
    echo "⚠️  Request may have failed"
    echo "Please check the response above"
    echo "======================================"
fi
