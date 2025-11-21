#!/bin/bash

# Usage:
#   ./start_test_nginx.sh [HOST] [PORT] [APP_ID] [DEPLOYER_HEX] [API_KEY]
#
# Examples:
#   ./start_test_nginx.sh
#   ./start_test_nginx.sh your-cvm-instance-host 50051
#   ./start_test_nginx.sh your-cvm-instance-host 50051 test-nginx-app
#   ./start_test_nginx.sh your-cvm-instance-host 50051 test-nginx-app 0xbae5046287f1b3fe2540d13160778c459d0f4038f1dcda0651679f5cb8a21f0ef1550b51ab5e6ae5a8e531512b1a06a97dfbb992c5e6f3aa36b04e1dd928d269
#   ./start_test_nginx.sh your-cvm-instance-host 50051 test-nginx-app 0xbae... my-secret-api-key-12345
#
# Or use environment variable:
#   export TAPP_API_KEY="my-secret-api-key-12345"
#   ./start_test_nginx.sh

# Default configuration
DEFAULT_HOST="your-cvm-instance-host"
DEFAULT_PORT="50051"
DEFAULT_APP_ID="test-nginx-app"
DEFAULT_DEPLOYER_HEX="0xbae5046287f1b3fe2540d13160778c459d0f4038f1dcda0651679f5cb8a21f0ef1550b51ab5e6ae5a8e531512b1a06a97dfbb992c5e6f3aa36b04e1dd928d269"

# Parse command line arguments
TARGET_HOST=${1:-$DEFAULT_HOST}
TARGET_PORT=${2:-$DEFAULT_PORT}
APP_ID=${3:-$DEFAULT_APP_ID}
DEPLOYER_HEX=${4:-$DEFAULT_DEPLOYER_HEX}
API_KEY=${5:-$TAPP_API_KEY}  # From argument or environment variable
TARGET_ADDRESS="$TARGET_HOST:$TARGET_PORT"

# Remove 0x prefix if present
DEPLOYER_HEX=${DEPLOYER_HEX#0x}
DEPLOYER_HEX=${DEPLOYER_HEX#0X}

echo "======================================"
echo "StartApp Request Configuration"
echo "======================================"
echo "Target:        $TARGET_ADDRESS"
echo "App ID:        $APP_ID"
echo "Deployer:      $DEPLOYER_HEX"
if [ -n "$API_KEY" ]; then
    echo "API Key:       ${API_KEY:0:8}... (configured)"
else
    echo "API Key:       (not set)"
fi
echo "======================================"
echo ""

if [ -n "$DEPLOYER_HEX" ]; then
    DEPLOYER_BASE64=$(echo -n "$DEPLOYER_HEX" | xxd -r -p | base64)
else
    DEPLOYER_BASE64=""
fi

# --- Content Preparation ---

nginx_content='user nginx;
worker_processes 1;

events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    server {
        listen 80;
        server_name localhost;

        location / {
            root /usr/share/nginx/html;
            index index.html;
        }
    }
}'

config_content='{
  "key": "value",
  "enabled": true
}'

nginx_conf=$(printf '%s' "$nginx_content" | base64 -w 0)
config_json=$(printf '%s' "$config_content" | base64 -w 0)

compose_content='version: "3.8"
services:
  web:
    image: nginx:alpine
    command: ["nginx", "-g", "daemon off;"]
    ports:
      - "8080:80"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./config.json:/app/config.json
'

request_json=$(jq -n \
  --arg compose "$compose_content" \
  --arg nginx "$nginx_conf" \
  --arg config "$config_json" \
  --arg app_id "$APP_ID" \
  --arg deployer "$DEPLOYER_BASE64" \
  '{
    compose_content: $compose,
    app_id: $app_id,
    deployer: $deployer,
    mount_files: [
      {
        source_path: "./nginx.conf",
        content: $nginx,
        mode: "0644"
      },
      {
        source_path: "./config.json",
        content: $config,
        mode: "0644"
      }
    ]
  }')


echo "Sending StartApp request..."
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

GRPCURL_CMD="$GRPCURL_CMD -import-path ./proto -proto tapp_service.proto -d @ \"$TARGET_ADDRESS\" tapp_service.TappService/StartApp"

response=$(printf "%s" "$request_json" | tr -d '\n' | eval $GRPCURL_CMD 2>&1)


echo "Response:"
echo "--------------------------------------"
echo "$response"
echo "--------------------------------------"
echo ""

task_id=$(echo "$response" | jq -r '.taskId // .task_id // empty' 2>/dev/null)

echo "======================================"
echo "Next Steps:"
echo "======================================"
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
echo "======================================"