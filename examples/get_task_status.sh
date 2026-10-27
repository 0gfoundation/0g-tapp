#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

DEFAULT_HOST="localhost"
DEFAULT_PORT="50051"

TASK_ID=""
TARGET_HOST="$DEFAULT_HOST"
TARGET_PORT="$DEFAULT_PORT"

while [[ $# -gt 0 ]]; do
    case $1 in
        --task-id)
            TASK_ID="$2"
            shift 2
            ;;
        --host)
            TARGET_HOST="$2"
            shift 2
            ;;
        --port)
            TARGET_PORT="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 --task-id TASK_ID [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --task-id TASK_ID       Task ID returned from StartApp (required)"
            echo "  --host HOST             gRPC server host (default: $DEFAULT_HOST)"
            echo "  --port PORT             gRPC server port (default: $DEFAULT_PORT)"
            echo "  --help, -h              Show this help message"
            exit 0
            ;;
        *)
            if [ -z "$TASK_ID" ]; then
                TASK_ID="$1"
            elif [ "$TARGET_HOST" = "$DEFAULT_HOST" ]; then
                TARGET_HOST="$1"
            elif [ "$TARGET_PORT" = "$DEFAULT_PORT" ]; then
                TARGET_PORT="$1"
            else
                echo "Unknown option: $1"
                exit 1
            fi
            shift
            ;;
    esac
done

TARGET_ADDRESS="$TARGET_HOST:$TARGET_PORT"

if [ -z "$TASK_ID" ]; then
    echo "Error: Task ID is required"
    exit 1
fi

# Dependency checks
missing_deps=()
if ! command -v grpcurl &> /dev/null; then
    missing_deps+=("grpcurl")
fi

proto_file="$SCRIPT_DIR/../proto/tapp_service.proto"
if [ ! -f "$proto_file" ]; then
    missing_deps+=("tapp_service.proto")
fi

if [ ${#missing_deps[@]} -gt 0 ]; then
    echo "❌ Missing dependencies: ${missing_deps[*]}"
    exit 1
fi

echo "======================================"
echo "GetTaskStatus Request"
echo "======================================"
echo "Target:        $TARGET_ADDRESS"
echo "Task ID:       $TASK_ID"
echo "======================================"
echo ""

echo "Querying task status..."
echo ""

# Just call grpcurl directly and let it output naturally
echo '{"task_id":"'"$TASK_ID"'"}' | \
  grpcurl -plaintext \
    -import-path "$SCRIPT_DIR/../proto" \
    -proto tapp_service.proto \
    -d @ \
    "$TARGET_ADDRESS" \
    tapp_service.TappService/GetTaskStatus

echo ""
echo "======================================"