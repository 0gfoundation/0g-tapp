#!/bin/bash

# Usage:
#   ./get_evidence.sh [HOST] [PORT] [REPORT_DATA_HEX]
#
#   Or use environment variables:
#   REPORT_DATA_HEX=your_custom_data ./get_evidence.sh
#
# Examples:
#   ./get_evidence.sh
#   ./get_evidence.sh your-cvm-instance-host 50051
#   ./get_evidence.sh your-cvm-instance-host 50051 abcd1234...
#   REPORT_DATA_HEX=abcd1234... ./get_evidence.sh

# Default configuration
DEFAULT_HOST="your-cvm-instance-host"
DEFAULT_PORT="50051"
DEFAULT_REPORT_DATA_HEX="bae5046287f1b3fe2540d13160778c459d0f4038f1dcda0651679f5cb8a21f0ef1550b51ab5e6ae5a8e531512b1a06a97dfbb992c5e6f3aa36b04e1dd928d269"

# Parse command line arguments
TARGET_HOST=${1:-$DEFAULT_HOST}
TARGET_PORT=${2:-$DEFAULT_PORT}

# Report data priority: command line arg > environment variable > default
if [ -n "$3" ]; then
    REPORT_DATA_HEX="$3"
elif [ -n "$REPORT_DATA_HEX" ]; then
    REPORT_DATA_HEX="$REPORT_DATA_HEX"
else
    REPORT_DATA_HEX="$DEFAULT_REPORT_DATA_HEX"
fi

TARGET_ADDRESS="$TARGET_HOST:$TARGET_PORT"

# Remove 0x prefix if present
REPORT_DATA_HEX=${REPORT_DATA_HEX#0x}
REPORT_DATA_HEX=${REPORT_DATA_HEX#0X}

# Validate report data length (should be at most 128 hex characters = 64 bytes)
if [ ${#REPORT_DATA_HEX} -gt 128 ]; then
    echo "Error: Report data must be at most 64 bytes (128 hex characters)"
    echo "Got: ${#REPORT_DATA_HEX} hex characters"
    echo ""
    echo "Usage: $0 [HOST] [PORT] [REPORT_DATA_HEX]"
    echo ""
    echo "Example:"
    echo "  $0 your-cvm-instance-host 50051 bae5046287f1b3fe2540d13160778c459d0f4038f1dcda0651679f5cb8a21f0ef1550b51ab5e6ae5a8e531512b1a06a97dfbb992c5e6f3aa36b04e1dd928d269"
    echo ""
    echo "Or set REPORT_DATA_HEX environment variable:"
    echo "  REPORT_DATA_HEX=bae5046287f1b3fe2540d13160778c459d0f4038f1dcda0651679f5cb8a21f0ef1550b51ab5e6ae5a8e531512b1a06a97dfbb992c5e6f3aa36b04e1dd928d269 $0"
    exit 1
fi

# Convert hex to base64 (if not empty)
if [ -n "$REPORT_DATA_HEX" ]; then
    REPORT_DATA_BASE64=$(echo -n "$REPORT_DATA_HEX" | xxd -r -p | base64)
else
    REPORT_DATA_BASE64=""
fi

# Display configuration
echo "======================================"
echo "GetEvidence Request Configuration"
echo "======================================"
echo "Target:             $TARGET_ADDRESS"
echo "Report Data (hex):  $REPORT_DATA_HEX"
echo "Report Data (b64):  $REPORT_DATA_BASE64"
echo "======================================"
echo ""

# Call gRPC service
grpcurl -plaintext -import-path ./proto -proto tapp_service.proto \
  -d "{
    \"report_data\": \"$REPORT_DATA_BASE64\"
  }" \
  "$TARGET_ADDRESS" \
  tapp_service.TappService/GetEvidence