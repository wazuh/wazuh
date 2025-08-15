#!/bin/bash

# Test script for inventory sync tool
# This script demonstrates different usage patterns

echo "=== Inventory Sync Test Tool Demo ==="
echo

# Check if the tool exists
TOOL_PATH="/home/gvalenzuela/Documents/Work/StatelessPersistence/src/build/wazuh_modules/inventory_sync/testtool/inventory_sync_testtool"
if [ ! -f "$TOOL_PATH" ]; then
    echo "Error: $TOOL_PATH not found. Make sure to build the tool first."
    exit 1
fi

# Test 1: Basic usage with default test data
echo "Test 1: Running with default test data..."
$TOOL_PATH -c examples/config.json
echo "Test 1 completed."
echo

# Test 2: Process specific message sequence
echo "Test 2: Processing specific message sequence..."
$TOOL_PATH -c examples/config.json -i examples/start_message.json,examples/data_message_001.json,examples/data_message_002.json,examples/data_message_003.json,examples/end_message.json
echo "Test 2 completed."
echo

# Test 3: Process entire examples directory
echo "Test 3: Processing entire examples directory..."
$TOOL_PATH -c examples/config.json -i examples/ -l test_output.log
echo "Test 3 completed. Check test_output.log for detailed logs."
echo

# Test 4: Process raw JSON message
echo "Test 4: Processing raw JSON message..."
$TOOL_PATH -c examples/config.json -i examples/raw_json_message.json
echo "Test 4 completed."
echo

echo "=== All tests completed ==="
