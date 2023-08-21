#!/bin/bash

# Check if a path argument is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <binary_path>"
    exit 1
fi

BINARY_PATH="$1"
ROOT_FOLDER="/home/runner/work/wazuh/wazuh/src/engine/test/integration_tests"

# Execute the binary with the argument "server start"
"$BINARY_PATH" server start &

# Capture the process ID of the binary
BINARY_PID=$!

# Wait for the server to start
# You might need to replace this with a more reliable check
sleep 2

# Find "features" folders and execute Behave
find "$ROOT_FOLDER" -type d -name "features" | while read features_dir; do
    steps_dir=$(dirname "$features_dir")/steps
    if [ -d "$steps_dir" ]; then
        echo "Running Behave in $features_dir"
        behave "$features_dir"
    fi
done

# Terminate the binary process by sending a termination signal
kill $BINARY_PID
