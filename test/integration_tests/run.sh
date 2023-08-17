#!/bin/bash

# Check if a path argument is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <binary_path>"
    exit 1
fi

BINARY_PATH="$1"
ROOT_FOLDER="integration_tests"

# Execute the binary with the argument "server start"
"$BINARY_PATH" server start &

# Capture the process ID of the binary
BINARY_PID=$!

# TODO: Investigate some way to evaluate if the server is started
sleep 1

find "$ROOT_FOLDER" -type d -name "features" -exec sh -c '
    features_dir="$0"
    steps_dir=$(dirname "$features_dir")/steps
    if [ -d "$steps_dir" ]; then
        echo "Running Behave in $features_dir"
        behave "$features_dir"
    fi
' {} \;

# Terminate the binary process by sending a termination signal
kill $BINARY_PID
