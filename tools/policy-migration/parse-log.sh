#!/bin/bash

# Define the log file and output file names
LOG_FILE="./ossec.log"
OUTPUT_FILE="./5x.txt"

# Clear the output file if it already exists
> "$OUTPUT_FILE"

# Use sed to extract the ID and the result, stopping at the first comma
sed -nE 's/.*Policy check "([0-9]+)".*result: ([^,]*),?.*/\1|\2/p' "$LOG_FILE" >> "$OUTPUT_FILE"

echo "Policy check results saved to $OUTPUT_FILE"
