#!/bin/bash
set -euo pipefail

# Define the log file and output file names
LOG_FILE="./ossec.log"
OUTPUT_FILE="./5x.txt"

# Clear the output file if it already exists
> "$OUTPUT_FILE"

# Use sed to extract the ID and the result, stopping at the first comma
sed -nE 's/.*Policy check "([0-9]+)".*result: ([^,]*),?.*/\1|\2/p' "$LOG_FILE" >> "$OUTPUT_FILE"

echo "✅ Log file parsed to $OUTPUT_FILE"

# 1. Locate databases
DB4=$(ls *.db | grep -E '^[0-9]+\.db$' | head -n 1)

# Check that db exists
if [[ -z "$DB4" ]]; then
  echo "❌ Error: no numbered DB (e.g., 001.db) found"
  exit 1
fi

echo "✅ Using $DB4 (4.x)"

# 2. Extract results into text file
sqlite3 "$DB4" "select id, result from sca_check;" > 4x.txt

echo "✅ Extracted results to 4x.txt"

# 3. Run Python merge script
if [[ ! -f merge.py ]]; then
  echo "❌ Error: merge.py not found in current directory"
  exit 1
fi

python3 merge.py
echo "✅ Merge complete. Output saved to merged_results.txt"
