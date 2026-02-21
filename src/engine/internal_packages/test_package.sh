#!/usr/bin/env bash
# Test script for wazuh-internal-tools package
# Verifies that all installed tools respond correctly to -h flag

set -uo pipefail  # Removed -e to allow test failures without stopping script

TOOLS=(
  engine-archiver
  engine-helper-test
  engine-test
  engine-public
  engine-private
  engine-it
  engine-router
)

EXTRA_TESTS=(
  "engine-private cm -h"
  "engine-private ns -h"
  "engine-private geo -h"
  "engine-private rawevt -h"
  "engine-public cm -h"
)

echo "=========================================="
echo "Testing wazuh-internal-tools installation"
echo "=========================================="
echo

fail_count=0
pass_count=0

test_command() {
  local cmd_str="$1"
  read -r -a cmd <<<"$cmd_str"

  printf "Testing: %-40s" "$cmd_str"

  output=$("${cmd[@]}" 2>&1)
  rc=$?

  if [[ $rc -eq 0 ]]; then
    echo "✓ PASS"
    ((pass_count++))
  else
    echo "✗ FAIL (exit code: $rc)"
    echo "  Output:"
    echo "$output" | head -c 500 | sed 's/^/    /'
    echo
    ((fail_count++))
  fi
}

# Test basic -h for each tool
for tool in "${TOOLS[@]}"; do
  test_command "$tool -h"
done

# Test extra commands
for test in "${EXTRA_TESTS[@]}"; do
  test_command "$test"
done

echo
echo "=========================================="
echo "Results: $pass_count passed, $fail_count failed"
echo "=========================================="

if [[ $fail_count -gt 0 ]]; then
  exit 1
fi

exit 0
