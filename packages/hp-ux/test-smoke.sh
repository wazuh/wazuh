#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
TARGET_SCRIPT="${SCRIPT_DIR}/generate_wazuh_packages.sh"
CERT_FILE="${SCRIPT_DIR}/certificates/cacert.pem"

failures=0

pass() {
  echo "PASS: $1"
}

fail() {
  echo "FAIL: $1"
  failures=$((failures + 1))
}

check_file_exists() {
  local file="$1"
  local label="$2"
  if [[ -f "$file" ]]; then
    pass "$label exists"
  else
    fail "$label missing: $file"
  fi
}

check_file_nonempty() {
  local file="$1"
  local label="$2"
  if [[ -s "$file" ]]; then
    pass "$label is not empty"
  else
    fail "$label is empty: $file"
  fi
}

check_contains() {
  local pattern="$1"
  local file="$2"
  local label="$3"
  if grep -Eq "$pattern" "$file"; then
    pass "$label"
  else
    fail "$label (pattern not found: $pattern)"
  fi
}

check_not_contains() {
  local pattern="$1"
  local file="$2"
  local label="$3"
  if grep -Eq "$pattern" "$file"; then
    fail "$label (unexpected pattern found: $pattern)"
  else
    pass "$label"
  fi
}

echo "Running smoke checks for: $TARGET_SCRIPT"

check_file_exists "$TARGET_SCRIPT" "HP-UX build script"
check_file_exists "$CERT_FILE" "CA certificate bundle"
check_file_nonempty "$CERT_FILE" "CA certificate bundle"

if bash -n "$TARGET_SCRIPT"; then
  pass "Shell syntax is valid"
else
  fail "Shell syntax check failed"
fi

check_contains 'CERT_BUNDLE=.*certificates/cacert\.pem' "$TARGET_SCRIPT" "Certificate bundle path is configured"
check_contains 'export CURL_CA_BUNDLE=' "$TARGET_SCRIPT" "CURL_CA_BUNDLE export is configured"
check_contains 'export SSL_CERT_FILE=' "$TARGET_SCRIPT" "SSL_CERT_FILE export is configured"

check_not_contains 'curl[^\n]*-k' "$TARGET_SCRIPT" "No insecure curl -k usage"
check_not_contains 'http://packages\.wazuh\.com' "$TARGET_SCRIPT" "No insecure HTTP to packages.wazuh.com"
check_not_contains 'http://packages-dev\.wazuh\.com' "$TARGET_SCRIPT" "No insecure HTTP to packages-dev.wazuh.com"

check_contains 'https://packages\.wazuh\.com' "$TARGET_SCRIPT" "Secure HTTPS packages.wazuh.com is present"

echo
if [[ "$failures" -eq 0 ]]; then
  echo "SMOKE RESULT: PASS"
  exit 0
fi

echo "SMOKE RESULT: FAIL ($failures checks failed)"
exit 1