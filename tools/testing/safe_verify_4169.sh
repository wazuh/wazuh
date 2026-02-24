#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHECK_CLUSTER_SCRIPT="$ROOT_DIR/tools/testing/check_cluster.sh"
RUN_DAPI_SCRIPT="$ROOT_DIR/tools/testing/run_dapi_tests.sh"
MARKER_FILE="/var/ossec/etc/poc_rce_marker.xml"
LOG_DIR="/tmp"
TS="$(date +%Y%m%d_%H%M%S)"
REPORT_FILE="$LOG_DIR/safe_verify_4169_${TS}.log"
DAPI_TEST_LOG="$LOG_DIR/dapi_regression_${TS}.log"

SECURITY_CANDIDATES=(
  "/var/ossec/api/configuration/security/security.yaml"
  "/var/ossec/api/configuration/security/rbac.db"
  "/var/ossec/api/configuration/api.yaml"
)

usage() {
  cat <<'EOF'
Usage:
  ./tools/testing/safe_verify_4169.sh [--skip-tests]

What it does (safe / non-destructive):
  1) Verifies cluster status (master+worker) using check_cluster.sh
  2) Computes SHA256 of detected security-related files before and after tests
  3) Runs DAPI regression tests
  4) Verifies no known PoC marker file exists
  5) Prints PASS/FAIL summary

Options:
  --skip-tests  Skip DAPI regression execution and only do integrity checks.
  -h, --help    Show help.
EOF
}

log() {
  printf "%b\n" "$*" | tee -a "$REPORT_FILE"
}

require_file() {
  local f="$1"
  if [[ ! -f "$f" ]]; then
    log "ERROR: Missing file: $f"
    exit 1
  fi
}

sha256_file() {
  local path="$1"
  sudo sha256sum "$path" | awk '{print $1}'
}

collect_security_targets() {
  local targets=()
  local candidate

  for candidate in "${SECURITY_CANDIDATES[@]}"; do
    if sudo test -f "$candidate"; then
      targets+=("$candidate")
    fi
  done

  printf '%s\n' "${targets[@]}"
}

skip_tests=0
if [[ $# -gt 0 ]]; then
  case "$1" in
    --skip-tests)
      skip_tests=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
fi

: > "$REPORT_FILE"
log "== Safe verification for Issue 4169 =="
log "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "Report: $REPORT_FILE"

require_file "$CHECK_CLUSTER_SCRIPT"
require_file "$RUN_DAPI_SCRIPT"

mapfile -t SECURITY_TARGETS < <(collect_security_targets)

if [[ ${#SECURITY_TARGETS[@]} -eq 0 ]]; then
  log "ERROR: No security integrity files found in expected locations."
  log "Checked: ${SECURITY_CANDIDATES[*]}"
  exit 1
fi

log "Detected integrity targets:"
for target in "${SECURITY_TARGETS[@]}"; do
  log "  - $target"
done

log "\n[1/4] Cluster health check"
if "$CHECK_CLUSTER_SCRIPT" --health-only | tee -a "$REPORT_FILE"; then
  cluster_ok=1
else
  cluster_ok=0
fi

log "\n[2/4] Baseline security artifacts hash"
declare -A HASH_BEFORE
for target in "${SECURITY_TARGETS[@]}"; do
  HASH_BEFORE["$target"]="$(sha256_file "$target")"
  log "SHA256 before | $target | ${HASH_BEFORE[$target]}"
done

if [[ "$skip_tests" -eq 0 ]]; then
  log "\n[3/4] Running DAPI regression tests"
  log "DAPI test log: $DAPI_TEST_LOG"
  if "$RUN_DAPI_SCRIPT" --regression --log "$DAPI_TEST_LOG" | tee -a "$REPORT_FILE"; then
    tests_ok=1
  else
    tests_ok=0
  fi
else
  log "\n[3/4] Skipping DAPI tests (--skip-tests)"
  tests_ok=1
fi

log "\n[4/4] Post-check integrity"
declare -A HASH_AFTER
for target in "${SECURITY_TARGETS[@]}"; do
  HASH_AFTER["$target"]="$(sha256_file "$target")"
  log "SHA256 after  | $target | ${HASH_AFTER[$target]}"
done

if sudo test -f "$MARKER_FILE"; then
  marker_ok=0
  log "Marker file status: FOUND ($MARKER_FILE)"
else
  marker_ok=1
  log "Marker file status: NOT FOUND"
fi

integrity_ok=1
for target in "${SECURITY_TARGETS[@]}"; do
  if [[ "${HASH_BEFORE[$target]}" != "${HASH_AFTER[$target]}" ]]; then
    integrity_ok=0
    log "Integrity check: CHANGED -> $target"
  fi
done

if [[ $integrity_ok -eq 1 ]]; then
  log "Security artifacts integrity: UNCHANGED"
fi

log "\n== Summary =="
log "Cluster health:   $([[ $cluster_ok -eq 1 ]] && echo PASS || echo FAIL)"
log "DAPI regression:  $([[ $tests_ok -eq 1 ]] && echo PASS || echo FAIL)"
log "Integrity files:  $([[ $integrity_ok -eq 1 ]] && echo PASS || echo FAIL)"
log "PoC marker file:  $([[ $marker_ok -eq 1 ]] && echo PASS || echo FAIL)"

if [[ $cluster_ok -eq 1 && $tests_ok -eq 1 && $integrity_ok -eq 1 && $marker_ok -eq 1 ]]; then
  log "\nSAFE VERIFY RESULT: PASS"
  exit 0
else
  log "\nSAFE VERIFY RESULT: FAIL"
  exit 1
fi
