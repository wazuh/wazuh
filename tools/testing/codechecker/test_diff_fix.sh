#!/bin/bash
# test_diff_fix.sh — Targeted test for the CodeChecker cmd diff exit-2 fix.
#
# Tests that flawfinder findings are merged into diff_new.json even when
# CodeChecker cmd diff exits 2 (its normal exit code when findings exist).
#
# Requires:
#   - workspace/wazuh/reports_base        (from a previous scan)
#   - workspace/wazuh/reports_target      (from a previous scan)
#   - workspace/reports_flawfinder_target (from a previous scan)
#
# Uses the current local scripts (no image rebuild needed) by mounting
# tools/testing/codechecker/ over /cc/ inside the existing image.
#
# Usage (from repo root):
#   bash tools/testing/codechecker/test_diff_fix.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE="$SCRIPT_DIR/workspace"
RESULTS_DIR="/tmp/cc-fixtest-$$"
IMAGE="${IMAGE:-ghcr.io/wazuh/codechecker:latest}"

echo "==> Checking prerequisites"
[ -d "$WORKSPACE/wazuh/reports_base" ]        || { echo "SKIP: no reports_base in workspace — run a scan first"; exit 0; }
[ -d "$WORKSPACE/wazuh/reports_target" ]      || { echo "SKIP: no reports_target in workspace — run a scan first"; exit 0; }
[ -d "$WORKSPACE/reports_flawfinder_target" ] || { echo "SKIP: no reports_flawfinder_target in workspace — run a scan first"; exit 0; }

echo "  workspace: $WORKSPACE"
echo "  image:     $IMAGE"
echo "  results:   $RESULTS_DIR"
mkdir -p "$RESULTS_DIR"

docker run --rm \
  -v "$SCRIPT_DIR:/cc" \
  -v "$WORKSPACE:/workspace" \
  -v "$RESULTS_DIR:/results" \
  "$IMAGE" bash -c '
set -euo pipefail

RED="\033[0;31m" GREEN="\033[0;32m" YELLOW="\033[1;33m" NC="\033[0m"
ok()   { echo -e "${GREEN}  [PASS] $1${NC}"; }
fail() { echo -e "${RED}  [FAIL] $1${NC}"; exit 1; }
info() { echo -e "${YELLOW}  $1${NC}"; }

b=/workspace/wazuh/reports_base
n=/workspace/wazuh/reports_target
fn=/workspace/reports_flawfinder_target
fb=/tmp/fw_base_empty   # empty dir = all target flawfinder findings appear as "new"

mkdir -p "$fb" /results

# ── Step 1: main diff → populates diff_new.json ──────────────────────────────
info "Step 1: main diff (clangsa/cppcheck)"
CodeChecker cmd diff -b "$b" -n "$n" --new -o json -e /results/diff_new.json >/dev/null 2>&1 || true
[ -f /results/diff_new.json/reports.json ] \
    && ok "diff_new.json/reports.json created" \
    || fail "diff_new.json/reports.json missing after main diff"
main_count=$(python3 -c "import json; d=json.load(open(\"/results/diff_new.json/reports.json\")); print(len(d[\"reports\"]))")
info "  main diff new findings: $main_count"

# ── Step 2: confirm CodeChecker cmd diff exits 2 when findings exist ──────────
info "Step 2: confirm exit-2 behaviour (empty base vs flawfinder target)"
{ CodeChecker cmd diff -b "$fb" -n "$fn" --new -o json -e /tmp/probe_fw >/dev/null 2>&1; ec=$?; } || true
info "  CodeChecker cmd diff exit code: $ec"
[ "$ec" -eq 2 ] \
    && ok "exit code is 2 as expected" \
    || info "  (exit code was $ec — may be 0 if no findings in this workspace)"

# ── Step 3: run the FIXED merge pattern ───────────────────────────────────────
info "Step 3: run fixed merge pattern (|| true + file-existence check)"
fw_new_dir=/results/diff_new.json

CodeChecker cmd diff -b "$fb" -n "$fn" --new -o json -e "${fw_new_dir}_fw" >/dev/null 2>&1 || true
if [ -f "${fw_new_dir}_fw/reports.json" ]; then
    fw_count=$(python3 -c "import json; d=json.load(open(\"${fw_new_dir}_fw/reports.json\")); print(len(d[\"reports\"]))")
    info "  flawfinder new findings: $fw_count"
    python3 /cc/merge_reports_json.py "${fw_new_dir}_fw/reports.json" "$fw_new_dir/reports.json" \
        && ok "merge_reports_json.py succeeded" \
        || fail "merge_reports_json.py failed"
    merged=$(python3 -c "import json; d=json.load(open(\"$fw_new_dir/reports.json\")); print(len(d[\"reports\"]))")
    info "  diff_new.json now has $merged findings ($main_count main + $fw_count flawfinder)"
    [ "$merged" -eq $(( main_count + fw_count )) ] \
        && ok "finding count correct: $main_count + $fw_count = $merged" \
        || fail "count mismatch: expected $(( main_count + fw_count )), got $merged"
else
    info "  (no flawfinder findings in reports.json_fw — workspace may have 0-diff flawfinder)"
    ok "file-existence check works (no merge needed when no findings)"
fi

echo ""
echo -e "${GREEN}All checks passed.${NC}"
'

echo ""
echo "Results in: $RESULTS_DIR"
