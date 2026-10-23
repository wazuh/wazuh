#!/bin/bash
###############################################################################
# run_infer.sh — Static data-race / concurrency analysis via Meta Infer
# (RacerD), stored into the CodeChecker dashboard.
#
# Uses compilation-database mode (not `infer run -- make`) because Infer's
# bundled clang crashes on Wazuh's heavy C++ TUs.  Strategy:
#   1. Build normally with `CodeChecker log` to get compile_commands.json.
#   2. Filter to C translation units (drops the C++ modules that crash Infer).
#   3. `infer capture --compilation-database` + `infer analyze --racerd-only`.
#   4. Convert with `report-converter -t fbinfer` and store to dashboard.
#
# Run INSIDE the codechecker container:
#   docker compose exec -e REF=6376a98 -e TARGET=server \
#     -e RUN_NAME=wazuh-coverity-w15-infer analyzer bash /cc/run_infer.sh
###############################################################################
set -euo pipefail

REF="${REF:-}"
TARGET="${TARGET:-manager}"
RUN_NAME="${RUN_NAME:-wazuh-${REF}-infer}"
WAZUH_DIR="${WAZUH_DIR:-/workspace/wazuh}"
URL="${URL:-http://127.0.0.1:8001/Default}"
JOBS="${JOBS:-$(nproc)}"
INFER_OUT="${INFER_OUT:-$WAZUH_DIR/infer-out}"
REPORTS="${REPORTS:-$WAZUH_DIR/reports_infer}"
COMPILE_DB="${COMPILE_DB:-$WAZUH_DIR/compile_commands_infer.json}"
FILES="${FILES:-}"

command -v infer >/dev/null 2>&1 || { echo "[FAIL] infer not installed"; exit 1; }
[ -n "$REF" ] || { echo "[FAIL] REF is required"; exit 1; }
cd "$WAZUH_DIR" || { echo "[FAIL] no clone at $WAZUH_DIR"; exit 1; }

echo "==> Checkout $REF"
git checkout --force "$REF" || { echo "[FAIL] checkout"; exit 1; }
git submodule update --init --recursive || true
git clean -xdf -e 'reports_*' -e 'compile_commands_*.json' -e 'infer-out' || true
find . -type d -name build -prune -exec rm -rf {} + 2>/dev/null || true

# 4.x trees recognise only "server"; 5.x+ use "manager".
if [ "$TARGET" = "manager" ] && [ -f "$WAZUH_DIR/VERSION.json" ]; then
    _major=$(python3 -c \
        "import json,sys; d=json.load(open(sys.argv[1])); print(d['version'].split('.')[0])" \
        "$WAZUH_DIR/VERSION.json" 2>/dev/null || echo "5")
    if [ "$_major" = "4" ]; then
        TARGET="server"
        echo "[OK] 4.x compat — using make TARGET=server"
    fi
fi

( cd src && make deps TARGET="$TARGET" -j"$JOBS" ) || { echo "[FAIL] make deps"; exit 1; }

echo "==> Build with CodeChecker log -> $COMPILE_DB"
( cd src && CodeChecker log -b "make TARGET=$TARGET DEBUG=1 -j$JOBS" -o "$COMPILE_DB" ) \
    || { echo "[FAIL] build/log"; exit 1; }
[ -s "$COMPILE_DB" ] || { echo "[FAIL] empty compile DB"; exit 1; }

echo "==> Filter compile DB to C TUs"
FILT="${COMPILE_DB%.json}.filtered.json"
python3 - "$COMPILE_DB" "$FILT" "${FILES}" <<'PY'
import json, sys, re
src, dst, patt = sys.argv[1], sys.argv[2], sys.argv[3]
db = json.load(open(src))
def keep(e):
    f = e.get("file", "")
    if not f.endswith(".c"):   return False
    if "/external/" in f:      return False
    if patt and not re.search(patt, f): return False
    return True
out = [e for e in db if keep(e)]
json.dump(out, open(dst, "w"))
print(f"  kept {len(out)}/{len(db)} TUs")
PY
[ -s "$FILT" ] || { echo "[FAIL] filtered DB is empty"; exit 1; }

echo "==> infer capture + analyze (RacerD)"
rm -rf "$INFER_OUT"
infer capture --keep-going --compilation-database "$FILT" --results-dir "$INFER_OUT" \
    || echo "[WARN] capture non-zero (per-TU failures tolerated)"
infer analyze --racerd-only --results-dir "$INFER_OUT" \
    || echo "[WARN] analyze non-zero (findings present is normal)"

if [ ! -s "$INFER_OUT/report.json" ] || \
   ! python3 -c "import json;json.load(open('$INFER_OUT/report.json'))" 2>/dev/null; then
    echo "[FAIL] no valid infer report.json"; exit 1
fi
N=$(python3 -c "import json;print(len(json.load(open('$INFER_OUT/report.json'))))" 2>/dev/null)
echo "[OK] Infer findings: ${N:-?}"

if [ "${N:-0}" = "0" ]; then
    echo "==> Infer/RacerD found 0 issues — storing empty run for dashboard tracking"
    echo "    (RacerD's raw-pthread-C support is partial; a clean run is a valid result)"
fi

echo "==> Convert + store as '$RUN_NAME'"
rm -rf "$REPORTS"
report-converter -t fbinfer -o "$REPORTS" "$INFER_OUT" \
    && CodeChecker store "$REPORTS" --name "$RUN_NAME" --url "$URL" \
       && echo "[OK] stored '$RUN_NAME'" \
    || echo "[WARN] convert/store failed"

echo "==> Findings on auth.c / wdb_global.c:"
grep -iE "auth\.c|wdb_global\.c" "$INFER_OUT/report.txt" 2>/dev/null | head || echo "  (none)"
