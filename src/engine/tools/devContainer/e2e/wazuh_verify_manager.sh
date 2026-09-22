#!/usr/bin/env bash
# wazuh_verify_manager.sh — parseable health check of an installed wazuh-manager.
#
# One line per check, "PASS|FAIL|SKIP  <n>. <name> (got: ...)", then
#   # summary: executed=N passed=N failed=N skipped=N
#   # manifest: <path>
# Exit status is 0 iff failed=0. Everything the checks read is copied under --out so a run can be
# attached as evidence: status.txt, conf-validate.txt, cacerts.pem, manager.log (the window since
# --start-mark), manager-errors.log, verify-manager.log, manifest.md. Nothing secret is written: the
# bundle served by GET /cacerts is public material.
#
# Used by the VS Code task "E2E Scripts: [Manager] Verify installed manager", by
# wazuh_install_manager.sh after every install, and by the manager-env skill.
set -u

usage() {
  cat <<EOF
Usage: sudo $0 [--home DIR] [--out DIR] [--start-mark FILE] [--api] [--daemons N]
               [--ignore-regex RE] [--no-manifest] [-h|--help]

Checks (each one PASS/FAIL/SKIP):
  1.  wazuh-manager-control status reports every daemon running (--daemons, default 7)
  1b. no daemon reported "not running"
  2.  wazuh-manager-conf validate exits 0
  3.  GET <prefix>/cacerts on the HTTPS agent listener answers 200 (port/prefix from the live config)
  4.  no new ERROR/CRITICAL line in logs/wazuh-manager.log since --start-mark, ignoring --ignore-regex
      (SKIP without a mark; the last 300 lines are still copied to manager.log)
  5.  API login with the default user (only with --api)

Options:
  --home DIR          installed manager (default /var/wazuh-manager, or WAZUH_MANAGER_HOME)
  --out DIR           where to write the evidence files (default \$TMPDIR/wazuh-e2e-evidence/<timestamp>)
  --start-mark FILE   file holding the byte offset of logs/wazuh-manager.log taken before the start
                      (wazuh_install_manager.sh writes it as start.mark)
  --api               also try POST /security/user/authenticate with the default credentials
  --daemons N         expected number of running daemons (default 7)
  --ignore-regex RE   ERROR/CRITICAL lines matching RE are known environment noise (default:
                      indexer-related noise of a manager running without an indexer)
  --no-manifest       do not write manifest.md (wazuh_install_manager.sh composes its own)
EOF
}

HOME_DIR="${WAZUH_MANAGER_HOME:-/var/wazuh-manager}"
OUT=""
MARK=""
API=0
DAEMONS=7
IGNORE='indexer|9200|IndexerDownloader|Failed to synchronize|IOC syncronization|not used by Wazuh, removing'
WRITE_MANIFEST=1
while [ $# -gt 0 ]; do
  case "$1" in
    --home) HOME_DIR=$2; shift 2 ;;
    --out) OUT=$2; shift 2 ;;
    --start-mark) MARK=$2; shift 2 ;;
    --api) API=1; shift ;;
    --daemons) DAEMONS=$2; shift 2 ;;
    --ignore-regex) IGNORE=$2; shift 2 ;;
    --no-manifest) WRITE_MANIFEST=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: run as root (the manager log and control script are not world-readable)" >&2
  exit 2
fi

CTRL="$HOME_DIR/bin/wazuh-manager-control"
CONF="$HOME_DIR/bin/wazuh-manager-conf"
LOGF="$HOME_DIR/logs/wazuh-manager.log"
if [ ! -x "$CTRL" ]; then
  echo "ERROR: no manager installed at $HOME_DIR ($CTRL missing)" >&2
  exit 2
fi

OUT="${OUT:-${TMPDIR:-/tmp}/wazuh-e2e-evidence/$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$OUT"
REP="$OUT/verify-manager.log"
: > "$REP"

ran=0; ok=0; ko=0; sk=0
say()   { echo "$*" | tee -a "$REP"; }
TSV="$OUT/checks.tsv"
: > "$TSV"
check() { # check <id> <name> <expected> <got>
  ran=$((ran + 1))
  if [ "$3" = "$4" ]; then ok=$((ok + 1)); say "PASS  $1. $2 (got: $4)"; printf '%s\t%s\tPASS\t%s\n' "$1" "$2" "$4" >> "$TSV"
  else ko=$((ko + 1)); say "FAIL  $1. $2 (expected: $3, got: $4)"; printf '%s\t%s\tFAIL\texpected %s, got %s\n' "$1" "$2" "$3" "$4" >> "$TSV"; fi
}
skip()  { sk=$((sk + 1)); say "SKIP  $1. $2 ($3)"; printf '%s\t%s\tSKIP\t%s\n' "$1" "$2" "$3" >> "$TSV"; }
now()   { date -u +%Y-%m-%dT%H:%M:%SZ; }

say "# wazuh_verify_manager.sh — $(now) — home=$HOME_DIR"

# 1. every daemon running (the DAEMONS list lives in src/init/wazuh-server.sh)
st=$("$CTRL" status 2>&1)
printf '%s\n' "$st" > "$OUT/status.txt"
running=$(grep -c 'is running' <<<"$st" || true)
not_running=$(grep -c 'not running' <<<"$st" || true)
check 1 "daemons running" "$DAEMONS" "$running"
check 1b "daemons reported not running" 0 "$not_running"

# 2. the installed configuration validates against the schema
if [ -x "$CONF" ]; then
  "$CONF" validate > "$OUT/conf-validate.txt" 2>&1
  check 2 "wazuh-manager-conf validate rc" 0 "$?"
else
  skip 2 "wazuh-manager-conf validate" "$CONF missing"
fi

# 3. the HTTPS agent listener answers GET /cacerts (port and prefix from the live config)
remote_json=$("$CONF" get remote 2>/dev/null || true)
PORT=$(printf '%s' "$remote_json" | python3 -c 'import json,sys;print(json.load(sys.stdin)["https"]["port"])' 2>/dev/null || echo 1517)
PFX=$(printf '%s' "$remote_json" | python3 -c 'import json,sys;print(json.load(sys.stdin)["https"].get("global_prefix","").rstrip("/"))' 2>/dev/null || echo "")
URL="https://127.0.0.1:${PORT}${PFX}/cacerts"
code=$(curl -sk -o "$OUT/cacerts.pem" -w '%{http_code}' --max-time 10 "$URL" 2>/dev/null || echo 000)
check 3 "GET ${PFX}/cacerts on :${PORT}" 200 "$code"

# 4. no new ERROR/CRITICAL since the start mark (known environment noise ignored, but listed)
if [ -n "$MARK" ] && [ -f "$MARK" ] && [ -f "$LOGF" ]; then
  off=$(tr -dc '0-9' < "$MARK")
  tail -c +$(( ${off:-0} + 1 )) "$LOGF" > "$OUT/manager.log"
  grep -E 'ERROR|CRITICAL' "$OUT/manager.log" | grep -Ev "$IGNORE" > "$OUT/manager-errors.log" || true
  check 4 "new ERROR/CRITICAL lines since start" 0 "$(wc -l < "$OUT/manager-errors.log")"
  say "      window: $(wc -l < "$OUT/manager.log") lines · WARNING: $(grep -c 'WARNING' "$OUT/manager.log" || true) · ignored ERROR/CRITICAL: $(grep -E 'ERROR|CRITICAL' "$OUT/manager.log" | grep -Ec "$IGNORE" || true)"
else
  [ -f "$LOGF" ] && tail -n 300 "$LOGF" > "$OUT/manager.log"
  skip 4 "new ERROR/CRITICAL lines" "no --start-mark; last 300 lines in manager.log"
fi

# 5. API login with the default user (framework/wazuh/rbac/default/users.yaml)
if [ "$API" -eq 1 ]; then
  API_PORT=$(grep -E '^port:' "$HOME_DIR/api/configuration/api.yaml" 2>/dev/null | awk '{print $2}')
  API_PORT="${API_PORT:-55000}"
  tok=$(curl -sk --max-time 15 -u "wazuh:${INITIAL_WAZUH_PASSWORD:-DevCont4iner-Api.}" -X POST "https://127.0.0.1:${API_PORT}/security/user/authenticate" 2>/dev/null \
        | python3 -c 'import json,sys;print(json.load(sys.stdin)["data"]["token"])' 2>/dev/null || true)
  check 5 "API login as wazuh on :${API_PORT}" yes "$([ -n "$tok" ] && echo yes || echo no)"
else
  skip 5 "API login" "--api not given"
fi

say "# summary: executed=$ran passed=$ok failed=$ko skipped=$sk"

if [ "$WRITE_MANIFEST" -eq 1 ]; then
  {
    echo "# manager-env manifest — $(now)"
    echo "mode: verify"
    echo "manager.home: $HOME_DIR"
    echo "remoted.https: port=$PORT prefix=${PFX:-/}"
    [ -f "$HOME_DIR/etc/.install-provenance" ] && sed 's/^/installed./' "$HOME_DIR/etc/.install-provenance"
    echo
    echo "| # | check | verdict | got / reason |"
    echo "|---|---|---|---|"
    awk -F'\t' '{ printf "| %s | %s | %s | %s |\n", $1, $2, $3, $4 }' "$TSV"
    echo
    echo "summary: executed=$ran passed=$ok failed=$ko skipped=$sk"
    echo "logs: verify-manager.log checks.tsv status.txt conf-validate.txt cacerts.pem manager.log manager-errors.log"
  } > "$OUT/manifest.md"
  say "# manifest: $OUT/manifest.md"
else
  say "# manifest: (skipped) $OUT"
fi

[ "$ko" -eq 0 ]
