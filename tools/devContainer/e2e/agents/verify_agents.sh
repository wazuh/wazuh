#!/usr/bin/env bash
# verify_agents.sh — parseable verification that the containerised agents enrolled and connected to
# the local manager. One line per check, "PASS|FAIL|SKIP  <n>. <container>: <check> (got: …)", then
#   # summary: executed=N passed=N failed=N skipped=N
#   # manifest: <path>
# Exit status is 0 iff failed=0.
#
# Evidence written under --out (never a key, a password or a token):
#   client.keys.txt        "id name ip" columns of the manager's etc/client.keys (the key column is dropped)
#   global-agents.txt      id, name, register_ip, connection_status, version, last_keepalive from global.db
#   api-agents.json        GET /agents (with --api)
#   <container>.log        docker logs tail per agent
#   manager-enroll.log     enrollment-related lines of the manager log (window since --start-mark)
#   agents-manifest.md     the table the evidence package reads
#
# What proves what:
#   4.x — authd on 1515 logs the enrollment at debug level only, so the proof is the key in
#         client.keys + connection_status=active in global.db + "Valid key received" and
#         "(4102): Connected to the server" in the agent log.
#   5.x — the token bootstrap: "Token bootstrap: enrollment succeeded" in the agent log,
#         etc/certs/root-ca.pem created and etc/enrollment_token unlinked inside the container, and
#         "Enrollment token '<id>' consumed by agent '<name>'" (authd) in the manager log.
set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

usage() {
  cat <<EOF
Usage: sudo $0 [--expect N] [--wait 120] [--out DIR] [--api] [--home DIR] [--compose FILE]
               [--services a,b] [--start-mark FILE] [-h|--help]

  --expect N        number of agents that must end up active (default: every container of the compose project)
  --wait SEC        how long to wait for connection_status=active before judging (default 120)
  --out DIR         evidence directory (default \$TMPDIR/wazuh-e2e-evidence/<timestamp>/agents)
  --api             also list the agents through the server API (wazuh:wazuh on the installed port)
  --home DIR        installed manager (default /var/wazuh-manager, or WAZUH_MANAGER_HOME)
  --compose FILE    compose file (default $SCRIPT_DIR/docker-compose.yml)
  --services a,b    only these compose services (default: all)
  --start-mark FILE byte offset of logs/wazuh-manager.log to start the log window from (default: last 3000 lines)
EOF
}

HOME_DIR="${WAZUH_MANAGER_HOME:-/var/wazuh-manager}"
EXPECT=""; WAIT=120; OUT=""; API=0; COMPOSE="$SCRIPT_DIR/docker-compose.yml"; SERVICES=""; MARK=""
while [ $# -gt 0 ]; do
  case "$1" in
    --expect) EXPECT=$2; shift 2 ;;
    --wait) WAIT=$2; shift 2 ;;
    --out) OUT=$2; shift 2 ;;
    --api) API=1; shift ;;
    --home) HOME_DIR=$2; shift 2 ;;
    --compose) COMPOSE=$2; shift 2 ;;
    --services) SERVICES=$2; shift 2 ;;
    --start-mark) MARK=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

die() { echo "ERROR: $*" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || die "run as root (client.keys, global.db and the manager log are not world-readable)"
command -v docker >/dev/null 2>&1 || die "docker not found"
[ -f "$COMPOSE" ] || die "compose file not found: $COMPOSE"
KEYS="$HOME_DIR/etc/client.keys"; GDB="$HOME_DIR/queue/db/global.db"; LOGF="$HOME_DIR/logs/wazuh-manager.log"
[ -f "$GDB" ] || die "no global.db at $GDB (is the manager installed and started?)"

OUT="${OUT:-${TMPDIR:-/tmp}/wazuh-e2e-evidence/$(date -u +%Y%m%dT%H%M%SZ)/agents}"
mkdir -p "$OUT"
REP="$OUT/verify-agents.log"; TSV="$OUT/checks.tsv"
: > "$REP"; : > "$TSV"
ran=0; ok=0; ko=0; sk=0
say()   { echo "$*" | tee -a "$REP"; }
check() { # check <id> <container> <name> <expected> <got>
  ran=$((ran + 1))
  if [ "$4" = "$5" ]; then ok=$((ok + 1)); say "PASS  $1. $2: $3 (got: $5)"; printf '%s\t%s\t%s\tPASS\t%s\n' "$1" "$2" "$3" "$5" >> "$TSV"
  else ko=$((ko + 1)); say "FAIL  $1. $2: $3 (expected: $4, got: $5)"; printf '%s\t%s\t%s\tFAIL\texpected %s, got %s\n' "$1" "$2" "$3" "$4" "$5" >> "$TSV"; fi
}
skip()  { sk=$((sk + 1)); say "SKIP  $1. $2: $3 ($4)"; printf '%s\t%s\t%s\tSKIP\t%s\n' "$1" "$2" "$3" "$4" >> "$TSV"; }
now()   { date -u +%Y-%m-%dT%H:%M:%SZ; }
gdb()   { python3 - "$GDB" "$1" <<'PY'
import sqlite3, sys
c = sqlite3.connect('file:%s?mode=ro' % sys.argv[1], uri=True)
for row in c.execute(sys.argv[2]):
    print('\t'.join('' if v is None else str(v) for v in row))
PY
}

say "# verify_agents.sh — $(now) — manager=$HOME_DIR compose=$COMPOSE"

# --- containers of the compose project (NDJSON or array, depending on the compose version)
mapfile -t ROWS < <(docker compose -f "$COMPOSE" ps -a --format json 2>/dev/null | python3 -c '
import json, sys
raw = sys.stdin.read().strip()
items = []
if raw:
    try:
        d = json.loads(raw); items = d if isinstance(d, list) else [d]
    except json.JSONDecodeError:
        items = [json.loads(l) for l in raw.splitlines() if l.strip()]
for i in items:
    print("%s\t%s\t%s" % (i.get("Name",""), i.get("Service",""), i.get("State","")))')
declare -a CONTAINERS=() SVCS=() STATES=() NAMES=() FLAVOURS=() VERSIONS=()
for row in "${ROWS[@]}"; do
  IFS=$'\t' read -r cname svc state <<<"$row"
  if [ -n "$SERVICES" ] && ! grep -qx "$svc" <<<"$(tr ',' '\n' <<<"$SERVICES")"; then continue; fi
  CONTAINERS+=("$cname"); SVCS+=("$svc"); STATES+=("$state")
  aname=$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$cname" 2>/dev/null | sed -n 's/^AGENT_NAME=//p' | head -1)
  NAMES+=("${aname:-$cname}")
  if [ "$state" = running ]; then
    if docker exec "$cname" test -x /var/ossec/bin/agent-auth 2>/dev/null; then FLAVOURS+=(4.x); else FLAVOURS+=(5.x); fi
    VERSIONS+=("$(docker exec "$cname" /var/ossec/bin/wazuh-control info 2>/dev/null | sed -n 's/^WAZUH_VERSION="\(.*\)"/\1/p' | head -1)")
  else
    FLAVOURS+=("?"); VERSIONS+=("")
  fi
done
N=${#CONTAINERS[@]}
EXPECT="${EXPECT:-$N}"
say "# containers: $N (expected active: $EXPECT)"
[ "$N" -gt 0 ] || { check 0 project "containers found" ">0" 0; say "# summary: executed=$ran passed=$ok failed=$ko skipped=$sk"; exit 1; }

# --- wait until every expected agent is active in global.db (keepalives take a while)
deadline=$((SECONDS + WAIT)); active=0
while :; do
  active=0
  for nm in "${NAMES[@]}"; do
    st=$(gdb "select connection_status from agent where name='$nm'" | head -1)
    [ "$st" = active ] && active=$((active + 1))
  done
  [ "$active" -ge "$EXPECT" ] && break
  [ "$SECONDS" -ge "$deadline" ] && break
  sleep 5
done
say "# active agents after $(( WAIT - (deadline - SECONDS) ))s: $active/$EXPECT"

# --- manager-side evidence (no key column ever leaves client.keys)
[ -f "$KEYS" ] && cut -d' ' -f1-3 "$KEYS" > "$OUT/client.keys.txt" || : > "$OUT/client.keys.txt"
{ echo -e "id\tname\tregister_ip\tconnection_status\tversion\tlast_keepalive"
  gdb "select id,name,register_ip,connection_status,version,last_keepalive from agent order by id"; } > "$OUT/global-agents.txt"
if [ -n "$MARK" ] && [ -f "$MARK" ] && [ -f "$LOGF" ]; then
  off=$(tr -dc '0-9' < "$MARK"); tail -c +$(( ${off:-0} + 1 )) "$LOGF"
else
  [ -f "$LOGF" ] && tail -n 3000 "$LOGF"
fi | grep -E "Enrollment token '.*' consumed by agent|Recorded credentials of agent|Invalid password|Duplicate name|Duplicate IP|enrollment-endpoint|Agent key generated|Enrollment token store loaded|agent-auth|New connection from|Agent '.*' connected" > "$OUT/manager-enroll.log" || true
if [ "$API" -eq 1 ]; then
  API_PORT=$(grep -E '^port:' "$HOME_DIR/api/configuration/api.yaml" 2>/dev/null | awk '{print $2}'); API_PORT="${API_PORT:-55000}"
  tok=$(curl -sk --max-time 15 -u wazuh:wazuh -X POST "https://127.0.0.1:${API_PORT}/security/user/authenticate" 2>/dev/null \
        | python3 -c 'import json,sys;print(json.load(sys.stdin)["data"]["token"])' 2>/dev/null || true)
  if [ -n "$tok" ]; then
    curl -sk --max-time 15 -H "Authorization: Bearer $tok" "https://127.0.0.1:${API_PORT}/agents?select=id,name,status,version&limit=500" > "$OUT/api-agents.json" 2>/dev/null || true
  else
    echo '{"error":"login failed"}' > "$OUT/api-agents.json"
  fi
fi

# --- per-container checks
declare -a ROWS_MD=()
for i in "${!CONTAINERS[@]}"; do
  n=$((i + 1)); c=${CONTAINERS[$i]}; nm=${NAMES[$i]}; fl=${FLAVOURS[$i]}; st=${STATES[$i]}
  docker logs --tail 400 "$c" > "$OUT/$c.log" 2>&1 || true
  keyline=$(awk -v n="$nm" '$2==n {print $1" "$2; exit}' "$OUT/client.keys.txt")
  check "${n}a" "$c" "key in the manager's client.keys" "$nm" "$(awk '{print $2}' <<<"$keyline")"
  status=$(gdb "select connection_status from agent where name='$nm'" | head -1)
  check "${n}b" "$c" "global.db connection_status" active "${status:-absent}"
  if [ "$st" != running ]; then
    skip "${n}c" "$c" "agent log" "container state=$st"
    skip "${n}d" "$c" "trust anchor / token file" "container state=$st"
  else
    case "$fl" in
      4.x)
        got=""
        grep -q 'Valid key received' "$OUT/$c.log" && got="Valid key received"
        grep -q 'Connected to the server' "$OUT/$c.log" && got="${got:+$got + }(4102) Connected to the server"
        check "${n}c" "$c" "agent log (authd 1515, shared password)" "Valid key received + (4102) Connected to the server" "${got:-neither}"
        skip "${n}d" "$c" "trust anchor / token file" "4.x: no token bootstrap"
        ;;
      *)
        got=""
        grep -q 'Token bootstrap: enrollment succeeded' "$OUT/$c.log" && got="Token bootstrap: enrollment succeeded"
        check "${n}c" "$c" "agent log (token bootstrap over POST /enroll)" "Token bootstrap: enrollment succeeded" "${got:-absent}"
        ca=$(docker exec "$c" sh -c 'test -s /var/ossec/etc/certs/root-ca.pem && echo present || echo missing' 2>/dev/null)
        tf=$(docker exec "$c" sh -c 'test -e /var/ossec/etc/enrollment_token && echo present || echo removed' 2>/dev/null)
        check "${n}d" "$c" "root-ca.pem installed by the bootstrap and enrollment_token unlinked" "present/removed" "${ca:-?}/${tf:-?}"
        ;;
    esac
  fi
  if [ "$fl" = 4.x ]; then
    skip "${n}e" "$c" "manager log" "authd logs the 1515 enrollment at debug level only; proof = a+b"
  else
    ml=$(grep -oE "Enrollment token '[^']*' consumed by agent '$nm'" "$OUT/manager-enroll.log" | tail -1)
    check "${n}e" "$c" "manager log: token consumed by this agent" yes "$([ -n "$ml" ] && echo yes || echo no)"
  fi
  hint=$(grep -oE 'Invalid password|Duplicate name|refusing to enroll unverified|Enrollment request could not be sent|HTTP/[0-9.]+ (401|403|404|429|503)|Invalid endpoint|Deployment variables refused \[[A-Z_]+\]' "$OUT/$c.log" | sort -u | tr '\n' ';')
  [ -z "$hint" ] || say "      hints in $c.log: $hint"
  if [ "$fl" = 4.x ]; then mlcell='n/a (authd 1515 logs at debug level)'
  elif [ -n "$ml" ]; then mlcell="token $(sed -n "s/Enrollment token '\\([^']*\\)'.*/\\1/p" <<<"$ml") consumed"
  else mlcell='—'; fi
  ROWS_MD+=("| $c | $fl | ${VERSIONS[$i]:-?} | $nm | ${keyline%% *} | ${status:-absent} | $c.log | $mlcell |")
done

# --- API and metrics (informational unless --api)
if [ "$API" -eq 1 ]; then
  listed=$(python3 -c '
import json,sys
names=set(sys.argv[2:])
try:
    d=json.load(open(sys.argv[1])); items=d.get("data",{}).get("affected_items",[])
    print(sum(1 for a in items if a.get("name") in names and a.get("status")=="active"))
except Exception: print(0)' "$OUT/api-agents.json" "${NAMES[@]}")
  check "$((N + 1))" api "GET /agents lists the expected agents as active" "$EXPECT" "$listed"
fi
SOCK="$HOME_DIR/queue/sockets/remote-admin-http.sock"
if [ -S "$SOCK" ]; then
  served=$(curl -s --unix-socket "$SOCK" http://localhost/metrics 2>/dev/null | python3 -c '
import json,sys
d=json.load(sys.stdin); ms=d if isinstance(d,list) else d.get("metrics",[])
print(next((m["value"] for m in ms if m.get("name","").endswith("cacerts.served")), "?"))' 2>/dev/null || echo "?")
  say "      remoted.cacerts.served = $served (5.x bootstraps fetch the CA from GET /cacerts)"
fi

say "# summary: executed=$ran passed=$ok failed=$ko skipped=$sk"
{
  echo "# agent-env manifest — $(now)"
  echo "manager.home: $HOME_DIR   compose: $COMPOSE"
  echo "packages: $(ls -1 "$SCRIPT_DIR/pkgs" 2>/dev/null | grep -E '\.(deb|rpm)$' | sed "s|^|$(basename "$SCRIPT_DIR")/pkgs/|" | tr '\n' ' ')"
  echo "active: $active/$EXPECT after up to ${WAIT}s"
  echo
  echo "| container | flavour | version | agent name | id | global.db status | agent log | manager log |"
  echo "|---|---|---|---|---|---|---|---|"
  printf '%s\n' "${ROWS_MD[@]}"
  echo
  echo "| # | container | check | verdict | got / reason |"
  echo "|---|---|---|---|---|"
  awk -F'\t' '{ printf "| %s | %s | %s | %s | %s |\n", $1, $2, $3, $4, $5 }' "$TSV"
  echo
  echo "summary: executed=$ran passed=$ok failed=$ko skipped=$sk"
  echo "logs: verify-agents.log checks.tsv client.keys.txt global-agents.txt manager-enroll.log$([ "$API" -eq 1 ] && echo ' api-agents.json') $(printf '%s.log ' "${CONTAINERS[@]}")"
} > "$OUT/agents-manifest.md"
say "# manifest: $OUT/agents-manifest.md"
[ "$ko" -eq 0 ]
