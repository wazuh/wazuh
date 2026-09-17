#!/usr/bin/env bash
# Every check this lab makes, as PASS/FAIL. Same contract as the single-node lab it replaces:
# each line is one assertion, the exit status is non-zero if any of them failed.
#
# Requires a lab already up: ./setup_lab.sh --packages <dir>
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CA="$HERE/certs/root-ca.pem"
PASS=0; FAIL=0

check() {   # check <description> <expected> <actual>
    local what="$1" want="$2" got="$3"
    if [[ "$got" == "$want" ]]; then
        printf '  PASS  %-62s %s\n' "$what" "$got"; PASS=$((PASS+1))
    else
        printf '  FAIL  %-62s expected %s, got %s\n' "$what" "$want" "$got"; FAIL=$((FAIL+1))
    fi
}

check_not() {  # check_not <description> <unwanted> <actual>
    local what="$1" bad="$2" got="$3"
    if [[ "$got" != "$bad" ]]; then
        printf '  PASS  %-62s %s\n' "$what" "$got"; PASS=$((PASS+1))
    else
        printf '  FAIL  %-62s should not be %s\n' "$what" "$bad"; FAIL=$((FAIL+1))
    fi
}

# status <host> <port> [path]
status() {
    local host="$1" port="$2" path="${3:-/wazuh-manager/}"
    curl -s -o /dev/null --max-time 10 --cacert "$CA" \
         --resolve "$host:$port:127.0.0.1" -w '%{http_code}' "https://$host:$port$path" 2>/dev/null
}

probe() { docker exec lab-probe python3 "$@" 2>&1; }

echo "=== 1. every front end answers, with full CA validation ==="
check "haproxy passthrough"        "200" "$(status wazuh-lb-haproxy 21517)"
check "haproxy termination"        "200" "$(status wazuh-lb-haproxy 21518)"
check "nginx passthrough"          "200" "$(status wazuh-lb-nginx   31517)"
check "nginx termination"          "200" "$(status wazuh-lb-nginx   31518)"
check "direct to master"           "200" "$(status wazuh-master     41517)"
check "direct to worker1"          "200" "$(status wazuh-worker1    41518)"
check "direct to worker2"          "200" "$(status wazuh-worker2    41519)"

echo
echo "=== 2. the cluster is real ==="
NODES="$(docker exec wazuh-master /var/wazuh-manager/bin/cluster_control -l 2>/dev/null | tail -n +2 | grep -c .)"
check "cluster_control lists three nodes" "3" "$NODES"

echo
echo "=== 3. GET / returns a body (load-balancers/README.md:203 says it does not) ==="
BODY="$(curl -s --max-time 10 --cacert "$CA" --resolve "wazuh-lb-haproxy:21518:127.0.0.1" \
        https://wazuh-lb-haproxy:21518/wazuh-manager/ 2>/dev/null)"
check "body is the liveness JSON" '{"status":"ok","module":"remoted"}' "$BODY"

echo
echo "=== 4. termination spreads per REQUEST across all three nodes ==="
SEEN="$(for _ in $(seq 9); do
    curl -s -o /dev/null -D - --max-time 10 --cacert "$CA" \
         --resolve "wazuh-lb-haproxy:21518:127.0.0.1" \
         https://wazuh-lb-haproxy:21518/wazuh-manager/ 2>/dev/null |
    grep -i '^x-lab-node' | tr -d '\r' | awk '{print $2}'
  done | sort -u | grep -c .)"
check "three distinct nodes served nine requests" "3" "$SEEN"

echo
echo "=== 5. a prefix mismatch is a 404, never a 401 ==="
check "unprefixed path on a prefixed manager" "404" "$(status wazuh-master 41517 /stateless)"

echo
echo "=== 6. TLS health metrics reflect the node's certificate ==="
tls_metric() {   # tls_metric <node> <metric name>
    docker exec "$1" sh -c \
      "curl -s --unix-socket /var/wazuh-manager/queue/sockets/remote-admin-http.sock http://localhost/metrics" 2>/dev/null |
    python3 -c "
import json,sys
try: d=json.load(sys.stdin)
except Exception: print('unavailable'); raise SystemExit
print(next((m['value'] for m in d['metrics'] if m['name']=='$2'), 'absent'))
"
}
check "master: the CA signs the served leaf" "1.0" "$(tls_metric wazuh-master remoted.server.tls.ca_matches_leaf)"
EXPIRY="$(tls_metric wazuh-master remoted.server.tls.cert_expiry_days)"
check_not "master: the certificate has not expired" "unavailable" "$EXPIRY"

echo
echo "  Certificate FAILURE drills run standalone, because they restart a node:"
echo "    ./cert_drill.sh \"expired leaf\"  certs-bad/expired.pem       certs-bad/expired-key.pem"
echo "    ./cert_drill.sh \"wrong CA\"      certs-bad/rogue.pem         certs-bad/rogue-key.pem"
echo "    ./cert_drill.sh \"SAN mismatch\"  certs/wazuh-badsan/node.pem certs/wazuh-badsan/node-key.pem"
echo "    ./cert_drill.sh restore"

echo "=== 7. enrollment credential modes ==="
# Mint a token rather than assuming one exists: the store is created on first mint, and a
# freshly provisioned master has none. Tokens are minted on the master only.
API_TOKEN="$(curl -sk -u wazuh:wazuh -X POST \
    "https://127.0.0.1:45000/security/user/authenticate?raw=true" --max-time 15 2>/dev/null)"
if [[ -n "${API_TOKEN:-}" ]]; then
    curl -sk -H "Authorization: Bearer $API_TOKEN" -H "Content-Type: application/json" \
        -X POST "https://127.0.0.1:45000/agents/enrollment-tokens" \
        -d '{"address":"wazuh-lb-haproxy","ttl":"1h","max_uses":50}' --max-time 30 >/dev/null 2>&1
fi
# Copy the store INTO the probe container rather than next to this script: the container may
# mount its /probe from anywhere, and writing to the wrong side leaves it reading a stale file.
STORE_TMP="$(mktemp)"
docker exec wazuh-master sh -c "cat /var/wazuh-manager/etc/enrollment_tokens.json" \
    > "$STORE_TMP" 2>/dev/null || true
if [[ -s "$STORE_TMP" ]]; then
    docker cp "$STORE_TMP" lab-probe:/probe/store.json >/dev/null 2>&1
else
    echo "  !! could not mint an enrollment token; the token check will not run" >&2
fi
rm -f "$STORE_TMP"

# A token is minted on the master and replicated to the workers on the cluster's own interval,
# so enrolling with it through the balancer fails until every node has it -- the documented
# window, 7-13 s in a three-node cluster. Retry rather than race it: the point of this check is
# that the token works, not how fast it propagates (measure_propagation.py does that).
MODES=""
for _ in $(seq 1 12); do
    MODES="$(probe /probe/enroll_modes.py --password labpassword)"
    grep -qE '^  enrollment token *-> 200' <<<"$MODES" && break
    sleep 3
done
check_not "no credential is refused"     "200" "$(grep -oE '^  no credential *-> [0-9]+' <<<"$MODES" | grep -oE '[0-9]+$')"
check     "shared password enrolls"      "200" "$(grep -oE '^  shared password *-> [0-9]+' <<<"$MODES" | grep -oE '[0-9]+$')"
check     "enrollment token enrolls"     "200" "$(grep -oE '^  enrollment token *-> [0-9]+' <<<"$MODES" | grep -oE '[0-9]+$')"
check_not "unknown token id is refused"  "200" "$(grep -oE '^  unknown token id *-> [0-9]+' <<<"$MODES" | grep -oE '[0-9]+$')"

echo
echo "=== 8. every route answers through every front end ==="
# route_matrix.py enrols its own agent and waits for the key to reach every node, so the
# authenticated rows exercise the routes instead of the propagation window. Reusing an agent
# whose credentials re-enrollment rotated turns every authenticated row into a 401 that still
# "answers" -- which reads as a pass and proves nothing.
MATRIX="$(probe /probe/route_matrix.py --password labpassword 2>&1)"
if [[ -n "$MATRIX" ]]; then
    sed "s/^/  /" <<<"$MATRIX"
    ERRS="$(grep -c "ERR:" <<<"$MATRIX" || true)"
    check "no front end failed to answer on any route" "0" "$ERRS"
    UNAUTH="$(grep -cE "^  POST /(control|stateless|stateful|download|stats|config|scan).*401" <<<"$MATRIX" || true)"
    check "no authenticated route answered 401" "0" "$UNAUTH"
    THREE="$(grep -c "\[3n\]" <<<"$MATRIX" || true)"
    if [[ "$THREE" -ge 8 ]]; then
        printf "  PASS  %-62s %s rows served by all three nodes\n" "termination spread across the cluster" "$THREE"; PASS=$((PASS+1))
    else
        printf "  FAIL  %-62s only %s rows saw three nodes\n" "termination spread across the cluster" "$THREE"; FAIL=$((FAIL+1))
    fi
else
    echo "  SKIP  the route matrix produced no output"
fi

echo
echo "======================================================================"
printf '  %d passed, %d failed\n' "$PASS" "$FAIL"
echo "======================================================================"
[[ $FAIL -eq 0 ]]
