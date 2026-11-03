#!/usr/bin/env bash
# Certificate failure drills against ONE node (worker2), measured from every front end.
#
# The point is that the two TLS models fail in completely different places:
#
#   passthrough  the agent is the backend's TLS peer, so the AGENT sees the TLS error
#                and there is no HTTP status at all
#   termination  the BALANCER is the backend's TLS peer, so the balancer refuses the
#                backend and the agent gets an HTTP status it cannot attribute
#
# But the manager judges its own pair BEFORE it serves it. `wazuh-manager-control restart`
# runs the credential check ahead of the stop, and that check refuses a remoted pair that is
# expired or does not chain to certs/root-ca.pem ("Invalid credentials", -j error 22): the
# restart exits 1 without stopping anything, so the old daemons keep serving the PREVIOUS
# leaf from memory. A leaf whose SANs merely name the wrong host passes the check and is
# served. So each drill reports, in this order:
#
#   1. the restart's verdict (refused + the resolver's reason, or restarted);
#   2. the leaf the node actually serves on 1517, next to the one installed on disk;
#   3. the node's TLS metrics and twelve requests per front end, which measure THAT leaf.
#
# A refused file stays on disk, so the node's NEXT start is refused as well -- a container
# restart then leaves it down. DRILL_COLD=1 measures exactly that: stop, then start, so a
# refused pair leaves worker2 with no daemon and the front ends measure a dead backend.
# Always finish with `restore`.
#
# Usage: [DRILL_COLD=1] ./cert_drill.sh <name> <cert.pem> <key.pem>
#        ./cert_drill.sh restore
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
NODE=wazuh-worker2
DIRECT_PORT=41519
CA="$HERE/certs/root-ca.pem"
N=12
CONTROL=/var/wazuh-manager/bin/wazuh-manager-control
COLD="${DRILL_COLD:-0}"

# The manager's control script must never write into a pipe (the daemons inherit it), so its
# output goes to files inside the container and is read back afterwards: the -j verdict on
# stdout, the resolver's MISSING/INVALID/UNSAFE lines on stderr (also appended to the log).
control() {
    docker exec "$NODE" sh -c \
        "$CONTROL -j $1 > /tmp/drill-control.json 2> /tmp/drill-control.err; echo \$?" 2>/dev/null
}

# What the last control call said, and why.
refusal_reason() {
    echo "  verdict: $(docker exec "$NODE" cat /tmp/drill-control.json 2>/dev/null)"
    docker exec "$NODE" cat /tmp/drill-control.err 2>/dev/null |
        grep -E '^(MISSING|INVALID|UNSAFE) ' | head -5 | sed 's/^/  /'
}

# install_cert <cert> <key>: put the pair on disk, then restart (or stop + start under
# DRILL_COLD=1). Prints the outcome; returns 0 whether or not the manager accepted the pair,
# since a refusal is a result of the drill, not a failure of the script.
install_cert() {
    local cert="$1" key="$2" rc
    docker cp "$cert" "$NODE:/tmp/leaf.pem" >/dev/null
    docker cp "$key"  "$NODE:/tmp/leaf-key.pem" >/dev/null
    docker exec "$NODE" sh -c '
        install -o root -g wazuh-manager -m 640 /tmp/leaf.pem     /etc/wazuh-manager/certs/remoted.pem &&
        install -o root -g wazuh-manager -m 640 /tmp/leaf-key.pem /etc/wazuh-manager/certs/remoted-key.pem &&
        rm -f /tmp/leaf.pem /tmp/leaf-key.pem' >/dev/null

    if [[ "$COLD" == "1" ]]; then
        control stop >/dev/null
        rc=$(control start)
        echo "-- stop + start (DRILL_COLD=1): exit $rc"
    else
        rc=$(control restart)
        echo "-- restart: exit $rc"
    fi
    if [[ "$rc" != "0" ]]; then
        if [[ "$COLD" == "1" ]]; then
            echo "  REFUSED: worker2 has no daemon running now; the front ends measure a dead backend"
        else
            echo "  REFUSED before the stop: worker2 keeps serving its PREVIOUS leaf from memory"
        fi
        refusal_reason
        return 0
    fi
    echo "  accepted: worker2 restarted with the installed leaf"
    local waited=0
    until docker exec "$NODE" ss -ltn 2>/dev/null | grep -q ':1517'; do
        sleep 2; waited=$((waited+2)); [[ $waited -gt 120 ]] && { echo "  !! $NODE never came back"; return 1; }
    done
    return 0
}

# served_leaf: the certificate on disk versus the one worker2 hands out on 1517 right now.
# After a refused restart they differ, and only the second one is what the probes measure.
served_leaf() {
    local disk served
    disk=$(docker exec "$NODE" openssl x509 -in /etc/wazuh-manager/certs/remoted.pem -noout \
           -subject -issuer -enddate 2>/dev/null | tr '\n' ' ')
    served=$(openssl s_client -connect "127.0.0.1:$DIRECT_PORT" -servername "$NODE" </dev/null 2>/dev/null |
             openssl x509 -noout -subject -issuer -enddate 2>/dev/null | tr '\n' ' ')
    echo "  on disk: ${disk:-(unreadable)}"
    echo "  served:  ${served:-(nothing: no listener on $DIRECT_PORT)}"
}

# probe <label> <host> <port>: N requests, tallying HTTP status or the curl error class.
probe() {
    local label="$1" host="$2" port="$3" i out code
    declare -A tally=()
    for i in $(seq $N); do
        out=$(curl -s -o /dev/null --max-time 8 --cacert "$CA" \
              --resolve "$host:$port:127.0.0.1" -w '%{http_code}' \
              "https://$host:$port/wazuh-manager/" 2>&1)
        code=$?
        if [[ $code -ne 0 ]]; then out="curl($code)"; fi
        tally[$out]=$(( ${tally[$out]:-0} + 1 ))
    done
    printf '  %-24s' "$label"
    for k in "${!tally[@]}"; do printf ' %s×%s' "${tally[$k]}" "$k"; done
    echo
}

tls_metrics() {
    docker exec "$NODE" sh -c \
      "curl -s --unix-socket /var/wazuh-manager/queue/sockets/remote-admin-http.sock http://localhost/metrics" 2>/dev/null |
    python3 -c "
import json,sys
try: d=json.load(sys.stdin)
except Exception: print('  (metrics unavailable)'); raise SystemExit
for m in d['metrics']:
    if m['name'] in ('remoted.server.tls.cert_expiry_days','remoted.server.tls.ca_matches_leaf'):
        print('  %-44s %s' % (m['name'], m['value']))
"
}

run_all() {
    probe "haproxy passthrough" wazuh-lb-haproxy 21517
    probe "haproxy termination" wazuh-lb-haproxy 21518
    probe "nginx passthrough"   wazuh-lb-nginx   31517
    probe "nginx termination"   wazuh-lb-nginx   31518
    probe "direct to worker2"   wazuh-worker2    "$DIRECT_PORT"
}

if [[ "${1:-}" == "restore" ]]; then
    echo "==> restoring worker2's own leaf"
    install_cert "$HERE/certs/wazuh-worker2/node.pem" "$HERE/certs/wazuh-worker2/node-key.pem" || exit 1
    echo "-- leaf --"; served_leaf
    echo "==> after restore"; run_all; tls_metrics
    exit 0
fi

NAME="${1:?name}"; CERT="${2:?cert}"; KEY="${3:?key}"
echo "=============================================================="
echo "DRILL: $NAME  (installed on $NODE only)"
echo "=============================================================="
install_cert "$CERT" "$KEY" || exit 1
echo "-- leaf --"; served_leaf
echo "-- worker2 TLS metrics --"; tls_metrics
echo "-- $N requests per front end --"; run_all
