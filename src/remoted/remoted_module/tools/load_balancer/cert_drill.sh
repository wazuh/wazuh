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
# Usage: ./cert_drill.sh <name> <cert.pem> <key.pem>
#        ./cert_drill.sh restore
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
NODE=wazuh-worker2
CA="$HERE/certs/root-ca.pem"
N=12

install_cert() {
    local cert="$1" key="$2"
    docker cp "$cert" "$NODE:/tmp/leaf.pem" >/dev/null
    docker cp "$key"  "$NODE:/tmp/leaf-key.pem" >/dev/null
    docker exec "$NODE" sh -c '
        install -o wazuh-manager -g wazuh-manager -m 640 /tmp/leaf.pem     /var/wazuh-manager/etc/certs/remoted.pem &&
        install -o wazuh-manager -g wazuh-manager -m 640 /tmp/leaf-key.pem /var/wazuh-manager/etc/certs/remoted-key.pem &&
        rm -f /tmp/leaf.pem /tmp/leaf-key.pem' >/dev/null
    docker exec "$NODE" /var/wazuh-manager/bin/wazuh-manager-control restart >/dev/null 2>&1
    local waited=0
    until docker exec "$NODE" ss -ltn 2>/dev/null | grep -q ':1517'; do
        sleep 2; waited=$((waited+2)); [[ $waited -gt 120 ]] && { echo "  !! $NODE never came back"; return 1; }
    done
    return 0
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
    probe "direct to worker2"   wazuh-worker2    41519
}

if [[ "${1:-}" == "restore" ]]; then
    echo "==> restoring worker2's own leaf"
    install_cert "$HERE/certs/wazuh-worker2/node.pem" "$HERE/certs/wazuh-worker2/node-key.pem" || exit 1
    echo "==> after restore"; run_all; tls_metrics
    exit 0
fi

NAME="${1:?name}"; CERT="${2:?cert}"; KEY="${3:?key}"
echo "=============================================================="
echo "DRILL: $NAME  (installed on $NODE only)"
echo "=============================================================="
install_cert "$CERT" "$KEY" || exit 1
echo "-- worker2 TLS metrics --"; tls_metrics
echo "-- $N requests per front end --"; run_all
