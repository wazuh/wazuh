#!/bin/bash
# Starts (or restarts) HAProxy with the chosen scenario configuration -- the HAProxy twin of
# start_load_balancer.sh, on the SAME ports (:8443 termination, :8444 passthrough) and against the
# same nodes and PKI, so a measurement taken with one proxy is comparable to the other.
#
# The .cfg files under haproxy/ are only configuration CONTENT; they start nothing on their own.
# HAProxy runs as a Docker container with one of them mounted over its own config file:
#
#     docker run -d --name remoted-lb-haproxy --network host \
#         -v <this directory>:/lab:ro \
#         -v <the chosen .cfg>:/usr/local/etc/haproxy/haproxy.cfg:ro \
#         haproxy:2.9
#
# The certificates are found because this directory is mounted at /lab, the path the .cfg files
# refer to. HAProxy needs cert+key in ONE file: generate_test_certificates.sh writes the
# combined certs/*.pem for exactly this.
#
# Only one proxy can own :8443/:8444 at a time, so starting this STOPS the NGINX container (and
# vice versa -- start_load_balancer.sh stops this one). That is deliberate: two proxies fighting
# over the same port would make results depend on which won the race.
#
# Usage: ./start_haproxy.sh <scenario> [port-to-wait-for]
#        ./start_haproxy.sh                 # lists the available scenarios
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CONTAINER=remoted-lb-haproxy
NGINX_CONTAINER=remoted-lb
IMAGE=haproxy:2.9

if [[ $# -lt 1 ]]; then
    echo "usage: $0 <scenario> [port]"
    echo "available scenarios:"
    ls -1 "$HERE/haproxy/" | sed 's/\.cfg$//;s/^/  /'
    exit 1
fi

SCENARIO="$1"
WAIT_PORT="${2:-8443}"
CONFIG="$HERE/haproxy/${SCENARIO}.cfg"

if [[ ! -f "$CONFIG" ]]; then
    echo "no such scenario: $SCENARIO"
    echo "available:"
    ls -1 "$HERE/haproxy/" | sed 's/\.cfg$//;s/^/  /'
    exit 1
fi

# HAProxy reads cert+key from one file. Rebuild them if they are missing (an existing PKI
# generated before this script was added would not have them).
for name in load_balancer proxy_client; do
    pem="$HERE/certs/${name}.pem"
    if [[ ! -f "$pem" ]]; then
        if [[ -f "$HERE/certs/${name}.crt" && -f "$HERE/certs/${name}.key" ]]; then
            cat "$HERE/certs/${name}.crt" "$HERE/certs/${name}.key" > "$pem"
            chmod 644 "$pem"
            echo "==> built missing certs/${name}.pem from the existing certificate and key"
        else
            echo "!! certs/${name}.crt or .key missing -- run ./generate_test_certificates.sh first"
            exit 1
        fi
    fi
done

docker rm -f "$CONTAINER" >/dev/null 2>&1 || true

# Free the ports: the two proxies serve the same ones on purpose.
if docker ps --format '{{.Names}}' | grep -qx "$NGINX_CONTAINER"; then
    docker rm -f "$NGINX_CONTAINER" >/dev/null 2>&1 || true
    echo "==> stopped the NGINX container; it owns the same ports"
fi

# Validate the configuration before starting, so a syntax error is reported as such instead of
# surfacing later as "the port never opened".
if ! docker run --rm -v "$HERE:/lab:ro" -v "$CONFIG:/usr/local/etc/haproxy/haproxy.cfg:ro" \
        "$IMAGE" haproxy -c -f /usr/local/etc/haproxy/haproxy.cfg >/tmp/haproxy-check.$$ 2>&1; then
    echo "==> the configuration is invalid:"
    sed 's/^/    /' /tmp/haproxy-check.$$
    rm -f /tmp/haproxy-check.$$
    exit 1
fi
rm -f /tmp/haproxy-check.$$

docker run -d --name "$CONTAINER" --network host \
    -v "$HERE:/lab:ro" \
    -v "$CONFIG:/usr/local/etc/haproxy/haproxy.cfg:ro" \
    "$IMAGE" >/dev/null

for _ in $(seq 1 20); do
    if ss -ltn 2>/dev/null | grep -q ":${WAIT_PORT}"; then
        # The port being open is NOT enough: the NGINX container may still own it, in which case
        # this container is dead and we would report success while measuring the other proxy.
        if ! docker ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
            echo "==> :${WAIT_PORT} is listening but the HAProxy container is NOT running --"
            echo "    something else owns that port. Logs:"
            docker logs "$CONTAINER" 2>&1 | tail -10
            exit 1
        fi
        echo "==> HAProxy up with '${SCENARIO}', listening on :${WAIT_PORT}"
        exit 0
    fi
    sleep 0.5
done

echo "==> HAProxy did not start listening on :${WAIT_PORT}. Logs:"
docker logs "$CONTAINER" 2>&1 | tail -10
exit 1
