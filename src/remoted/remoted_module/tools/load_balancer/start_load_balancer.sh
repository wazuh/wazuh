#!/bin/bash
# Starts (or restarts) the lab's NGINX container with the chosen scenario configuration.
#
# The .conf files under nginx/ are only configuration CONTENT; they start nothing on their own.
# NGINX runs as a Docker container with one of them mounted over its own config file. That is
# all this script does:
#
#     docker run -d --name remoted-lb --network host \
#         -v <this directory>:/lab:ro \
#         -v <the chosen .conf>:/etc/nginx/nginx.conf:ro \
#         nginx:1.27
#
# The certificates are found because this directory is mounted at /lab, which is the path the
# .conf files refer to.
#
# Usage: ./start_load_balancer.sh <scenario> [port-to-wait-for]
#        ./start_load_balancer.sh                 # lists the available scenarios
#
# NOTE: both_topologies_bridge_network requires NGINX to have its OWN IP, so that scenario is
# started without --network host and with published ports instead.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CONTAINER=remoted-lb

if [[ $# -lt 1 ]]; then
    echo "usage: $0 <scenario> [port]"
    echo "available scenarios:"
    ls -1 "$HERE/nginx/" | sed 's/\.conf$//;s/^/  /'
    exit 1
fi

SCENARIO="$1"
WAIT_PORT="${2:-8443}"
CONFIG="$HERE/nginx/${SCENARIO}.conf"

if [[ ! -f "$CONFIG" ]]; then
    echo "no such scenario: $SCENARIO"
    echo "available:"
    ls -1 "$HERE/nginx/" | sed 's/\.conf$//;s/^/  /'
    exit 1
fi

docker rm -f "$CONTAINER" >/dev/null 2>&1 || true

# Free the ports: start_haproxy.sh serves the same :8443/:8444 from its own container, and two
# proxies fighting over one port means the measurement silently comes from whichever won. Without
# this, the second one to start just fails to bind and the FIRST one keeps answering -- so you
# measure the wrong proxy and cannot tell from the output.
if docker ps --format '{{.Names}}' | grep -qx remoted-lb-haproxy; then
    docker rm -f remoted-lb-haproxy >/dev/null 2>&1 || true
    echo "==> stopped the HAProxy container; it owns the same ports"
fi

if [[ "$SCENARIO" == *bridge_network* ]]; then
    # Own IP: needed for verification_mode=full, which compares the peer's address.
    echo "==> bridge network mode: NGINX gets its own container IP"
    docker run -d --name "$CONTAINER" -p 8443:8443 -p 8444:8444 \
        -v "$HERE:/lab:ro" \
        -v "$CONFIG:/etc/nginx/nginx.conf:ro" \
        nginx:1.27 >/dev/null
else
    docker run -d --name "$CONTAINER" --network host \
        -v "$HERE:/lab:ro" \
        -v "$CONFIG:/etc/nginx/nginx.conf:ro" \
        nginx:1.27 >/dev/null
fi

for _ in $(seq 1 20); do
    if ss -ltn 2>/dev/null | grep -q ":${WAIT_PORT}"; then
        # The port being open is NOT enough: the other proxy may own it (see above), in which case
        # the container is dead and we would report success while measuring something else.
        if ! docker ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
            echo "==> :${WAIT_PORT} is listening but the NGINX container is NOT running -- something"
            echo "    else owns that port. Logs:"
            docker logs "$CONTAINER" 2>&1 | grep -v docker-entrypoint | tail -10
            exit 1
        fi
        echo "==> NGINX up with '${SCENARIO}', listening on :${WAIT_PORT}"
        [[ "$SCENARIO" == *bridge_network* ]] && \
            echo "    container IP: $(docker inspect "$CONTAINER" \
                --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')"
        exit 0
    fi
    sleep 0.5
done

echo "==> NGINX did not start listening on :${WAIT_PORT}. Logs:"
docker logs "$CONTAINER" 2>&1 | grep -v docker-entrypoint | tail -10
exit 1
