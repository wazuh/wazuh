#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# indexer_control.sh — Wrapper around wazuh-indexer lifecycle for benchmarks.
#
# Subcommands:
#   start             service wazuh-indexer start
#   stop              service wazuh-indexer stop
#   restart           stop + start
#   status            service wazuh-indexer status
#   init-security     /usr/share/wazuh-indexer/bin/indexer-security-init.sh
#   wait-healthy      poll https://localhost:9200 until cluster is up (or timeout)
#
# Notes:
#   * Requires root or sudo for service control.
#   * indexer-security-init.sh is the first-run bootstrap; it must NOT be re-run
#     on a working cluster. Use --force if you really want to.
#   * Used by run_benchmark.sh for the indexer_down scenario.
# ---------------------------------------------------------------------------
set -euo pipefail

INDEXER_HOST="${INDEXER_HOST:-localhost}"
INDEXER_PORT="${INDEXER_PORT:-9200}"
INDEXER_USER="${INDEXER_USER:-admin}"
INDEXER_PASS="${INDEXER_PASS:-admin}"
INIT_SCRIPT="/usr/share/wazuh-indexer/bin/indexer-security-init.sh"
WAIT_HEALTHY_TIMEOUT="${WAIT_HEALTHY_TIMEOUT:-120}"

usage() {
    cat <<EOF
Usage: $(basename "$0") <command> [options]

Commands:
  start                Start wazuh-indexer
  stop                 Stop wazuh-indexer (used for indexer_down scenario)
  restart              Stop then start
  status               Show service status
  init-security        Run indexer-security-init.sh (first-time bootstrap)
  wait-healthy [SEC]   Poll the indexer HTTPS endpoint until 'cluster_status != red'
                       Default timeout: ${WAIT_HEALTHY_TIMEOUT}s

Environment overrides:
  INDEXER_HOST           default: $INDEXER_HOST
  INDEXER_PORT           default: $INDEXER_PORT
  INDEXER_USER           default: $INDEXER_USER
  INDEXER_PASS           default: $INDEXER_PASS
  WAIT_HEALTHY_TIMEOUT   default: ${WAIT_HEALTHY_TIMEOUT}s

Examples:
  $(basename "$0") start
  $(basename "$0") wait-healthy 90
  $(basename "$0") init-security        # ONLY on first install
  $(basename "$0") stop                 # provoke indexer-down scenario
EOF
}

cmd_start() {
    echo "[indexer] starting wazuh-indexer..."
    service wazuh-indexer start
}

cmd_stop() {
    echo "[indexer] stopping wazuh-indexer..."
    service wazuh-indexer stop
}

cmd_status() {
    service wazuh-indexer status || true
}

cmd_init_security() {
    if [[ ! -x "$INIT_SCRIPT" ]]; then
        echo "[indexer] $INIT_SCRIPT not found or not executable" >&2
        exit 2
    fi
    echo "[indexer] running indexer-security-init.sh (first-time bootstrap)..."
    "$INIT_SCRIPT"
}

cmd_wait_healthy() {
    local timeout="${1:-$WAIT_HEALTHY_TIMEOUT}"
    local url="https://${INDEXER_HOST}:${INDEXER_PORT}/_cluster/health"
    local deadline=$(( $(date +%s) + timeout ))

    echo "[indexer] waiting for $url (timeout ${timeout}s)..."
    while (( $(date +%s) < deadline )); do
        local body
        if body=$(curl -sk -u "${INDEXER_USER}:${INDEXER_PASS}" --max-time 5 "$url" 2>/dev/null); then
            if echo "$body" | grep -qE '"status"[[:space:]]*:[[:space:]]*"(green|yellow)"'; then
                echo "[indexer] healthy: $body"
                return 0
            fi
        fi
        sleep 2
    done

    echo "[indexer] TIMEOUT waiting for cluster health" >&2
    return 1
}

main() {
    if [[ $# -lt 1 ]]; then
        usage
        exit 1
    fi
    local cmd="$1"
    shift || true
    case "$cmd" in
        start)         cmd_start          ;;
        stop)          cmd_stop           ;;
        restart)       cmd_stop; cmd_start ;;
        status)        cmd_status         ;;
        init-security) cmd_init_security  ;;
        wait-healthy)  cmd_wait_healthy "${1:-}" ;;
        -h|--help|help) usage              ;;
        *)
            echo "Unknown command: $cmd" >&2
            usage
            exit 1
            ;;
    esac
}

main "$@"
