#!/usr/bin/env bash
set -uo pipefail
# ---------------------------------------------------------------------------
# run_matrix.sh — Run the whole load matrix LOAD_REPORT.md is built from.
#
# This is the reproducible definition of the report: which scenarios, over which
# transport, under which label. Re-running it on another manager regenerates every
# figure (numbers will differ with the hardware; the shape of the matrix will not).
#
# Usage:
#   sudo ./prepare_manager.sh              # once: open, password-free enrollment
#   ./run_matrix.sh                        # 12 runs -> results_<label>/
#   ./make_report_tables.py > tables.md    # the report's tables, from the artifacts
#
# The cluster name is read from the local manager's config (the server answers 403
# to a foreign cluster). Pass --cluster only for a remote manager or to override it.
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Empty means "let run_benchmark.sh read it from the manager's own config"; pass
# --cluster only for a remote manager, or to override what the config says.
CLUSTER=""
CLUSTER_NODE=""
SOCKET="/var/wazuh-manager/queue/sockets/inventory-sync.sock"
SEED=4242
# Agent-mode runs wait for remoted to load the fleet's keys before measuring. On the
# reference manager that took ~100 s, so the budget is deliberately generous; a run
# that exhausts it fails loudly instead of measuring 401s.
ENROLL_SETTLE=240s
ONLY=""

usage() { grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --cluster)        CLUSTER="$2"; shift 2 ;;
        --cluster-node)   CLUSTER_NODE="$2"; shift 2 ;;
        --socket)         SOCKET="$2"; shift 2 ;;
        --seed)           SEED="$2"; shift 2 ;;
        --enroll-settle)  ENROLL_SETTLE="$2"; shift 2 ;;
        --only)           ONLY="$2"; shift 2 ;;   # run a single label
        -h|--help)        usage ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# label  mode   scenario
MATRIX=(
    # Relay cost: identical real payloads and seed over both transports; the
    # difference between each pair is remoted's relay and nothing else.
    "syscollector_uds    uds    scenarios/real_syscollector_debian.json"
    "syscollector_agent  agent  scenarios/real_syscollector_debian.json"
    "fim_uds             uds    scenarios/real_fim_first_sync_ubuntu.json"
    "fim_agent           agent  scenarios/real_fim_first_sync_ubuntu.json"
    # Vulnerability-detection scan lane (single worker by default)
    "vd_uds              uds    scenarios/real_vd_debian.json"
    # Capacity: unpaced. The real_* scenarios above are paced, so their
    # throughput is the scenario's, not the manager's.
    "burst_uds           uds    scenarios/mega_burst.json"
    "burst_agent         agent  scenarios/mega_burst.json"
    "ramp_503            uds    scenarios/contract_ramp_503.json"
    "session_storm       uds    scenarios/session_storm.json"
    # /control at fleet scale
    "control_storm       agent  scenarios/control_notify_storm.json"
    # Response contracts under pressure
    "contract_400        uds    scenarios/contract_invalid_bodies.json"
    "contract_413        uds    scenarios/contract_oversized_413.json"
)

failed=0
for entry in "${MATRIX[@]}"; do
    read -r label mode scenario <<<"$entry"
    [[ -n "$ONLY" && "$ONLY" != "$label" ]] && continue

    cluster_args=()
    [[ -n "$CLUSTER" ]] && cluster_args+=(--cluster "$CLUSTER")
    [[ -n "$CLUSTER_NODE" ]] && cluster_args+=(--cluster-node "$CLUSTER_NODE")

    extra=()
    if [[ "$mode" == "agent" ]]; then
        # Names are reused across runs, so clear the previous fleet first; this only
        # ever deletes bench-* agents.
        ./cleanup_agents.sh >/dev/null 2>&1 || true
        extra=(--enroll-settle "$ENROLL_SETTLE")
    fi

    echo "=== $label ($mode) — $(date -u +%H:%M:%S)"
    ./run_benchmark.sh --scenario "$scenario" --mode "$mode" --socket "$SOCKET" \
        --label "$label" --seed "$SEED" \
        "${cluster_args[@]}" "${extra[@]}" --no-charts >"/tmp/${label}.run.log" 2>&1
    rc=$?
    grep -E 'sessions:|stateless:|control:|latency ms|^run:' "/tmp/${label}.run.log" | sed 's/^/    /'
    if [[ $rc -ne 0 ]]; then
        echo "    !! $label exited $rc — the measurement is not trustworthy (see /tmp/${label}.run.log)"
        failed=$((failed + 1))
    fi
done

echo ""
echo "======================================================="
if [[ $failed -eq 0 ]]; then
    echo "  Matrix complete. Next: ./make_report_tables.py > tables.md"
else
    echo "  Matrix complete with $failed invalid run(s) — fix those before reporting numbers."
fi
echo "======================================================="
exit $((failed > 0))
