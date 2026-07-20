#!/usr/bin/env bash
set -euo pipefail
# ---------------------------------------------------------------------------
# orchestrate_real_agents.sh — coordinate a real-agent test from one place.
#
# Phases (run independently or combined via `full`):
#   prep   — push syscollector_inventory_count.sh to each VM, top up the
#            installed-package count to a target, stop the agent, and wipe
#            its local syscollector DB so the next start triggers a clean
#            first-sync.
#   start  — start every agent in parallel via SSH. With --sync-at, schedules
#            the start at a specific clock second on every VM (sub-second
#            simultaneity, assuming NTP-synced VMs and `at` installed).
#   resync — stop the agent on each VM, wipe its syscollector local + sync_protocol
#            DBs so the next scan emits the full inventory as inserts, then
#            restart all agents in parallel. Skips the slow top-up phase: use
#            this AFTER an initial `prep` whenever you want to re-trigger a
#            clean first-sync without re-installing packages or recreating
#            users.
#
#            With --wipe-indexer the script ALSO runs delete_by_query on
#            wazuh-states-inventory-* for each agent.name BEFORE restarting.
#            Why: agent's normal loop always declares Mode_ModuleDelta, so the
#            manager does NOT issue delete_by_query on its own (it only does so
#            on Mode_ModuleFull, which is gated by the 24h recovery interval).
#            Wiping the indexer manually guarantees every bulk upsert during
#            the next first-sync lands as a fresh document and no stale docs
#            survive from the previous run.
#   full   — prep, then start.
#
# Usage:
#   ./orchestrate_real_agents.sh prep   vm1 vm2 vm3 vm4
#   ./orchestrate_real_agents.sh start  vm1 vm2 vm3 vm4
#   ./orchestrate_real_agents.sh resync vm1 vm2 vm3 vm4               # agent-side only
#   ./orchestrate_real_agents.sh resync --wipe-indexer vm1 vm2 vm3 vm4 # truly fresh
#   ./orchestrate_real_agents.sh start  --sync-at "+30 seconds" vm1 vm2 vm3 vm4
#   ./orchestrate_real_agents.sh full   --target 2000 vm1 vm2 vm3 vm4
#
#   # With Vagrant VMs (different port + key per box):
#   vagrant ssh-config > /tmp/vagrant-hosts.conf
#   ./orchestrate_real_agents.sh full --ssh-config /tmp/vagrant-hosts.conf \
#       --user vagrant ubuntu22 ubuntu24 debian10 debian11
#
# Options:
#   --user USER          SSH user (default: root). Non-root implies --sudo.
#   --target N           Top-up target for the inventory count (default: 2000).
#   --sync-at WHEN       Pass to `date -d` to compute an HH:MM start time, then
#                        schedule via `at` on each VM. Sub-second simultaneity
#                        across VMs. Requires `at`/`atd` on each VM and synced
#                        clocks. Example: --sync-at "+1 minute".
#   --no-top-up          Skip the package top-up phase (only stop + wipe DB).
#   --no-wipe            Skip the DB wipe (don't force a first-sync).
#   --identity FILE      SSH identity file (passed to ssh -i).
#   --ssh-config FILE    Use FILE as the SSH config (passed to ssh -F). Easiest
#                        way to handle Vagrant: `vagrant ssh-config > file`.
#                        The config carries per-host User/Port/IdentityFile,
#                        so --user/--identity become unnecessary.
#   --sudo / --no-sudo   Force or skip the sudo prefix on remote commands.
#                        Default: auto (sudo when --user is not root).
#   --wipe-indexer       (resync only) Run delete_by_query on
#                        wazuh-states-inventory-* for each agent.name before
#                        restarting. Default off.
#   --indexer URL        Indexer base URL (default: https://127.0.0.1:9200).
#   --indexer-auth U:P   Basic auth for the indexer (default: admin:admin).
#   --agent-field FIELD  Indexer field used to match each VM (default:
#                        wazuh.agent.name — that's the actual nested path in
#                        wazuh-states-inventory-* docs). Use wazuh.agent.id if
#                        your VM hostnames don't match the registered name.
#
# Run this from your workstation, not the manager. Each VM only needs SSH
# access from you and to be a Debian-based Wazuh agent.
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

USER_NAME="root"
TARGET=2000
TOPUP_VIA="users"   # "users" = fast (useradd); "packages" = slow (apt -doc)
SYNC_AT=""
DO_TOPUP=true
DO_WIPE=true
SSH_IDENTITY=""
SSH_CONFIG=""
USE_SUDO="auto"   # auto | yes | no
WIPE_INDEXER=false
INDEXER_URL="https://127.0.0.1:9200"
INDEXER_AUTH="admin:admin"
AGENT_FIELD="wazuh.agent.name"

usage() {
    sed -n '/^# Usage:/,/^# ---/p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
}

# --- parse phase argument ---
if [[ $# -lt 1 ]]; then usage; fi
PHASE="$1"; shift
case "$PHASE" in
    prep|start|full|resync) ;;
    -h|--help) usage ;;
    *) echo "Unknown phase: $PHASE" >&2; usage ;;
esac

# --- parse options + positional hostnames ---
HOSTS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --user)        USER_NAME="$2"; shift 2 ;;
        --target)      TARGET="$2";    shift 2 ;;
        --via)         TOPUP_VIA="$2"; shift 2 ;;
        --sync-at)     SYNC_AT="$2";   shift 2 ;;
        --no-top-up)   DO_TOPUP=false; shift ;;
        --no-wipe)     DO_WIPE=false;  shift ;;
        --identity)    SSH_IDENTITY="-i $2"; shift 2 ;;
        --ssh-config)  SSH_CONFIG="-F $2"; shift 2 ;;
        --sudo)        USE_SUDO=yes;   shift ;;
        --no-sudo)     USE_SUDO=no;    shift ;;
        --wipe-indexer)   WIPE_INDEXER=true; shift ;;
        --indexer)        INDEXER_URL="$2";   shift 2 ;;
        --indexer-auth)   INDEXER_AUTH="$2";  shift 2 ;;
        --agent-field)    AGENT_FIELD="$2";   shift 2 ;;
        -h|--help)     usage ;;
        --)            shift; HOSTS+=("$@"); break ;;
        -*)            echo "Unknown option: $1" >&2; usage ;;
        *)             HOSTS+=("$1");  shift ;;
    esac
done

if [[ ${#HOSTS[@]} -eq 0 ]]; then
    echo "Error: no hostnames provided." >&2
    usage
fi

SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=10)
# If using an ssh-config (e.g. from `vagrant ssh-config`), let it handle
# StrictHostKeyChecking, User, Port and IdentityFile. Otherwise default to
# accept-new (lenient first-time, strict after).
if [[ -n "$SSH_CONFIG" ]]; then
    SSH_OPTS+=($SSH_CONFIG)
else
    SSH_OPTS+=(-o StrictHostKeyChecking=accept-new)
fi
[[ -n "$SSH_IDENTITY" ]] && SSH_OPTS+=($SSH_IDENTITY)

# Decide if remote commands need `sudo`. With ssh-config the per-host User
# (often `vagrant` or non-root) overrides our --user default, so by default
# we sudo unless explicitly told not to.
case "$USE_SUDO" in
    yes) SUDO=("sudo" "-n") ;;
    no)  SUDO=() ;;
    auto)
        if [[ -n "$SSH_CONFIG" ]] || [[ "$USER_NAME" != "root" ]]; then
            SUDO=("sudo" "-n")
        else
            SUDO=()
        fi
        ;;
esac
sudo_prefix() {
    if [[ ${#SUDO[@]} -gt 0 ]]; then
        printf '%s ' "${SUDO[@]}"
    fi
}

# If ssh-config is given, we just pass the host name; ssh will resolve User,
# Port, IdentityFile from the config block. Otherwise prepend USER@.
remote_target() {
    if [[ -n "$SSH_CONFIG" ]]; then
        printf '%s' "$1"
    else
        printf '%s@%s' "$USER_NAME" "$1"
    fi
}

ssh_run() {
    local host="$1"; shift
    ssh "${SSH_OPTS[@]}" "$(remote_target "$host")" "$@"
}

scp_to() {
    local host="$1" src="$2" dest="$3"
    scp "${SSH_OPTS[@]}" "$src" "$(remote_target "$host"):${dest}"
}

# ---------------------------------------------------------------------------
# Phase: prep
# ---------------------------------------------------------------------------
do_prep() {
    local local_script="$SCRIPT_DIR/syscollector_inventory_count.sh"
    if [[ "$DO_TOPUP" == true ]] && [[ ! -f "$local_script" ]]; then
        echo "Error: cannot find $local_script — needed for --target top-up." >&2
        exit 1
    fi

    echo "=== prep phase (target=$TARGET, top_up=$DO_TOPUP, wipe=$DO_WIPE) ==="
    local failed=()
    local ok=()
    for vm in "${HOSTS[@]}"; do
        echo
        echo "[$vm] preparing..."
        local SP; SP=$(sudo_prefix)
        # Wrap each VM's prep in a subshell + `|| true` so a failure on one
        # VM (e.g. EOL repos, top-up packages missing) does not abort the
        # rest of the loop. Each step's exit code is OR-ed into a flag.
        local rc=0
        if [[ "$DO_TOPUP" == true ]]; then
            scp_to "$vm" "$local_script" "/tmp/syscollector_inventory_count.sh" \
                || { echo "[$vm] scp failed"; rc=1; }
            if (( rc == 0 )); then
                ssh_run "$vm" "chmod +x /tmp/syscollector_inventory_count.sh && \
                               ${SP}/tmp/syscollector_inventory_count.sh \
                                   --top-up $TARGET --via $TOPUP_VIA" \
                    || { echo "[$vm] top-up failed (continuing anyway)"; rc=1; }
            fi
        fi
        echo "[$vm] stopping wazuh-agent..."
        ssh_run "$vm" "${SP}service wazuh-agent stop || ${SP}systemctl stop wazuh-agent || true" \
            || echo "[$vm] stop returned non-zero (probably agent not installed yet)"
        if [[ "$DO_WIPE" == true ]]; then
            echo "[$vm] wiping syscollector local DB..."
            ssh_run "$vm" "${SP}rm -f /var/ossec/queue/syscollector/db/local.db*" \
                || echo "[$vm] wipe failed (DB path missing?)"
        fi
        if (( rc == 0 )); then
            ok+=("$vm")
            echo "[$vm] ready."
        else
            failed+=("$vm")
            echo "[$vm] PREP HAD ERRORS — review output above."
        fi
    done
    echo
    echo "=== prep summary ==="
    echo "  OK     (${#ok[@]}):     ${ok[*]:-none}"
    echo "  FAILED (${#failed[@]}): ${failed[*]:-none}"
    if (( ${#failed[@]} > 0 )); then
        echo
        echo "  Hint: run the inventory script manually on a failed VM to see"
        echo "        the actual count, e.g.:"
        echo "          ssh -F <ssh-config> ${failed[0]} -- '/tmp/syscollector_inventory_count.sh'"
    fi
}

# ---------------------------------------------------------------------------
# Phase: start
# ---------------------------------------------------------------------------
do_start_parallel_ssh() {
    echo "=== start phase: parallel SSH (best-effort simultaneity) ==="
    local SP; SP=$(sudo_prefix)
    local pids=()
    for vm in "${HOSTS[@]}"; do
        (
            t0=$(date +%s.%N)
            ssh_run "$vm" "${SP}service wazuh-agent start || ${SP}systemctl start wazuh-agent" \
                && echo "[$vm] started (ssh round-trip: $(printf '%.2f' $(echo "$(date +%s.%N) - $t0" | bc)) s)" \
                || echo "[$vm] START FAILED" >&2
        ) &
        pids+=($!)
    done
    for pid in "${pids[@]}"; do wait "$pid" || true; done
    echo "=== all start commands returned ==="
}

do_start_scheduled() {
    # Compute target absolute time using local clock (we trust local NTP).
    local when_iso when_hhmm when_yyyymmdd
    when_iso=$(date -d "$SYNC_AT" --iso-8601=seconds 2>/dev/null) || {
        echo "Error: --sync-at value invalid: '$SYNC_AT'" >&2
        echo "Hint: use values like '+30 seconds', '+1 minute', or '14:30'." >&2
        exit 1
    }
    when_hhmm=$(date -d "$SYNC_AT" '+%H:%M')
    when_yyyymmdd=$(date -d "$SYNC_AT" '+%Y-%m-%d')

    echo "=== start phase: scheduled via at(1) at $when_iso ==="
    echo "    (requires 'at' installed and clocks synced via NTP on each VM)"
    echo

    local SP; SP=$(sudo_prefix)
    for vm in "${HOSTS[@]}"; do
        ssh_run "$vm" "echo '${SP}service wazuh-agent start || ${SP}systemctl start wazuh-agent' \
                       | ${SP}at -M $when_hhmm $when_yyyymmdd" 2>&1 \
            | sed "s/^/[$vm] /"
    done

    echo
    echo "Scheduled. Agents will start at $when_iso (sub-second across VMs)."
    echo "Run 'date' on each VM beforehand if you want to double-check clock sync."
}

do_start() {
    if [[ -n "$SYNC_AT" ]]; then
        do_start_scheduled
    else
        do_start_parallel_ssh
    fi
}

# ---------------------------------------------------------------------------
# Indexer helpers (used by resync --wipe-indexer)
#
# We match documents by AGENT_FIELD (default agent.name == VM hostname). If
# your VM hostnames don't match the registered agent.name, pass
# --agent-field agent.id and adjust your HOSTS args to be agent IDs instead.
# ---------------------------------------------------------------------------
indexer_snapshot_for_agent() {
    local agent_value="$1"
    curl -sk -u "$INDEXER_AUTH" -X POST \
        "$INDEXER_URL/wazuh-states-inventory-*/_search?size=0" \
        -H 'Content-Type: application/json' \
        -d "{\"query\":{\"term\":{\"${AGENT_FIELD}\":\"${agent_value}\"}},
              \"aggs\":{\"by_idx\":{\"terms\":{\"field\":\"_index\",\"size\":20}}}}" \
        2>/dev/null \
        | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
    bs = d.get("aggregations", {}).get("by_idx", {}).get("buckets", [])
    if not bs:
        print("(empty)")
    else:
        total = sum(b["doc_count"] for b in bs)
        parts = [b["key"].replace("wazuh-states-inventory-", "") + "=" + str(b["doc_count"]) for b in bs]
        print("total={}  ".format(total) + ", ".join(parts))
except Exception as e:
    print("snapshot parse error: {}".format(e))
'
}

indexer_delete_for_agent() {
    local agent_value="$1"
    curl -sk -u "$INDEXER_AUTH" -X POST \
        "$INDEXER_URL/wazuh-states-inventory-*/_delete_by_query?refresh=true&conflicts=proceed" \
        -H 'Content-Type: application/json' \
        -d "{\"query\":{\"term\":{\"${AGENT_FIELD}\":\"${agent_value}\"}}}" \
        2>/dev/null \
        | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
    deleted = d.get("deleted", "?")
    total   = d.get("total", "?")
    took    = d.get("took", "?")
    print("deleted={}  total={}  took={}ms".format(deleted, total, took))
except Exception as e:
    print("delete_by_query parse error: {}".format(e))
'
}

# ---------------------------------------------------------------------------
# Phase: resync — force a fresh first-sync on every VM.
#
# Stops the agent, wipes its syscollector DBs (DBSync local cache + sync_protocol
# persistent queues) so the next scan has no prior state to diff against, and
# restarts the agent.
#
# IMPORTANT: the agent's normal loop always uses Mode_ModuleDelta. The manager
# only issues delete_by_query on Mode_ModuleFull (gated by a 24h recovery
# interval). So after a local wipe, the next sync's bulk upserts will land on
# whatever stale docs already exist in the indexer for that agent. To get a
# truly fresh "everything inserted" state, pass --wipe-indexer.
#
# Stop+wipe is done serially (each ~1 s), restart is done in parallel SSH
# so the 4 first-syncs hit the manager within ~100-500 ms of each other.
# ---------------------------------------------------------------------------
do_resync() {
    echo "=== resync phase: stop + wipe + restart on ${#HOSTS[@]} agent(s) ==="
    if [[ "$WIPE_INDEXER" == true ]]; then
        echo "    + wiping indexer state per ${AGENT_FIELD} ($INDEXER_URL)"
    fi
    local SP; SP=$(sudo_prefix)

    # Step 1: stop + wipe (serial — fast and idempotent).
    for vm in "${HOSTS[@]}"; do
        echo
        echo "[$vm] stop + wipe..."
        ssh_run "$vm" "${SP}service wazuh-agent stop || ${SP}systemctl stop wazuh-agent || true" \
            || echo "[$vm] stop returned non-zero (agent not running?)"
        # Wipe DBSync local cache + both sync_protocol persistent queues
        # (syscollector and syscollector_vd). All three live under the same
        # queue/syscollector/db directory.
        ssh_run "$vm" "${SP}rm -f /var/ossec/queue/syscollector/db/local.db* \
                                  /var/ossec/queue/syscollector/db/syscollector_sync.db* \
                                  /var/ossec/queue/syscollector/db/syscollector_vd_sync.db*" \
            || echo "[$vm] wipe failed (DB path missing? agent maybe not installed)"

        if [[ "$WIPE_INDEXER" == true ]]; then
            echo -n "[$vm] indexer pre-snapshot:  "
            indexer_snapshot_for_agent "$vm"
            echo -n "[$vm] indexer delete_by_query: "
            indexer_delete_for_agent "$vm"
        fi
        echo "[$vm] ready to restart."
    done

    # Step 2: parallel start so all VMs kick off their first-sync ~simultaneously.
    echo
    do_start

    if [[ "$WIPE_INDEXER" == true ]]; then
        echo
        echo "Tip: re-snapshot once the first-syncs finish to confirm the inserts landed:"
        for vm in "${HOSTS[@]}"; do
            printf '  [%s] ' "$vm"
            # Avoid spamming the indexer right after restart — the user runs
            # this command manually when they're ready to compare.
            echo "curl -sk -u '$INDEXER_AUTH' '$INDEXER_URL/wazuh-states-inventory-*/_search?size=0&q=${AGENT_FIELD}:$vm' | python3 -m json.tool"
        done
    fi
}

# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------
case "$PHASE" in
    prep)   do_prep ;;
    start)  do_start ;;
    full)   do_prep; do_start ;;
    resync) do_resync ;;
esac
