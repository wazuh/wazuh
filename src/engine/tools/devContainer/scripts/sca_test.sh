#!/usr/bin/env bash
set -Eeuo pipefail

# Run a repeatable "first enrollment + SCA scan on start" scenario for the
# 5.x Ubuntu test agent, including monitor capture and chart generation.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-${SCRIPT_DIR}/../e2e/agents/docker-compose.yml}"
AGENT_SERVICE="${AGENT_SERVICE:-agent_5x_ubuntu}"
AGENT_CONTAINER="${AGENT_CONTAINER:-wazuh-agent-5x-ubuntu}"
AGENT_NAME="${AGENT_NAME:-wazuh-agent-5x-ubuntu}"
MANAGER_SERVICE="${MANAGER_SERVICE:-wazuh-manager}"
API_URL="${WAZUH_API_URL:-https://localhost:55000}"
API_USER="${WAZUH_API_USER:-wazuh}"
API_PASS="${WAZUH_API_PASS:-wazuh}"
STARTUP_WAIT="${STARTUP_WAIT:-30}"
RUN_SECONDS="${RUN_SECONDS:-360}"
SCA_SYNC_INTERVAL="${SCA_SYNC_INTERVAL:-3m}"
CLEANUP_AFTER="${CLEANUP_AFTER:-yes}"
STOP_CONTAINER_AFTER_CLEAN="${STOP_CONTAINER_AFTER_CLEAN:-yes}"
CLEAN_MODE="${CLEAN_MODE:-volume}"
RESULTS_DIR="${RESULTS_DIR:-${SCRIPT_DIR}/result_sca_1agent_ubuntu}"
CHARTS_DIR="${CHARTS_DIR:-${RESULTS_DIR}/charts}"
MONITOR_INTERVAL="${MONITOR_INTERVAL:-1}"
MONITOR_PID=""

if [[ -n "${PYTHON_BIN:-}" ]]; then
  :
elif [[ -n "${TMP_PY_VENV:-}" && -x "${TMP_PY_VENV}/bin/python" ]]; then
  PYTHON_BIN="${TMP_PY_VENV}/bin/python"
elif [[ -x "/workspaces/Wazuh_5x/venv/bin/python" ]]; then
  PYTHON_BIN="/workspaces/Wazuh_5x/venv/bin/python"
else
  PYTHON_BIN="$(command -v python3 || true)"
fi

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Runs:
  1. Stop wazuh-manager so the agent cannot enroll during preparation
  2. Reset the agent as a first-run agent
  3. Start wazuh-manager
  4. Remove old manager records for ${AGENT_NAME}
  5. Start monitor.py in background
  6. Start ${AGENT_CONTAINER}
  7. Wait while SCA scan/enrollment happens
  8. Stop monitor and generate charts
  9. Optionally clean local/manager state again
  10. Stop wazuh-manager

Options:
  --duration SECONDS       Test window after agent start (default: ${RUN_SECONDS})
  --startup-wait SECONDS   Wait after manager start before agent start (default: ${STARTUP_WAIT})
  --interval VALUE         SCA synchronization interval to set (default: ${SCA_SYNC_INTERVAL})
  --results-dir PATH       Monitor output directory (default: ${RESULTS_DIR})
  --charts-dir PATH        Charts output directory (default: RESULTS_DIR/charts)
  --clean-mode MODE        volume or files (default: ${CLEAN_MODE})
  --agent-name NAME        Agent name to remove from manager (default: ${AGENT_NAME})
  --container NAME         Docker container name (default: ${AGENT_CONTAINER})
  --service NAME           Compose service name (default: ${AGENT_SERVICE})
  --compose-file PATH      Compose file (default: ${COMPOSE_FILE})
  --no-cleanup-after       Leave agent registered after the run
  -h, --help               Show this help

Environment:
  WAZUH_API_USER / WAZUH_API_PASS / WAZUH_API_URL
  STARTUP_WAIT / RUN_SECONDS / SCA_SYNC_INTERVAL / RESULTS_DIR / CLEAN_MODE / PYTHON_BIN
EOF
}

log() {
  printf '[sca-test] %s\n' "$*" >&2
}

die() {
  printf '[sca-test] ERROR: %s\n' "$*" >&2
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --duration)
      RUN_SECONDS="$2"
      shift 2
      ;;
    --startup-wait)
      STARTUP_WAIT="$2"
      shift 2
      ;;
    --interval)
      SCA_SYNC_INTERVAL="$2"
      shift 2
      ;;
    --results-dir)
      RESULTS_DIR="$2"
      CHARTS_DIR="${RESULTS_DIR}/charts"
      shift 2
      ;;
    --charts-dir)
      CHARTS_DIR="$2"
      shift 2
      ;;
    --clean-mode)
      CLEAN_MODE="$2"
      shift 2
      ;;
    --agent-name)
      AGENT_NAME="$2"
      shift 2
      ;;
    --container)
      AGENT_CONTAINER="$2"
      shift 2
      ;;
    --service)
      AGENT_SERVICE="$2"
      shift 2
      ;;
    --compose-file)
      COMPOSE_FILE="$2"
      shift 2
      ;;
    --no-cleanup-after)
      CLEANUP_AFTER="no"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "Unknown option: $1"
      ;;
  esac
done

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

compose() {
  docker compose -f "$COMPOSE_FILE" "$@"
}

container_running() {
  [[ "$(docker inspect -f '{{.State.Running}}' "$AGENT_CONTAINER" 2>/dev/null || true)" == "true" ]]
}

agent_image() {
  docker inspect -f '{{.Config.Image}}' "$AGENT_CONTAINER"
}

agent_sh() {
  local script="$1"

  if container_running; then
    docker exec "$AGENT_CONTAINER" sh -lc "$script"
    return
  fi

  local image
  image="$(agent_image)"
  docker run --rm --volumes-from "$AGENT_CONTAINER" --entrypoint sh "$image" -lc "$script"
}

stop_agent_processes() {
  if container_running; then
    log "Stopping Wazuh inside ${AGENT_CONTAINER}..."
    docker exec "$AGENT_CONTAINER" /var/ossec/bin/wazuh-control stop || true
  else
    log "${AGENT_CONTAINER} is stopped; local volume will be cleaned without running the agent entrypoint."
  fi
}

clean_local_agent_state() {
  log "Cleaning local agent first-run state and setting SCA sync interval=${SCA_SYNC_INTERVAL}..."
  agent_sh "
set -e
rm -f /var/ossec/etc/client.keys
rm -f /var/ossec/var/run/*.pid 2>/dev/null || true
mkdir -p /var/ossec/queue/rids
mkdir -p /var/ossec/queue/sca/db
mkdir -p /var/ossec/queue/syscollector/db
rm -f /var/ossec/queue/rids/* 2>/dev/null || true
rm -f /var/ossec/queue/sca/db/*.db* 2>/dev/null || true
rm -f /var/ossec/queue/syscollector/db/*.db* 2>/dev/null || true
rm -f /var/ossec/var/db/global.db* 2>/dev/null || true
rm -f /var/ossec/var/db/agents.db* 2>/dev/null || true
perl -0pi -e 's#(<sca>.*?<synchronization>.*?<interval>)[^<]*(</interval>)#\${1}${SCA_SYNC_INTERVAL}\${2}#s' /var/ossec/etc/ossec.conf
chown root:wazuh /var/ossec/etc/ossec.conf 2>/dev/null || chown root:root /var/ossec/etc/ossec.conf
chmod 640 /var/ossec/etc/ossec.conf
"
}

reset_agent_volume() {
  log "Resetting ${AGENT_SERVICE} volume through docker compose (cleanest first-run state)..."
  [[ -f "$COMPOSE_FILE" ]] || die "compose file not found: ${COMPOSE_FILE}"

  compose stop "$AGENT_SERVICE" >/dev/null 2>&1 || true
  compose rm -f "$AGENT_SERVICE" >/dev/null 2>&1 || true

  while IFS= read -r volume; do
    [[ -n "$volume" ]] || continue
    log "Removing Docker volume ${volume}..."
    docker volume rm "$volume" >/dev/null 2>&1 || true
  done < <(docker volume ls -q | grep -E "(^|_)${AGENT_SERVICE}_var$")

  compose create --no-build "$AGENT_SERVICE" >/dev/null
  clean_local_agent_state
  stop_agent_container
}

prepare_agent_first_run() {
  case "$CLEAN_MODE" in
    volume)
      reset_agent_volume
      ;;
    files)
      stop_agent_processes
      clean_local_agent_state
      stop_agent_container
      ;;
    *)
      die "invalid --clean-mode '${CLEAN_MODE}' (use: volume or files)"
      ;;
  esac
}

stop_agent_container() {
  if [[ "$STOP_CONTAINER_AFTER_CLEAN" == "yes" ]] && container_running; then
    log "Stopping Docker container ${AGENT_CONTAINER} so it cannot auto-enroll during manager cleanup..."
    docker stop "$AGENT_CONTAINER" >/dev/null
  fi
}

api_token() {
  curl -sS -k -X POST "${API_URL}/security/user/authenticate" \
    -u "${API_USER}:${API_PASS}" \
    | "$PYTHON_BIN" -c 'import json,sys; print(json.load(sys.stdin)["data"]["token"])'
}

wait_for_api() {
  log "Waiting for Wazuh API at ${API_URL}..."
  local attempt token
  for attempt in $(seq 1 60); do
    if token="$(api_token 2>/dev/null)" && [[ -n "$token" ]]; then
      printf '%s' "$token"
      return 0
    fi
    sleep 2
  done
  return 1
}

remove_manager_agent_records() {
  local token="$1"

  log "Removing manager records for agent name '${AGENT_NAME}'..."
  local agents_json agent_ids
  agents_json="$(curl -sS -k "${API_URL}/agents?limit=500&select=id,name&q=name~${AGENT_NAME}&offset=0" \
    -H "Authorization: Bearer ${token}")"

  agent_ids="$(printf '%s' "$agents_json" | "$PYTHON_BIN" -c '
import json, sys
d = json.load(sys.stdin)
target = sys.argv[1]
items = [a for a in d.get("data", {}).get("affected_items", []) if a.get("name") == target]
ids = [a["id"] for a in items if a.get("id") != "000"]
print(",".join(ids))
' "$AGENT_NAME")"

  if [[ -z "$agent_ids" ]]; then
    log "No old manager records found for ${AGENT_NAME}."
    return 0
  fi

  log "Deleting agent id(s): ${agent_ids}"
  curl -sS -k -X DELETE "${API_URL}/agents?agents_list=${agent_ids}&status=all&older_than=0s" \
    -H "Authorization: Bearer ${token}" \
    | "$PYTHON_BIN" -c '
import json, sys
d = json.load(sys.stdin).get("data", {})
print("Deleted:", d.get("total_affected_items", 0), "Failed:", d.get("total_failed_items", 0))
'
}

start_manager() {
  log "Starting ${MANAGER_SERVICE}..."
  service "$MANAGER_SERVICE" start
}

stop_manager() {
  log "Stopping ${MANAGER_SERVICE}..."
  service "$MANAGER_SERVICE" stop || true
}

start_agent_container() {
  log "Starting ${AGENT_CONTAINER}..."
  docker start "$AGENT_CONTAINER" >/dev/null
}

show_agent_key() {
  if container_running; then
    log "Current agent key:"
    docker exec "$AGENT_CONTAINER" sh -lc 'cat /var/ossec/etc/client.keys 2>/dev/null || true'
  fi
}

start_monitor() {
  log "Starting monitor.py with ${PYTHON_BIN} -> ${RESULTS_DIR}"
  mkdir -p "$RESULTS_DIR"
  "$PYTHON_BIN" "$SCRIPT_DIR/monitor.py" \
    --output-dir "$RESULTS_DIR" \
    --pidfile "${RESULTS_DIR}/monitor.pid" \
    --interval "$MONITOR_INTERVAL" &
  MONITOR_PID="$!"
  log "monitor.py pid=${MONITOR_PID}"
}

stop_monitor() {
  if [[ -n "$MONITOR_PID" ]] && kill -0 "$MONITOR_PID" 2>/dev/null; then
    log "Stopping monitor.py..."
    kill -TERM "$MONITOR_PID" 2>/dev/null || true
    wait "$MONITOR_PID" 2>/dev/null || true
  fi
}

generate_charts() {
  log "Generating charts with ${PYTHON_BIN} -> ${CHARTS_DIR}"
  if ! "$PYTHON_BIN" "$SCRIPT_DIR/monitor_graphics_generator.py" \
    --results "$RESULTS_DIR" \
    --output "$CHARTS_DIR"; then
    log "WARN: chart generation failed; results remain in ${RESULTS_DIR}"
  fi
}

main() {
  need_cmd docker
  need_cmd curl
  [[ -n "$PYTHON_BIN" && -x "$PYTHON_BIN" ]] || die "Python not found. Set PYTHON_BIN=/path/to/python"
  [[ "$CLEAN_MODE" == "volume" || "$CLEAN_MODE" == "files" ]] || die "invalid CLEAN_MODE=${CLEAN_MODE}"

  trap 'stop_monitor; stop_manager' EXIT

  log "Preparing clean first-enrollment state."
  stop_manager
  prepare_agent_first_run

  start_manager
  log "Sleeping ${STARTUP_WAIT}s for manager startup..."
  sleep "$STARTUP_WAIT"

  local token
  token="$(wait_for_api)" || die "Wazuh API did not become ready"
  remove_manager_agent_records "$token"

  start_monitor
  start_agent_container
  log "Running scenario for ${RUN_SECONDS}s..."
  sleep "$RUN_SECONDS"
  show_agent_key
  stop_monitor
  generate_charts

  if [[ "$CLEANUP_AFTER" == "yes" ]]; then
    log "Post-run cleanup enabled."
    stop_agent_processes
    clean_local_agent_state
    stop_agent_container
    remove_manager_agent_records "$token"
  else
    log "Post-run cleanup skipped (--no-cleanup-after)."
  fi

  stop_manager
  log "Done."
}

main
