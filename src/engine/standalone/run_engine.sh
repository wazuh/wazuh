#!/usr/bin/env bash
OLD_PWD="$(pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

DATA_PATH="$SCRIPT_DIR/data"
SOCKET_PATH="$SCRIPT_DIR/sockets"
LOG_PATH="$SCRIPT_DIR/logs"

export WAZUH_TZDB_PATH="${DATA_PATH}/tzdb"
export WAZUH_ENGINE_STANDALONE="true"
export WAZUH_STANDALONE_LOG_LEVEL="info"
export WAZUH_STORE_PATH="${DATA_PATH}/store"
export WAZUH_KVDB_PATH="${DATA_PATH}/kvdb"
export WAZUH_SERVER_API_SOCKET="${SOCKET_PATH}/engine-api.sock"
export WAZUH_SERVER_EVENT_SOCKET="${SOCKET_PATH}/engine-prod-event.sock"
export WAZUH_SERVER_ENRICHED_EVENTS_SOCKET="${SOCKET_PATH}/queue-http.sock"
export WAZUH_SKIP_USER_CHANGE="true"
export WAZUH_STREAMLOG_BASE_PATH="${LOG_PATH}"

# If not exist create directories
mkdir -p "$SOCKET_PATH" "$LOG_PATH"

"${SCRIPT_DIR}/bin/wazuh-engine" -f

# Clean stale PID files
find "${DATA_PATH}" -maxdepth 1 -name "*.pid" -exec rm -f {} \;

cd "$OLD_PWD"
