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
export WAZUH_OUTPUTS_PATH="${DATA_PATH}/outputs"
export WAZUH_CM_RULESET_PATH="${DATA_PATH}/content"
export WAZUH_SERVER_API_SOCKET="${SOCKET_PATH}/engine-api.sock"
export WAZUH_STREAMLOG_BASE_PATH="${LOG_PATH}"
export WAZUH_SERVER_ENABLE_EVENT_PROCESSING="false"

# If not exist create directories
mkdir -p "$SOCKET_PATH" "$LOG_PATH"
mkdir -p "${WAZUH_OUTPUTS_PATH}" # For cmsync output files
mkdir -p "${WAZUH_CM_RULESET_PATH}" # For Ruleset store

"${SCRIPT_DIR}/bin/wazuh-engine" -f

# Clean stale PID files
find "${DATA_PATH}" -maxdepth 1 -name "*.pid" -exec rm -f {} \;

cd "$OLD_PWD"
