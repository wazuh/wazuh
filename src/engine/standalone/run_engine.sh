#!/usr/bin/env bash
OLD_PWD="$(pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

DATA_PATH="$SCRIPT_DIR/data"
SOCKET_PATH="$SCRIPT_DIR/sockets"
LOG_PATH="$SCRIPT_DIR/logs"

export WAZUH_TZDB_PATH="${DATA_PATH}/tzdb"
export WAZUH_GEO_DB_PATH="${DATA_PATH}/mmdb"
export WAZUH_ENGINE_STANDALONE="true"
export WAZUH_STANDALONE_LOG_LEVEL="info"
export WAZUH_STORE_PATH="${DATA_PATH}/store"
export WAZUH_OUTPUTS_PATH="${DATA_PATH}/outputs"
export WAZUH_KVDB_IOC_PATH="${DATA_PATH}/kvdb-ioc"
export WAZUH_CM_RULESET_PATH="${DATA_PATH}/content"
export WAZUH_SERVER_API_SOCKET="${SOCKET_PATH}/engine-api.sock"
export WAZUH_STREAMLOG_BASE_PATH="${LOG_PATH}"
export WAZUH_SERVER_ENABLE_EVENT_PROCESSING="false"
export WAZUH_SERVER_API_MAX_RESOURCE_PAYLOAD_SIZE="50000"
export WAZUH_SERVER_API_MAX_RESOURCE_KVDB_PAYLOAD_SIZE="100000"

# ┌──────────────────────────────────────────────────────────┬─────────────────────────────────────────────────┐
# │ Log4j2 Configuration                                     │ Environment Variable                            │
# ├──────────────────────────────────────────────────────────┼─────────────────────────────────────────────────┤
# │ <RollingFile fileName="...">                             │ WAZUH_STANDALONE_LOG_FILE_PATH                  │
# │                                                          │   (default: /var/log/wazuh-indexer/wazuh-      │
# │                                                          │    engine.log)                                  │
# ├──────────────────────────────────────────────────────────┼─────────────────────────────────────────────────┤
# │ <Policies>                                               │                                                 │
# │   <TimeBasedTriggeringPolicy                             │ WAZUH_STANDALONE_LOG_ROTATION_HOUR              │
# │     interval="1"                                         │   (default: 0 = midnight)                       │
# │     modulate="true"/>                                    │ WAZUH_STANDALONE_LOG_ROTATION_MINUTE            │
# │                                                          │   (default: 0)                                  │
# │   <SizeBasedTriggeringPolicy                             │ WAZUH_STANDALONE_LOG_MAX_FILE_SIZE              │
# │     size="128 MB"/>                                      │   (default: 134217728 = 128 MB)                 │
# │ </Policies>                                              │                                                 │
# ├──────────────────────────────────────────────────────────┼─────────────────────────────────────────────────┤
# │ <DefaultRolloverStrategy                                 │ WAZUH_STANDALONE_LOG_MAX_FILES                  │
# │   max="7"                                                │   (default: 7)                                  │
# │   fileIndex="max">                                       │                                                 │
# │   <Delete>                                               │                                                 │
# │     <IfAccumulatedFileSize                               │ WAZUH_STANDALONE_LOG_MAX_ACCUMULATED_SIZE       │
# │       exceeds="2 GB"/>                                   │   (default: 2147483648 = 2 GB)                  │
# │   </Delete>                                              │                                                 │
# │ </DefaultRolloverStrategy>                               │                                                 │
# └──────────────────────────────────────────────────────────┴─────────────────────────────────────────────────┘

# Auto-detect log file path based on environment
if [ -d "/var/log/wazuh-indexer" ]; then
    # Production environment: wazuh-indexer installed
    export WAZUH_STANDALONE_LOG_FILE_PATH="/var/log/wazuh-indexer/wazuh-engine.log"
else
    # Development/CI environment: use local logs directory
    export WAZUH_STANDALONE_LOG_FILE_PATH="${LOG_PATH}/wazuh-engine.log"
fi

export WAZUH_STANDALONE_LOG_ROTATION_ENABLED="true"
export WAZUH_STANDALONE_LOG_MAX_FILE_SIZE="134217728"        # 128 MB
export WAZUH_STANDALONE_LOG_ROTATION_HOUR="0"                # midnight
export WAZUH_STANDALONE_LOG_ROTATION_MINUTE="0"
export WAZUH_STANDALONE_LOG_MAX_FILES="7"
export WAZUH_STANDALONE_LOG_MAX_ACCUMULATED_SIZE="2147483648" # 2 GB

# If not exist create directories
mkdir -p "$SOCKET_PATH" "$LOG_PATH"
mkdir -p "${WAZUH_OUTPUTS_PATH}/default" # Base outputs path with default/ directory
mkdir -p "${WAZUH_CM_RULESET_PATH}" # For Ruleset store

exec "${SCRIPT_DIR}/bin/wazuh-engine" -f
