#!/bin/bash

setup_engine() {
    echo "--- Setting up the engine ---"
    mkdir -p "$ENGINE_DIR/store/schema" "$ENGINE_DIR/etc/kvdb"
    local schemas=("wazuh-logpar-types" "wazuh-asset" "wazuh-policy" "engine-schema")
    for schema in "${schemas[@]}"; do
        mkdir -p "$ENGINE_DIR/store/schema/$schema"
        cp "$ENGINE_SRC_DIR/ruleset/schemas/$schema.json" "$ENGINE_DIR/store/schema/$schema/0"
    done

    mkdir -p "$ENVIRONMENT_DIR" "$ENVIRONMENT_DIR/engine" "$ENVIRONMENT_DIR/queue/sockets" "$ENVIRONMENT_DIR/logs"
}

main() {
    if [ $# -lt 1 ]; then
        echo "Usage: $0 <github_working_directory> [<engine_source_directory>]"
        exit 1
    fi

    local github_working_directory="$1"
    ENVIRONMENT_DIR="$github_working_directory/environment"
    ENGINE_SRC_DIR="$github_working_directory/src/engine"
    ENGINE_DIR="$ENVIRONMENT_DIR/engine"

    setup_engine
}
main "$@"
