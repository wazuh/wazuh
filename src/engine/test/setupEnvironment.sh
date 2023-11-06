#!/bin/bash

environment_directory=""

SCRIPT_DIR=$(dirname $(readlink -f $0))
WAZUH_DIR=$(realpath -s "$SCRIPT_DIR/../../../")

while getopts "e:" opt; do
    case $opt in
        e)
            environment_directory="$OPTARG/environment"
            ;;
        \?)
            echo "Invalid option: -$OPTARG" >&2
            exit 1
            ;;
        :)
            echo "Option -$OPTARG requires an argument." >&2
            exit 1
            ;;
    esac
done

setup_engine() {
    mkdir -p "$ENGINE_DIR/store/schema" "$ENGINE_DIR/etc/kvdb"
    local schemas=("wazuh-logpar-types" "wazuh-asset" "wazuh-policy" "engine-schema")
    for schema in "${schemas[@]}"; do
        mkdir -p "$ENGINE_DIR/store/schema/$schema"
        cp "$ENGINE_SRC_DIR/ruleset/schemas/$schema.json" "$ENGINE_DIR/store/schema/$schema/0"
    done

    mkdir -p "$ENVIRONMENT_DIR" "$ENVIRONMENT_DIR/engine" "$ENVIRONMENT_DIR/queue/sockets" "$ENVIRONMENT_DIR/logs"
}

main() {
    if [ -z "$environment_directory" ]; then
        echo "environment_directory is optional. For default is wazuh directory. Usage: $0 -e <environment_directory>"
    fi

    ENGINE_SRC_DIR="$SCRIPT_DIR/../"
    ENVIRONMENT_DIR="${environment_directory:-$WAZUH_DIR/environment}"
    ENGINE_DIR="$ENVIRONMENT_DIR/engine"

    setup_engine
}

main
