#!/bin/bash

github_working_directory=""
environment_directory=""

while getopts ":d:e:" opt; do
    case $opt in
        d) github_working_directory="$OPTARG" ;;
        e) environment_directory="$OPTARG/environment" ;;
        \?) echo "Invalid option: -$OPTARG" >&2
            exit 1
            ;;
        :) echo "Option -$OPTARG requires an argument." >&2
            exit 1
            ;;
    esac
done

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
    if [ -z "$github_working_directory" ]; then
        echo "GitHub working directory is mandatory. Usage: $0 -d <github_working_directory> [-e <environment_directory>]"
        exit 1
    fi

    ENGINE_SRC_DIR="$github_working_directory/src/engine"
    ENVIRONMENT_DIR="${environment_directory:-$github_working_directory/environment}"
    ENGINE_DIR="$ENVIRONMENT_DIR/engine"

    setup_engine
}

main
