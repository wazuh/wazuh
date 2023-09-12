#!/bin/bash
setup_directories() {
    local base_dir="$1"
    local src_dir="$2"
    echo "--- Folder creation ---"
    mkdir -p "$base_dir" "$base_dir/engine" "$base_dir/queue/sockets" "$base_dir/logs"
    local ruleset_dir="$src_dir/ruleset/wazuh-core-test"
    mkdir -p "$ruleset_dir/decoders" "$ruleset_dir/filters"
    echo "name: decoder/test-message/0" > "$ruleset_dir/decoders/test-message.yml"
    echo "name: filter/allow-all/0" > "$ruleset_dir/filters/allow-all.yml"
    cat <<- EOM > "$ruleset_dir/manifest.yml"
name: integration/wazuh-core-test/0
decoders:
  - decoder/test-message/0
filters:
  - filter/allow-all/0
EOM
}

setup_engine() {
    local src_dir="$1"
    local engine_dir="$2"
    echo "--- Setting up the engine ---"
    mkdir -p "$engine_dir/store/schema" "$engine_dir/etc/kvdb"
    local schemas=("wazuh-logpar-types" "wazuh-asset" "wazuh-policy" "engine-schema")
    for schema in "${schemas[@]}"; do
        mkdir -p "$engine_dir/store/schema/$schema"
        cp "$src_dir/ruleset/schemas/$schema.json" "$engine_dir/store/schema/$schema/0"
    done
}

main() {
    if [ $# -lt 1 ]; then
        echo "Usage: $0 <github_working_directory> [<engine_source_directory>]"
        exit 1
    fi
    GITHUB_WORKING_DIRECTORY="$1"
    ENGINE_SRC_DIR="${2:-$GITHUB_WORKING_DIRECTORY/src/engine}"
    ENVIRONMENT_DIR="$GITHUB_WORKING_DIRECTORY/environment"
    ENGINE_DIR="$ENVIRONMENT_DIR/engine"
    setup_directories "$ENVIRONMENT_DIR" "$ENGINE_SRC_DIR"
    setup_engine "$ENGINE_SRC_DIR" "$ENGINE_DIR"
}
main "$@"
