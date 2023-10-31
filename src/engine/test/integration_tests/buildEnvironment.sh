#!/bin/bash
setup_directories() {
    local base_dir="$1"
    local src_dir="$2"
    echo "--- Folder creation ---"
    mkdir -p "$base_dir" "$base_dir/engine" "$base_dir/queue/sockets" "$base_dir/logs"
}

load_integrations() {
    local environment_dir="$1"
    local engine_src_dir="$2"

    echo "--- Loading ruleset & enabling wazuh environment  ---"
    local serv_conf_file="$engine_src_dir/test/integration_tests/configuration_files/general.conf"
    sed -i "s|github_workspace|$environment_dir|g" "$serv_conf_file"

    "$engine_src_dir/build/main" --config "$serv_conf_file" server -l error start &

    sleep 2

    # Capture the process ID of the binary
    local binary_pid=$!

    # Add filter for route
    "$engine_src_dir/build/main" catalog --api_socket $environment_dir/queue/sockets/engine-api -n system create filter < $engine_src_dir/ruleset/filters/allow-all.yml

    cd $engine_src_dir/ruleset
    engine-integration add --api-sock $environment_dir/queue/sockets/engine-api -n system wazuh-core/
    engine-integration add --api-sock $environment_dir/queue/sockets/engine-api -n wazuh integrations/syslog/
    engine-integration add --api-sock $environment_dir/queue/sockets/engine-api -n wazuh integrations/system/
    engine-integration add --api-sock $environment_dir/queue/sockets/engine-api -n wazuh integrations/windows/
    engine-integration add --api-sock $environment_dir/queue/sockets/engine-api -n wazuh integrations/apache-http/
    engine-integration add --api-sock $environment_dir/queue/sockets/engine-api -n wazuh integrations/suricata/

    "$engine_src_dir/build/main" policy --api_socket $environment_dir/queue/sockets/engine-api add -p policy/wazuh/0 -f
    "$engine_src_dir/build/main" policy --api_socket $environment_dir/queue/sockets/engine-api parent-set decoder/integrations/0
    "$engine_src_dir/build/main" policy --api_socket $environment_dir/queue/sockets/engine-api parent-set -n wazuh decoder/integrations/0
    "$engine_src_dir/build/main" policy --api_socket $environment_dir/queue/sockets/engine-api asset-add -n system integration/wazuh-core/0
    "$engine_src_dir/build/main" policy --api_socket $environment_dir/queue/sockets/engine-api asset-add -n wazuh integration/syslog/0
    "$engine_src_dir/build/main" policy --api_socket $environment_dir/queue/sockets/engine-api asset-add -n wazuh integration/system/0
    "$engine_src_dir/build/main" policy --api_socket $environment_dir/queue/sockets/engine-api asset-add -n wazuh integration/windows/0
    "$engine_src_dir/build/main" policy --api_socket $environment_dir/queue/sockets/engine-api asset-add -n wazuh integration/apache-http/0
    "$engine_src_dir/build/main" policy --api_socket $environment_dir/queue/sockets/engine-api asset-add -n wazuh integration/suricata/0

    "$engine_src_dir/build/main" router --api_socket $environment_dir/queue/sockets/engine-api add default filter/allow-all/0 255 policy/wazuh/0

    cd $engine_src_dir
    engine-test add -i windows -f eventchannel
    engine-test add -i syslog -f syslog -o /tmp/syslog.log

    kill $binary_pid
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
    load_integrations "$ENVIRONMENT_DIR" "$ENGINE_SRC_DIR"
}
main "$@"
