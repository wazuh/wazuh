#!/bin/bash

update_conf() {
    local serv_conf_file="$ENGINE_SRC_DIR/test/health_test/configuration_files/general.conf"
    cp $serv_conf_file $ENVIRONMENT_DIR/engine
    sed -i "s|github_workspace|$ENVIRONMENT_DIR|g" "$ENVIRONMENT_DIR/engine/general.conf"
}

load_integrations() {
    # Add filter for route
    "$ENGINE_SRC_DIR/build/main" catalog --api_socket $ENVIRONMENT_DIR/queue/sockets/engine-api -n system create filter < $ENGINE_SRC_DIR/ruleset/filters/allow-all.yml

    wazuh_core_dir="$ENGINE_SRC_DIR/ruleset/wazuh-core"
    manifest="$ENVIRONMENT_DIR/engine/wazuh-core/manifest.yml"
    cp -r $wazuh_core_dir $ENVIRONMENT_DIR/engine

    # Check if the file exists
    if [ -f "$manifest" ]; then
        # Remove the "outputs" node from the manifest.yml file
        sed -i '/^outputs:/,/^$/d' "$manifest"
        echo "The 'outputs' node has been removed from the $manifest file."
    else
        echo "The file $manifest does not exist."
    fi

    cd $ENVIRONMENT_DIR/engine

    engine-integration add --api-sock $ENVIRONMENT_DIR/queue/sockets/engine-api -n system wazuh-core/

    cd $ENGINE_SRC_DIR/ruleset
    engine-integration add --api-sock $ENVIRONMENT_DIR/queue/sockets/engine-api -n wazuh integrations/syslog/
    engine-integration add --api-sock $ENVIRONMENT_DIR/queue/sockets/engine-api -n wazuh integrations/system/
    engine-integration add --api-sock $ENVIRONMENT_DIR/queue/sockets/engine-api -n wazuh integrations/windows/
    engine-integration add --api-sock $ENVIRONMENT_DIR/queue/sockets/engine-api -n wazuh integrations/apache-http/
    engine-integration add --api-sock $ENVIRONMENT_DIR/queue/sockets/engine-api -n wazuh integrations/suricata/
}

load_policies() {
    "$ENGINE_SRC_DIR/build/main" policy --api_socket $ENVIRONMENT_DIR/queue/sockets/engine-api add -p policy/wazuh/0 -f
    "$ENGINE_SRC_DIR/build/main" policy --api_socket $ENVIRONMENT_DIR/queue/sockets/engine-api parent-set decoder/integrations/0
    "$ENGINE_SRC_DIR/build/main" policy --api_socket $ENVIRONMENT_DIR/queue/sockets/engine-api parent-set -n wazuh decoder/integrations/0
    "$ENGINE_SRC_DIR/build/main" policy --api_socket $ENVIRONMENT_DIR/queue/sockets/engine-api asset-add -n system integration/wazuh-core/0
    "$ENGINE_SRC_DIR/build/main" policy --api_socket $ENVIRONMENT_DIR/queue/sockets/engine-api asset-add -n wazuh integration/syslog/0
    "$ENGINE_SRC_DIR/build/main" policy --api_socket $ENVIRONMENT_DIR/queue/sockets/engine-api asset-add -n wazuh integration/system/0
    "$ENGINE_SRC_DIR/build/main" policy --api_socket $ENVIRONMENT_DIR/queue/sockets/engine-api asset-add -n wazuh integration/windows/0
    "$ENGINE_SRC_DIR/build/main" policy --api_socket $ENVIRONMENT_DIR/queue/sockets/engine-api asset-add -n wazuh integration/apache-http/0
    "$ENGINE_SRC_DIR/build/main" policy --api_socket $ENVIRONMENT_DIR/queue/sockets/engine-api asset-add -n wazuh integration/suricata/0

    "$ENGINE_SRC_DIR/build/main" router --api_socket $ENVIRONMENT_DIR/queue/sockets/engine-api add default filter/allow-all/0 255 policy/wazuh/0
}

main() {
    if [ $# -lt 1 ]; then
        echo "Usage: $0 <github_working_directory> [<engine_source_directory>]"
        exit 1
    fi

    local github_working_directory="$1"
    ENGINE_SRC_DIR="$github_working_directory/src/engine"
    ENVIRONMENT_DIR="$github_working_directory/environment"

    update_conf

    # Run the command to start the server
    "$ENGINE_SRC_DIR/build/main" --config "$ENVIRONMENT_DIR/engine/general.conf" server -l error start &
    sleep 2

    # Capture the process ID of the binary
    local binary_pid=$!

    load_integrations
    load_policies

    # Kill the process at this point if necessary
    kill $binary_pid
}
main "$@"
