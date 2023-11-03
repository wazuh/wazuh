#!/bin/bash

update_conf() {
    local serv_conf_file="$ENGINE_SRC_DIR/test/health_test/configuration_files/general.conf"
    cp $serv_conf_file $ENVIRONMENT_DIR/engine
    sed -i "s|github_workspace|$ENVIRONMENT_DIR|g" "$ENVIRONMENT_DIR/engine/general.conf"
}

create_dummy_integration() {
    local wazuh_core_test="$ENVIRONMENT_DIR/engine/wazuh-core-test"
    mkdir -p "$wazuh_core_test/decoders" "$wazuh_core_test/filters"
    echo "name: decoder/test-message/0" > "$wazuh_core_test/decoders/test-message.yml"
    echo "name: filter/allow-all/0" > "$wazuh_core_test/filters/allow-all.yml"
    cat <<- EOM > "$wazuh_core_test/manifest.yml"
name: integration/wazuh-core-test/0
decoders:
- decoder/test-message/0
EOM
}

main() {
    if [ $# -lt 1 ]; then
        echo "Usage: $0 <github_working_directory> [<engine_source_directory>]"
        exit 1
    fi

    local github_working_directory="$1"
    ENVIRONMENT_DIR="$github_working_directory/environment"
    ENGINE_SRC_DIR="$github_working_directory/src/engine"

    update_conf
    create_dummy_integration
}
main "$@"
