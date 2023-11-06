#!/bin/bash

environment_directory=""

SCRIPT_DIR=$(dirname $(readlink -f $0))
WAZUH_DIR=$(realpath -s "$SCRIPT_DIR/../../../..")

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

update_conf() {
    local serv_conf_file="$ENGINE_SRC_DIR/test/integration_tests/configuration_files/general.conf"
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
    if [ -z "$environment_directory" ]; then
        echo "environment_directory is optional. For default is wazuh directory. Usage: $0 -e <environment_directory>"
    fi

    ENGINE_SRC_DIR="$WAZUH_DIR/src/engine"
    ENVIRONMENT_DIR="${environment_directory:-$WAZUH_DIR/environment}"
    ENVIRONMENT_DIR=$(echo "$ENVIRONMENT_DIR" | sed 's|//|/|g')

    update_conf

    create_dummy_integration
}
main "$@"
