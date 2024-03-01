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

check_arguments() {
    if [ -z "$environment_directory" ]; then
        echo "environment_directory is optional. For default is wazuh directory. Usage: $0 -e <environment_directory>"
    fi
}

check_config_file() {
    if [ -z "$environment_directory" ]; then
        environment_directory="$WAZUH_DIR/environment"
        serv_conf_file="$environment_directory/engine/general.conf"
    else
        environment_directory=$(echo "$environment_directory" | sed 's|//|/|g')
        serv_conf_file="$(realpath -m "$environment_directory/engine/general.conf")"
    fi

    if [ ! -f "$serv_conf_file" ]; then
        echo "Error: Configuration file $serv_conf_file not found."
        exit 1
    fi
}

run_behave_tests() {
    local integration_tests_dir="$1"
    local exit_code=0
    for features_dir in $(find "$integration_tests_dir" -type d -name "features"); do
        local steps_dir=$(dirname "$features_dir")/steps
        if [ -d "$steps_dir" ]; then
            echo "Running Behave in $features_dir"
            behave "$features_dir" --tags ~exclude || exit_code=1
        fi
    done
    echo "Exit code $exit_code"
    return $exit_code
}

main() {
    check_arguments
    check_config_file

    local engine_src_dir="$WAZUH_DIR/src/engine"
    local integration_tests_dir="$engine_src_dir/test/integration_tests"

    ENGINE_DIR=$engine_src_dir ENV_DIR=$environment_directory WAZUH_DIR=$(realpath -s "$SCRIPT_DIR/../../../..") CONF_FILE=$serv_conf_file run_behave_tests "$integration_tests_dir"
    exit_code=$?
    echo "Exit code $exit_code"

    exit $exit_code
}
main "$@"
