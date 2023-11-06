#!/bin/bash

environment_directory=""
input_file_path=""

SCRIPT_DIR=$(dirname $(readlink -f $0))
WAZUH_DIR=$(realpath -s "$SCRIPT_DIR/../../../..")

while getopts "e:i:" opt; do
    case $opt in
        e) environment_directory="$OPTARG/environment" ;;
        i) input_file_path="$OPTARG" ;;
        \?) echo "Invalid option: -$OPTARG" >&2
            exit 1
            ;;
        :) echo "Option -$OPTARG requires an argument." >&2
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

run_test_health() {
    local engine_src_dir="$WAZUH_DIR/src/engine"
    local health_test_dir="$engine_src_dir/test/health_test"
    local command="python3 $health_test_dir/health_test.py $WAZUH_DIR $environment_directory $input_file_path"
    $command
}

main() {
    check_arguments
    check_config_file

    # Execute the binary with the argument "server start"
    local engine_src_dir="$WAZUH_DIR/src/engine"
    "$engine_src_dir/build/main" --config "$serv_conf_file" server -l error --api_timeout 100000 start &
    # Capture the process ID of the binary
    local binary_pid=$!
    # Wait for the server to start
    sleep 2

    run_test_health
    exit_code=$?
    echo "Exit code $exit_code"

    kill $binary_pid
    exit $exit_code
}

main
