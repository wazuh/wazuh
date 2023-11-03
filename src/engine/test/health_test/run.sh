#!/bin/bash

check_arguments() {
    if [ $# -lt 1 ]; then
        echo "Usage: $0 <github_working_directory> [<engine_source_dir>] [<configuration_file] [<input_file_path]"
        exit 1
    fi
}

check_config_file() {
    local conf_file="$1"
    if [ ! -f "$conf_file" ]; then
        echo "Error: Configuration file $conf_file not found."
        exit 1
    fi
}

run_test_health() {
    local command="python3 $health_test_dir/health_test.py $github_working_dir $input_file_path"
    echo "Running test_health command: $command"
    $command
}

main() {
    check_arguments "$@"
    local github_working_dir="$1"
    local input_file_path="$2"
    local engine_src_dir="${3:-$github_working_dir/src/engine}"
    local conf_file="${4:-general.conf}"
    local health_test_dir="$engine_src_dir/test/health_test"
    local serv_conf_file="$github_working_dir/environment/engine/$conf_file"

    check_config_file "$serv_conf_file"

    # Execute the binary with the argument "server start"
    "$engine_src_dir/build/main" --config "$serv_conf_file" server -l error --api_timeout 100000 start &
    # Capture the process ID of the binary
    local binary_pid=$!
    # Wait for the server to start
    sleep 2

    run_test_health "$health_test_dir"
    exit_code=$?
    echo "Exit code $exit_code"

    kill $binary_pid
    exit $exit_code
}
main "$@"
