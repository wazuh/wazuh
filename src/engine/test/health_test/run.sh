#!/bin/bash

github_working_dir=""
environment_build_dir=""
input_file_path=""

while getopts ":d:e:i:" opt; do
    case $opt in
        d) github_working_dir="$OPTARG" ;;
        e) environment_build_dir="$OPTARG/environment" ;;
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
    if [ -z "$github_working_dir" ]; then
        echo "GitHub working directory is mandatory. Usage: $0 -d <github_working_directory> [-e <environment_build_dir>] [-i <input_file_path>]"
        exit 1
    fi
}

check_config_file() {
    if [ -z "$environment_build_dir" ]; then
        environment_build_dir="$github_working_dir/environment"
        serv_conf_file="$environment_build_dir/engine/general.conf"
    else
        environment_build_dir=$(echo "$environment_build_dir" | sed 's|//|/|g')
        serv_conf_file="$(realpath -m "$environment_build_dir/engine/general.conf")"
    fi

    if [ ! -f "$serv_conf_file" ]; then
        echo "Error: Configuration file $serv_conf_file not found."
        exit 1
    fi
}

run_test_health() {
    local engine_src_dir="$github_working_dir/src/engine"
    local health_test_dir="$engine_src_dir/test/health_test"
    local command="python3 $health_test_dir/health_test.py $github_working_dir $environment_build_dir $input_file_path"
    $command
}

main() {
    check_arguments
    check_config_file

    # Execute the binary with the argument "server start"
    local engine_src_dir="$github_working_dir/src/engine"
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
