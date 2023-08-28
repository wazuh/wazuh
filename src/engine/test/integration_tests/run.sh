#!/bin/bash
check_arguments() {
    if [ $# -lt 1 ]; then
        echo "Usage: $0 <github_working_directory> [<config_file>]"
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

run_behave_tests() {
    local integration_tests_dir="$1"
    local exit_code=0
    for features_dir in $(find "$integration_tests_dir" -type d -name "features"); do
        local steps_dir=$(dirname "$features_dir")/steps
        if [ -d "$steps_dir" ]; then
            echo "Running Behave in $features_dir"
            behave "$features_dir" || exit_code=1
        fi
    done
    echo "Exit code $exit_code"
    return $exit_code
}

main() {
    check_arguments "$@"
    local github_working_dir="$1"
    local conf_file="${2:-general.conf}"
    local engine_src_dir="$github_working_dir/src/engine"
    local environment_dir="$github_working_dir/environment"
    local integration_tests_dir="$engine_src_dir/test/integration_tests"
    local serv_conf_file="$integration_tests_dir/configuration_files/$conf_file"
    check_config_file "$serv_conf_file"
    # Replace occurrences of /var/ossec with the new path
    sed -i "s|github_workspace|$environment_dir|g" "$serv_conf_file"
    # Execute the binary with the argument "server start"
    "$engine_src_dir/build/main" --config "$serv_conf_file" server -l trace start &
    # Capture the process ID of the binary
    local binary_pid=$!
    # Wait for the server to start
    sleep 2
    run_behave_tests "$integration_tests_dir"
    local behave_exit_code=$?
    # Terminate the binary process
    kill $binary_pid
    exit $behave_exit_code
}
main "$@"
