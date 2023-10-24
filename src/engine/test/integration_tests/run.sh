#!/bin/bash
check_arguments() {
    if [ $# -lt 1 ]; then
        echo "Usage: $0 <github_working_directory> [<engine_source_dir>] [<configuration_file]"
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

run_test_health() {
    local command="python3 $integration_tests_dir/health_test.py $github_working_dir"
    echo "Running test_health command: $command"
    $command
}

main() {
    check_arguments "$@"
    local github_working_dir="$1"
    local test_type="$2"
    local engine_src_dir="${3:-$github_working_dir/src/engine}"
    local conf_file="${4:-general.conf}"
    local environment_dir="$github_working_dir/environment"
    local integration_tests_dir="$engine_src_dir/test/integration_tests"
    local serv_conf_file="$integration_tests_dir/configuration_files/$conf_file"
    check_config_file "$serv_conf_file"
    # Replace occurrences of /var/ossec with the new path
    sed -i "s|github_workspace|$environment_dir|g" "$serv_conf_file"
    # Execute the binary with the argument "server start"
    "$engine_src_dir/build/main" --config "$serv_conf_file" server -l error start &
    # Capture the process ID of the binary
    local binary_pid=$!
    # Wait for the server to start
    sleep 2
    if [ "$test_type" == "integration_test" ]; then
        ENGINE_DIR=$engine_src_dir ENV_DIR=$github_working_dir run_behave_tests "$integration_tests_dir"
        exit exit_code=$?
    elif [ "$test_type" == "health_test" ]; then
        run_test_health "$integration_tests_dir"
        exit_code=$?
    else
        echo "Invalid test type: $test_type"
        exit_code=1
    fi

    echo "Exit code $exit_code"
    kill $binary_pid
    exit $exit_code
}
main "$@"
