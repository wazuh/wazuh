#!/bin/bash

clean() {
    echo "Cleaning build and dependencies..."
    cd "$GITHUB_WORKSPACE"
    make clean-deps -C src
    rm -rf src/external/*
    rm -rf src/unit_tests/build
    make clean -C src
}

build_wazuh_test_flags() {
    local target=$1
    echo "Building Wazuh for target: $target"
    cd "$GITHUB_WORKSPACE"
    make deps -C src TARGET=${target} -j$(nproc)
    make -C src TARGET=${target} DEBUG=1 TEST=1 -j$(nproc)
}

build_wazuh_unit_tests() {
    local target=$1
    echo "Building Wazuh Unit Tests for target: $target"
    mkdir -p "$GITHUB_WORKSPACE/src/unit_tests/build"
    cd "$GITHUB_WORKSPACE/src/unit_tests/build"
    if [[ $target == "agent" ]]; then
        cmake -DTARGET=${target} ..
    elif [[ $target == "server" ]]; then
        cmake -DTARGET=${target} ..
    elif [[ $target == "winagent" ]]; then
        cmake -DTARGET=${target} -DCMAKE_TOOLCHAIN_FILE=../Toolchain-win32.cmake ..
    fi
    make -j$(nproc)
}

run_wazuh_unit_tests() {
    local target=$1
    echo "Running Wazuh Unit Tests for target: $target"
    cd "$GITHUB_WORKSPACE/src/unit_tests/build"
    if [[ $target == "agent" ]]; then
        ctest --output-on-failure  > "test_results.txt" || true
        make coverage > "coverage_results.txt" || true
    elif [[ $target == "server" ]]; then
        ctest --output-on-failure  > "test_results.txt" || true
        make coverage > "coverage_results.txt" || true
    elif [[ $target == "winagent" ]]; then
        WINEARCH="win32" WINEPATH="/usr/i686-w64-mingw32/lib;$(realpath $(pwd)/../..)" ctest --output-on-failure > test_results.txt || true
    fi
}

format_display_test_results() {
    echo "Formatting and displaying test results"
    cd "$GITHUB_WORKSPACE/src/unit_tests/build"
    echo -e "## Test Results\n\n### Tests\n\n|Test|Status|\n|---|:-:|"
    sed -En 's- *[[:digit:]]+/[[:digit:]]+ Test +#[[:digit:]]+: ([[:graph:]]+) \.+[ *]+([[:alpha:]]+) +.+-|\1|\2|-p' test_results.txt | sed 's/|Passed|/|🟢|/;s/|Failed|/|🔴|/'
    if grep -q "FAILED" test_results.txt; then
        cat test_results.txt
        exit 1
    fi
}


format_display_test_coverage() {
    if [[ $1 != "winagent" ]]; then
        echo "Formatting and displaying test coverage"
        cd "$GITHUB_WORKSPACE/src/unit_tests/build"
        if grep "Summary coverage rate:" coverage_results.txt > /dev/null; then
            echo -e "\n### Coverage\n\n|Coverage type|Percentage|Result|\n|---|---|---|"
            sed -En 's/ +([[:alpha:]])([[:alpha:]]+)\.+: ([[:digit:]]+\.[[:digit:]]+%) \(([[:print:]]+)\)/|\U\1\L\2|\3|\4|/p' coverage_results.txt
        fi
    fi
}


main() {
    local target=$1

    if [[ -z $target ]]; then
        echo "Error: No target specified."
        exit 1
    fi

    if [[ $target != "agent" && $target != "winagent" && $target != "server" ]]; then
        echo "Error: Invalid target '$target'. Expected 'agent', 'winagent' or 'server'."
        exit 1
    fi

    if [[ -z "${GITHUB_WORKSPACE}" ]]; then
        GITHUB_WORKSPACE=$(git rev-parse --show-toplevel)
    fi

    echo "Starting process for target: $target"

    clean
    build_wazuh_test_flags $target
    build_wazuh_unit_tests $target
    run_wazuh_unit_tests $target
    format_display_test_results
    format_display_test_coverage $target
}
