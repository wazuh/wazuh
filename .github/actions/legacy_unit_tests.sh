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
    make -C src TARGET=${target} TEST=1 -j$(nproc)
}

build_wazuh_unit_tests() {
    local target=$1
    local gcov_path
    # gcov must match the active gcc. The workflow installs the wazuh-packaged GCC at /opt/gcc-14
    # (currently 14.3, version tag B43*); pin to its bundled gcov to avoid being shadowed by the
    # system's /usr/bin/gcov-14 (Ubuntu 24.04 ships GCC 14.2, version tag B42*).
    if [[ -x /opt/gcc-14/bin/gcov ]]; then
        gcov_path=/opt/gcc-14/bin/gcov
    else
        gcov_path=$(command -v gcov)
    fi
    echo "Building Wazuh Unit Tests for target: $target"
    mkdir -p "$GITHUB_WORKSPACE/src/unit_tests/build"
    cd "$GITHUB_WORKSPACE/src/unit_tests/build"
    if [[ $target == "agent" ]]; then
        cmake -DTARGET=${target} -DGCOV_PATH="${gcov_path}" ..
    elif [[ $target == "manager" ]]; then
        cmake -DTARGET=${target} -DGCOV_PATH="${gcov_path}" ..
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
    elif [[ $target == "manager" ]]; then
        ctest --output-on-failure  > "test_results.txt" || true
        make coverage > "coverage_results.txt" || true
    elif [[ $target == "winagent" ]]; then
        WINEARCH="win32" WINEPATH="/usr/i686-w64-mingw32/lib;/usr/lib/gcc/i686-w64-mingw32/13-posix;$(realpath $(pwd)/../..);$(realpath $(pwd)/../../build/bin)" ctest --output-on-failure > test_results.txt || true
    fi
}

format_display_test_results() {
    echo "Formatting and displaying test results"
    cd "$GITHUB_WORKSPACE/src/unit_tests/build"
    {
        echo -e "## Test Results\n\n### Tests\n\n|Test|Status|\n|---|:-:|"
        sed -En 's- *[[:digit:]]+/[[:digit:]]+ Test +#[[:digit:]]+: ([[:graph:]]+) \.+[ *]+([[:alpha:]]+) +.+-|\1|\2|-p' test_results.txt | sed 's/|Passed|/|🟢|/;s/|Failed|/|🔴|/'
    } | tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"
    if grep -q "FAILED" test_results.txt; then
        cat test_results.txt
        exit 1
    fi
}


format_display_test_coverage() {
    local target=$1
    if [[ $target == "winagent" ]]; then
        return 0
    fi

    echo "Formatting and displaying test coverage"
    cd "$GITHUB_WORKSPACE/src/unit_tests/build"

    if ! grep -q "Summary coverage rate:" coverage_results.txt; then
        echo "::warning::No coverage summary found in coverage_results.txt for target '${target}'"
        cat coverage_results.txt || true
        return 0
    fi

    local lines_pct
    lines_pct=$(sed -En 's/ +lines\.+: ([[:digit:]]+\.[[:digit:]]+%) .*/\1/p' coverage_results.txt | head -n1)

    {
        echo
        echo "### Coverage (${target})"
        echo
        echo "**Lines coverage:** ${lines_pct:-N/A}"
        echo
        echo "|Coverage type|Percentage|Result|"
        echo "|---|---|---|"
        # lcov 2.x emits the summary block twice (once from geninfo, once from the final lcov pass);
        # awk de-dupes while preserving order so the table doesn't show duplicate rows.
        sed -En 's/ +([[:alpha:]])([[:alpha:]]+)\.+: ([[:digit:]]+\.[[:digit:]]+%) \(([[:print:]]+)\)/|\U\1\L\2|\3|\4|/p' coverage_results.txt | awk '!seen[$0]++'
    } | tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"
}


main() {
    local target=$1

    if [[ -z $target ]]; then
        echo "Error: No target specified."
        exit 1
    fi

    if [[ $target != "agent" && $target != "winagent" && $target != "manager" ]]; then
        echo "Error: Invalid target '$target'. Expected 'agent', 'winagent' or 'manager'."
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
