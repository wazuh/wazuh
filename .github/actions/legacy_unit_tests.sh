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
        # winagent is cross-compiled with mingw 10.3; the matching gcov is the
        # cross tool, not the host's GCC 14.x. We pin to the -posix variant
        # because that's what `g++-mingw-w64-i686-posix` (the toolchain's
        # default in winagent.cmake) was built with.
        #
        # lcov 2.x detects the gcov version by parsing `<gcov> --version` with
        # a `[0-9.]+` regex. The mingw cross-gcov prints
        #   gcov (GCC) 10-posix YYYYMMDD
        # The `-posix` suffix breaks the regex, lcov silently falls back to
        # GCOV 4.2 format and can't parse the GCOV 10 .gcno files (every file
        # ends up as "no functions found"). We wrap the cross-gcov so
        # `--version` emits a parseable banner; all other invocations pass
        # through unchanged.
        local win_gcov_wrapper="${PWD}/winagent-gcov-wrapper.sh"
        cat > "${win_gcov_wrapper}" <<'EOF'
#!/bin/bash
if [[ "$1" == "-v" || "$1" == "--version" ]]; then
    echo "gcov (GCC) 10.3.0"
    echo "Copyright (C) 2020 Free Software Foundation, Inc."
    echo "This is free software; see the source for copying conditions."
    exit 0
fi
exec /usr/bin/i686-w64-mingw32-gcov-posix "$@"
EOF
        chmod +x "${win_gcov_wrapper}"
        cmake -DTARGET=${target} -DCMAKE_TOOLCHAIN_FILE=../Toolchain-win32.cmake \
              -DGCOV_PATH="${win_gcov_wrapper}" ..
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
        # Tests run via wine (CMAKE_CROSSCOMPILING_EMULATOR in Toolchain-win32.cmake).
        # libgcov writes .gcda alongside the .gcno using the absolute Linux paths
        # baked at build time; wine maps the host root through drive Z: so the
        # writes land back in the expected build-tree locations.
        #
        # `export` (not inline assignment) because `make coverage` invokes
        # `ctest` a second time inside add_custom_target(coverage) — without
        # the wine env those re-run binaries can't find their DLLs and every
        # test fails, leaving no .gcda for lcov to capture.
        export WINEARCH="win32"
        export WINEPATH="/usr/i686-w64-mingw32/lib;/usr/lib/gcc/i686-w64-mingw32/13-posix;$(realpath $(pwd)/../..);$(realpath $(pwd)/../../build/bin)"
        ctest --output-on-failure > test_results.txt || true
        # Capture coverage. lcov invokes ${GCOV_PATH} which we pinned to the
        # mingw cross-gcov wrapper at configure time so the .gcda format matches.
        make coverage > "coverage_results.txt" || true
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
