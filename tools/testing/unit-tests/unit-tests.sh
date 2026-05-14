#!/bin/bash

set -euo pipefail

# Defaults
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(realpath "$SCRIPT_DIR/../../..")"
UNIT_TESTS_DIR="$SCRIPT_DIR"
IMAGE="ghcr.io/wazuh/unit-tests:latest"
JOBS="${THREADS:-1}"

# Usage
function usage() {
    cat <<EOF
Usage: $0 [--build-image] [--build] [--jobs N] [--help]

Options:
  --build-image   Build the Docker image (exits after)
  --build         Run unit tests directly in current project (no download)
  --results       Generate markdown results from existing result-* files
  --clean         Remove generated files (result-*.txt and *.log)
  --jobs N        Number of parallel jobs to use for build (default: 1, can use THREADS env var)
  --help          Show this help

No arguments: runs unit tests using Docker image and generates markdown results

Environment variables:
  THREADS         Number of parallel jobs (default: 1)
EOF
}

# Parse arguments
DO_BUILD_IMAGE=false
DO_BUILD=false
DO_RESULTS=false
DO_CLEAN=false
DO_DOCKER=false

if [[ $# -eq 0 ]]; then
    # Default mode: run through Docker
    DO_DOCKER=true
else
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --build-image) DO_BUILD_IMAGE=true ;;
            --build)       DO_BUILD=true ;;
            --results)     DO_RESULTS=true ;;
            --clean)       DO_CLEAN=true ;;
            --jobs)
                shift
                if [[ $# -eq 0 || ! "$1" =~ ^[0-9]+$ ]]; then
                    echo "Error: --jobs requires a numeric argument"
                    exit 1
                fi
                JOBS="$1"
                ;;
            --help) usage; exit 0 ;;
            *) echo "Unknown option: $1"; usage; exit 1 ;;
        esac
        shift
    done

    # If no specific action was requested, default to Docker mode
    if [[ "$DO_BUILD_IMAGE" == "false" && "$DO_BUILD" == "false" && "$DO_RESULTS" == "false" && "$DO_CLEAN" == "false" ]]; then
        DO_DOCKER=true
    fi
fi

# Update THREADS environment variable for consistency
export THREADS="$JOBS"

# Core functions
build() {
    local target="$1"
    >&2 echo "[*] Building $target => build-$target.log"
    {
        find external/* > /dev/null 2>&1 || make deps TARGET=$target
        make clean-internals
        make clean-windows
        make clean-test
        make TARGET=$target DEBUG=1 TEST=1 -j$JOBS
    } > build-$target.log 2>&1
}

cmocka-tests() {
    local target="$1"
    >&2 echo "[*] Running $target cmocka tests => cmocka-tests-$target.log"

    local toolchainopt=""
    if [ "$target" = "winagent" ]; then
        toolchainopt="-DCMAKE_TOOLCHAIN_FILE=../Toolchain-win32.cmake"
    fi

    {
        rm -rf unit_tests/build
        mkdir -p unit_tests/build
        cd unit_tests/build
        cmake -DTARGET=$target $toolchainopt ..
        make -j$JOBS
    } > cmocka-tests-$target.log 2>&1

    if [ "$target" = "winagent" ]; then
        WINEARCH="win32" WINEPATH="/usr/i686-w64-mingw32/lib;$(realpath $(pwd)/../..)" ctest || true
    else
        make coverage || true
    fi 2>> cmocka-tests-$target.log

    {
        cd ../..
        rm -r unit_tests/build
    } >&2
}

run-ctest() {
    >&2 echo "[*] Running ctest => ctest.log"
    ctest --test-dir build --output-on-failure 2> ctest.log || true
}

clean-build() {
    make clean-deps
    rm -rf external/*
    make clean
}

rtr() {
    local component="$1"
    python3 build.py -r $component || true
}

# Print functions (from core-unit-tests.sh)
print-ctest() {
    [ -n "$1" ]

    echo -e "## Unit tests\n\n|Test|Status|\n|---|:-:|"
    sed -En 's- *[[:digit:]]+/[[:digit:]]+ Test +#[[:digit:]]+: ([[:graph:]]+) \.+[ *]+([[:alpha:]]+) +.+-|\1|\2|-p' $1 | sed 's/|Passed|/|🟢|/;s/|Failed|/|🔴|/'
}

print-cmocka-tests() {
    [ -n "$1" ]
    [ -n "$2" ]

    echo -e "## $1\n\n### Tests\n\n|Test|Status|\n|---|:-:|"
    sed -En 's- *[[:digit:]]+/[[:digit:]]+ Test +#[[:digit:]]+: ([[:graph:]]+) \.+[ *]+([[:alpha:]]+) +.+-|\1|\2|-p' $2 | sed 's/|Passed|/|🟢|/;s/|Failed|/|🔴|/'

    if grep "Summary coverage rate:" $2 > /dev/null
    then
        echo -e "\n### Coverage\n\n|Coverage type|Percentage|Result|\n|---|---|---|"
        sed -En 's/ +([[:alpha:]])([[:alpha:]]+)\.+: ([[:digit:]]+\.[[:digit:]]+%) \(([[:print:]]+)\)/|\U\1\L\2|\3|\4|/p' $2
    fi
}

print-rtr() {
    [ -n "$1" ]
    [ -n "$2" ]

    echo -e "## $1\n\n### Tests\n\n|Test|Status|\n|---|:-:|"

    sed -En 's/\x1b\[[0-9;]*m//g;s/^ ?\[(Cppcheck): ([[:alpha:]]+)\]/|\1|\2|/p' $2 | sed 's/|PASSED|/|🟢|/;s/|FAILED|/|🔴|/'
    sed -En '/= Running Tests/,/= Running (Coverage|Valgrind)/p' $2 | sed -En 's/\x1b\[[0-9;]*m//g;s/^ ?\[([[:print:]]+): ([[:alpha:]]+)\]/|\1|\2|/p' | sed 's/|PASSED|/|🟢|/;s/|FAILED|/|🔴|/'

    echo -e "\n### Coverage\n\n|Coverage type|Percentage|Result|\n|---|---|---|"
    sed -En 's/\x1b\[[0-9;]*m//g;s/^ ?\[([[:alpha:]]+) Coverage ([[:print:]]+): ([[:alpha:]]+)\]/|\1|\2|\3|/p' $2 | sed 's/|PASSED|/|🟢|/;s/|FAILED|/|🔴|/'
}

generate-results() {
    # RTR components and titles
    declare -A components=( \
        [data_provider]=data_provider \
        [dbsync]=shared_modules/dbsync \
        [rsync]=shared_modules/rsync \
        [syscollector]=wazuh_modules/syscollector \
        [fim]=syscheckd \
    )

    declare -A rtr_titles=( \
        [data_provider]="Data provider" \
        [dbsync]="DBsync" \
        [rsync]="Rsync" \
        [syscollector]="Syscollector" \
        [fim]="File integrity monitoring" \
    )

    # Print RTR results
    for i in ${!components[@]}; do
        if [[ -f "result-$i.txt" ]]; then
            print-rtr "${rtr_titles[$i]}" result-$i.txt
            echo
        fi
    done

    # Print ctest results
    if [[ -f "result-ctest.txt" ]]; then
        print-ctest result-ctest.txt
        echo
    fi

    # Print cmocka test results
    declare -A cmocka_titles=( \
        [server]="Linux Manager cmocka tests" \
        [agent]="Linux agent cmocka tests" \
        [winagent]="Windows agent cmocka tests" \
    )

    for i in ${!cmocka_titles[@]}; do
        if [[ -f "result-cmocka-$i.txt" ]]; then
            print-cmocka-tests "${cmocka_titles[$i]}" result-cmocka-$i.txt
            echo
        fi
    done
}

# --build-image: build Docker image and exit
if $DO_BUILD_IMAGE; then
    >&2 echo "[*] Building Docker image..."
    docker build -t "$IMAGE" "$UNIT_TESTS_DIR"
    >&2 echo "[*] Image built successfully."
    exit 0
fi

# --clean: remove generated files
if $DO_CLEAN; then
    >&2 echo "[*] Cleaning generated files..."
    cd "$ROOT_DIR/src"
    rm -f result-*.txt *.log
    >&2 echo "[*] Cleanup completed."
    exit 0
fi

# --results: generate markdown from result files
if $DO_RESULTS; then
    >&2 echo "[*] Generating markdown results from result-* files..."
    cd "$ROOT_DIR/src"
    generate-results
    exit 0
fi

# --build: run unit tests directly in current project
if $DO_BUILD; then
    >&2 echo "[*] Running unit tests directly in current project (jobs=$JOBS)..."
    cd "$ROOT_DIR/src"

    # Execute the main test sequence
    clean-build > /dev/null 2>&1
    build server
    cmocka-tests server > result-cmocka-server.txt
    run-ctest > result-ctest.txt

    # RTR tests for components
    declare -A components=( \
        [data_provider]=data_provider \
        [dbsync]=shared_modules/dbsync \
        [rsync]=shared_modules/rsync \
        [syscollector]=wazuh_modules/syscollector\
        [fim]=syscheckd\
    )

    for i in ${!components[@]}; do
        >&2 echo "[*] Running ${components[$i]} RTR toolset => rtr-$i.log"
        rtr ${components[$i]} > result-$i.txt 2> rtr-$i.log
    done

    build agent
    cmocka-tests agent > result-cmocka-agent.txt

    # Clean build and build winagent
    {
        clean-build > /dev/null 2>&1
        build winagent
    }
    cmocka-tests winagent > result-cmocka-winagent.txt

    >&2 echo "[*] Unit tests completed successfully."
    exit 0
fi

# Default mode: run through Docker and generate results
if [[ "$DO_DOCKER" == "true" ]]; then
    >&2 echo "[*] Running unit tests through Docker (jobs=$JOBS)..."
    docker run --rm \
        -v "$ROOT_DIR:/src" \
        -w /src \
        -u "$(id -u):$(id -g)" \
        -e THREADS="$JOBS" \
        "$IMAGE" \
        tools/testing/unit-tests/unit-tests.sh --build

    >&2 echo "[*] Docker unit tests completed successfully."

    # Generate markdown results after Docker execution
    >&2 echo "[*] Generating markdown results..."
    cd "$ROOT_DIR/src"
    generate-results
fi
