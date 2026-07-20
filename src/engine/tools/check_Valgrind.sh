#!/bin/bash

# Function to display help message
usage() {
    echo "Usage: $0 [options] [arguments]"
    echo
    echo "Options:"
    echo "  -h, --help          Show this help message"
    echo "  -e, --exclude DIRS  Colon-separated list of directories to exclude"
    echo "  -t, --test-dir DIR  Directory to search for tests (default: build directory)"
    echo "  -r, --regex PATTERN Optional regular expression to filter tests (default: no filtering)"
    echo "  -o, --output FILE   File to redirect output (default: ${SCRIPT_DIR}/valgrindReport.log)"
}

# Initialize variables
EXCLUDE_DIRS=""
TEST_DIR=""
REGEX_FILTER=""
OUTPUT_FILE=""

# Parse command-line options
while [[ "$1" == -* ]]; do
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
        -e|--exclude)
            EXCLUDE_DIRS=$2
            shift 2
            ;;
        -t|--test-dir)
            TEST_DIR=$2
            shift 2
            ;;
        -r|--regex)
            REGEX_FILTER=$2
            shift 2
            ;;
        -o|--output)
            OUTPUT_FILE=$2
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Set default values if not provided
SCRIPT_DIR=$(dirname $(readlink -f $0))
BUILD_DIR=$SCRIPT_DIR/../build
BUILD_SRC_DIR=$(realpath "${BUILD_DIR}/source")

# If no test directory is specified, use the default build directory
if [ -z "$TEST_DIR" ]; then
    TEST_DIR=$BUILD_DIR
fi

# If no output file is specified, use the default
if [ -z "$OUTPUT_FILE" ]; then
    OUTPUT_FILE="${SCRIPT_DIR}/valgrindReport.log"
fi

# Check if the directories exist
if [ ! -d "${BUILD_DIR}" ]; then
    echo "Build directory does not exist"
    exit 1
fi
if [ ! -d "${BUILD_SRC_DIR}" ]; then
    echo "Build source directory does not exist"
    exit 1
fi

# Function to check if a directory is in the exclude list
is_excluded() {
    local dir=$1
    local abs_dir=$(realpath "$dir")
    for excluded in ${EXCLUDE_DIRS//:/ }; do
        local abs_excluded=$(realpath "$excluded")
        if [[ "$abs_dir" == "$abs_excluded"* ]]; then
            return 0
        fi
    done
    return 1
}

# Get file lists
TEST_LIST=""
if [[ "$TEST_DIR" == "$BUILD_DIR" ]]; then
    # Search for test files with exclusion if using default directory
    while IFS= read -r dir; do
        if ! is_excluded "$dir" && [[ ! "$dir" == *source ]]; then
            # Search for files ending in _ctest or _utest
            files=$(find "$dir" \( -iname '*_ctest' -o -iname '*_utest' \) -type f)
            if [[ -n "$files" ]]; then
                TEST_LIST+="$files"$'\n'
            fi
        fi
    done < <(find "${BUILD_SRC_DIR}" -type d)
else
    TEST_LIST=$(find "${TEST_DIR}" \( -iname '*_ctest' -o -iname '*_utest' \) -type f)
fi

LIBS_LIST=$(find "${BUILD_SRC_DIR}" -iname '*.a' -type f)

# Split the list into an array
IFS=$'\n' read -d '' -r -a test_arr <<< "${TEST_LIST}"
IFS=$'\n' read -d '' -r -a lib_arr <<< "${LIBS_LIST}"

# Merge the arrays
bin_arr=("${test_arr[@]}" "${lib_arr[@]}")
bin_arr+=("${BUILD_DIR}/main")

for testAbs in "${bin_arr[@]}"
do
    relativePath=$(realpath --relative-to="${BUILD_DIR}" "${testAbs}")
    nm -an $testAbs | grep -q '__asan\|__tsan'
    if [ $? -eq 0 ]; then
        if [[ "$testAbs" == *test ]]; then
            echo "🟢 $relativePath"
        fi
    else
        if [[ "$relativePath" == *.a ]]; then
            echo "🔴 $relativePath failed, compile with asan"
            exit 1
        fi
    fi
done

# clear the Valgrind log with the date
echo -n > $OUTPUT_FILE
echo "**************************************************************************" |& tee -a ${OUTPUT_FILE}
echo "                Valgrind report on $(date)" |& tee -a ${OUTPUT_FILE}
echo "**************************************************************************" |& tee -a ${OUTPUT_FILE}

# Function to build Valgrind command
build_valgrind_cmd() {
    local test="$1"
    local regex_filter="$2"
    
    # Base command for Valgrind
    cmd="valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes \"$test\""
    
    # Append --gtest_filter if regex_filter is set
    if [ -n "$regex_filter" ]; then
        cmd+=" --gtest_filter=\"$regex_filter\""
    fi
    
    echo "$cmd"
}

# Run Valgrind on all tests
for test in "${test_arr[@]}"
do
    echo "===========================================================================" |& tee -a "${OUTPUT_FILE}"
    relativePath=$(realpath --relative-to="${TEST_DIR}" "${test}")
    echo "Running Valgrind on ${relativePath}: " |& tee -a "${OUTPUT_FILE}"
    echo "--------------------------------------------------------------------------" |& tee -a "${OUTPUT_FILE}"
    
    cmd=$(build_valgrind_cmd "${test}" "${REGEX_FILTER}")
    
    echo "cmd: ${cmd}" |& tee -a "${OUTPUT_FILE}"
    eval $cmd |& tee -a "${OUTPUT_FILE}"

    echo "===========================================================================" |& tee -a "${OUTPUT_FILE}"
    echo -e "\n\n\n" |& tee -a "${OUTPUT_FILE}"
done
