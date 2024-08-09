#!/bin/bash

# Function to display help message
usage() {
    echo "Usage: $0 [options] [test_directory] [regex_pattern] [output_file]"
    echo
    echo "Options:"
    echo "  -h, --help          Show this help message"
    echo "  -e, --exclude DIRS  Colon-separated list of directories to exclude (applies only when using default test directory)"
    echo
    echo "Arguments:"
    echo "  test_directory      Directory to search for tests (default: build directory)"
    echo "  regex_pattern       Optional regular expression to filter tests (default: no filtering)"
    echo "  output_file         Optional file to redirect output (default: stdout)"
}

# Initialize variables
EXCLUDE_DIRS=""

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
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Search the test directory
SCRIPT_DIR=$(dirname $(readlink -f $0))
BUILD_DIR=$SCRIPT_DIR/../build
BUILD_SRC_DIR=$(realpath "${BUILD_DIR}/source")

echo "SCRIPT DIR: ${SCRIPT_DIR}"
echo "BUILD DIR: $(readlink -f ${BUILD_DIR})"
echo "BUILD SRC DIR: ${BUILD_SRC_DIR}"

# Check if the directories exist
if [ ! -d "${BUILD_DIR}" ]; then
    echo "Build directory does not exist"
    exit 1
fi
if [ ! -d "${BUILD_SRC_DIR}" ]; then
    echo "Build source directory does not exist"
    exit 1
fi

# Handle test directory argument
if [ "$#" -gt 0 ]; then
    TEST_DIR=$1
    shift
else
    # Default to the build directory if no argument is provided
    TEST_DIR=$BUILD_DIR
fi

# Handle regex argument for ctest
REGEX=""
if [ "$#" -gt 0 ]; then
    REGEX="--tests-regex $1"
    shift
fi

# Handle output file argument
OUTPUT_FILE=""
if [ "$#" -gt 0 ]; then
    OUTPUT_FILE=$1
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
            echo "🔴 $relativePath failed, no compile with asan"
            exit 1
        fi
    fi
done

# Run ctest and handle output redirection
if [ -n "$OUTPUT_FILE" ]; then
    ctest --test-dir "${TEST_DIR}" --output-on-failure "${REGEX}" -V > "$OUTPUT_FILE"
else
    ctest --test-dir "${TEST_DIR}" --output-on-failure "${REGEX}" -V
fi
