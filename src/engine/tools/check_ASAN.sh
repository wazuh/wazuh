#!bash

# Search the test directory
OLD_PWD=`pwd`
SCRIPT_DIR=$(dirname $(readlink -f $0))
cd $SCRIPT_DIR
BUILD_DIR=$SCRIPT_DIR/../../build
BUILD_SRC_DIR=$(realpath "${BUILD_DIR}/source")
TEST_DIR=$(realpath "${BUILD_DIR}/test")
TEST_SRC_DIR=$(realpath "${TEST_DIR}/source")
echo "BUILD DIR: ${BUILD_DIR}"
echo "BUILD SRC DIR: ${BUILD_SRC_DIR}"
echo "TEST SRC IR: ${TEST_SRC_DIR}"
echo "TEST DIR: ${TEST_DIR}"

# Chec if the all directories exist
if [ ! -d "${BUILD_DIR}" ]; then
    echo "Build directory does not exist"
    exit 1
fi
if [ ! -d "${BUILD_SRC_DIR}" ]; then
    echo "Build source directory does not exist"
    exit 1
fi
if [ ! -d "${TEST_DIR}" ]; then
    echo "Test directory does not exist"
    exit 1
fi
if [ ! -d "${TEST_SRC_DIR}" ]; then
    echo "Test source directory does not exist"
    exit 1
fi

# Get filist
TEST_LIST=$(find "${TEST_SRC_DIR}" -iname '*_test' -type f)
LIBS_LIST=$(find "${BUILD_SRC_DIR}" -iname '*.a' -type f)
# Split the list into an array
IFS=$'\n' read -d '' -r -a test_arr <<< "${TEST_LIST}"
IFS=$'\n' read -d '' -r -a lib_arr <<< "${LIBS_LIST}"

# Merge the arrays
bin_arr=("${test_arr[@]}" "${lib_arr[@]}")
bin_arr+=("${BUILD_DIR}/main")

# Check if the binary was compiled with ASAN
for testAbs in "${bin_arr[@]}"
do
    relativePath=$(realpath --relative-to="${BUILD_DIR}" "${testAbs}")
    nm -an $testAbs | grep -q '__asan\|__tsan\|__msan'
    if [ $? -eq 0 ]; then
        echo "🟢 $relativePath"
    else
        echo "🔴 $relativePath failed, no compile with asan"
        exit 1
    fi
done

# Exclude KVDBTest.KVDBConcurrency
# ctest --test-dir "${TEST_DIR}" --output-on-failure --exclude-regex KVDBTest.KVDBConcurrency
ctest --test-dir "${TEST_DIR}" --output-on-failure
