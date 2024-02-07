#!/bin/bash

# Function to check if protoc is installed
check_protoc_installed() {
    if ! [ -x "$(command -v protoc)" ]; then
        echo 'Error: protoc is not installed.' >&2
        exit 1
    fi
}

# Function to set up paths and variables
initialize_variables() {
    OLD_PWD=$(pwd)
    PROTO_DEPS_SRC_DIR=../../../build/_deps/protobuf-src/src
    SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
    SRC_PROTO_DIR="${SCRIPT_DIR}/src"
    CLANG_DIR="${SCRIPT_DIR}/../../"
    CPP_DIR="${SCRIPT_DIR}/include/eMessages/"
    PYTHON_DIR="${SCRIPT_DIR}/../../tools/api-communication/src/api_communication/proto"
}

# Function to select the appropriate clang-format version
select_clang_format_version() {
    if [ -x "$(command -v clang-format-11)" ]; then
        CLANG_FORMAT=clang-format-11
    elif [ -x "$(command -v clang-format-10)" ]; then
        CLANG_FORMAT=clang-format-10
    elif [ -x "$(command -v clang-format)" ]; then
        CLANG_FORMAT=clang-format
    else
        echo 'Error: clang-format is not installed.' >&2
        exit 1
    fi
}

# Function to format code using clang-format
format_code() {
    cd "$CLANG_DIR" || exit 1
    $CLANG_FORMAT -i -style=file "${SRC_PROTO_DIR}"/*.proto
}

# Function to clean up unnecessary files
clean_up_files() {
    clean_directory() {
        local dir="$1"
        local preserve_file1="$2"
        local preserve_file2="$3"
        if [ -d "$dir" ]; then
            find "$dir" -type f ! \( -name "$preserve_file1" -o -name "$preserve_file2" \) -delete
        fi
    }

    clean_directory "$CPP_DIR" "eMessage.h" "readme.md"
    clean_directory "$PYTHON_DIR" "__init__.py"
}

# Function to generate code using protoc
generate_code() {
    cd "${SRC_PROTO_DIR}" || exit 1
    protoc --proto_path="$PROTO_DEPS_SRC_DIR" --proto_path="${SRC_PROTO_DIR}" --cpp_out="$CPP_DIR" *.proto
    protoc --proto_path="$PROTO_DEPS_SRC_DIR" --proto_path="${SRC_PROTO_DIR}" --python_out="$PYTHON_DIR" --pyi_out="$PYTHON_DIR" *.proto
}

# Function to modify Python imports
modify_python_imports() {
    python_files=$(grep -rl '^import .*_pb2' --include="*.py" "$PYTHON_DIR")

    for file in $python_files; do
        sed -i '/^import .*_pb2/s/import \(.*\) as \(.*\)/import api_communication.proto.\1 as _\1/' "$file"
    done
}

# Main script starts here
check_protoc_installed
initialize_variables
select_clang_format_version
format_code
clean_up_files
generate_code
modify_python_imports

# Go back to the original working directory
cd $OLD_PWD || exit 1
