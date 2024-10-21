#!/bin/bash
# Search for the protoc compiler and source from the vcpkg directory
set_proto_config() {
    if [ -z "$VCPKG_INSTALLED_DIR" ]; then
        echo "Error: VCPKG_INSTALLED_DIR is not set, build the code using cmake." >&2
        ENGINE_DIR=$(readlink -f "${ENGINE_DIR}")
        echo "i.e: cd ${ENGINE_DIR} && cmake --preset debug -DENGINE_GENERATE_PROTO=ON && cmake --build ./build --target generate_protobuf_code" >&2
        exit 1
    fi

    VCPKG_PROTO=${VCPKG_INSTALLED_DIR}/tools/protobuf/protoc
    INCLUDE_PROTO_DIR=${VCPKG_INSTALLED_DIR}/include/

    if [ ! -f "$VCPKG_PROTO" ]; then
        echo "Error: protoc compiler not found in VCPKG_INSTALLED_DIR." >&2
        exit 1
    fi

    if [ ! -d "$INCLUDE_PROTO_DIR/google/protobuf" ]; then
        echo "Error: include directory not found in VCPKG_INSTALLED_DIR." >&2
        exit 1
    fi
}

# Function to set up paths and variables
initialize_variables() {
    # Parameters of protoc
    OUTPUT_CPP_DIR="${SCRIPT_DIR}/include/eMessages/"
    ENGINE_SRC_PROTO="${SCRIPT_DIR}/src"
    OUTPUT_PYTHON_DIR="${ENGINE_DIR}/tools/api-communication/src/api_communication/proto"

    # Prepare clang-format for pre-processing
    CLANG_DIR="${ENGINE_DIR}"
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
        CLANG_FORMAT=true
        echo 'Warning: clang-format not found, skipping code formatting.'
    fi
}

# Function to format code using clang-format
format_code() {
    cd "$CLANG_DIR" || exit 1
    $CLANG_FORMAT -i -style=file "${ENGINE_SRC_PROTO}"/*.proto
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

    clean_directory "$OUTPUT_CPP_DIR" "eMessage.h" "readme.md"
    clean_directory "$OUTPUT_PYTHON_DIR" "__init__.py"
}

# Function to generate code using protoc
generate_code() {
    cd "${ENGINE_SRC_PROTO}" || exit 1
    $VCPKG_PROTO --proto_path="$INCLUDE_PROTO_DIR" --proto_path="${ENGINE_SRC_PROTO}" --cpp_out="$OUTPUT_CPP_DIR" *.proto
    $VCPKG_PROTO --proto_path="$INCLUDE_PROTO_DIR" --proto_path="${ENGINE_SRC_PROTO}" --python_out="$OUTPUT_PYTHON_DIR" --pyi_out="$OUTPUT_PYTHON_DIR" *.proto
}

# Necessary modifications for python imports
modify_python_imports() {
    python_files=$(grep -rl '^import .*_pb2' --include="*.py" "$OUTPUT_PYTHON_DIR")

    for file in $python_files; do
        sed -i '/^import .*_pb2/s/import \(.*\) as \(.*\)/import api_communication.proto.\1 as _\1/' "$file"
    done
}

# Global constants
OLD_PWD=$(pwd)  
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
ENGINE_DIR="${SCRIPT_DIR}/../.." 

# Main script starts here
set_proto_config
initialize_variables
select_clang_format_version
format_code
clean_up_files
generate_code
modify_python_imports

# Go back to the original working directory
cd $OLD_PWD || exit 1
