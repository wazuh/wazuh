#!/bin/bash

check_protoc_installed() {
    if ! [ -x "$(command -v protoc)" ]; then
        echo 'Error: protoc is not installed.' >&2
        exit 1
    fi
}

move_to_script_directory() {
    SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
    SRC_PROTO_DIR="${SCRIPT_DIR}/src"
    PROTO_DEPS_SRC_DIR=../../../build/_deps/protobuf-src/src

    cd "$SRC_PROTO_DIR" || exit 1
}

verify_changes_in_proto_directory() {
    # Get the current timestamp and the list of .proto files
    current_modification_time=$(find . -name "*.proto" -exec stat -c "%Y" {} + | md5sum | awk '{print $1}')
    current_file_list=$(find . -name "*.proto" | sort)

    # Read the stored timestamp and file list (if they exist)
    previous_modification_time=""
    previous_file_list=""
    if [ -f "$TMPDIR/previous_modification_time" ]; then
        previous_modification_time=$(cat "$TMPDIR/previous_modification_time")
    fi
    if [ -f "$TMPDIR/previous_file_list" ]; then
        previous_file_list=$(cat "$TMPDIR/previous_file_list")
    fi

    # Compare timestamps and file lists
    if [ "$current_modification_time" = "$previous_modification_time" ] && [ "$current_file_list" = "$previous_file_list" ]; then
        echo "No changes in .proto files."
        exit 0
    fi

    # Store the current timestamp and file list in temporary files
    echo "$current_modification_time" > "$TMPDIR/previous_modification_time"
    echo "$current_file_list" > "$TMPDIR/previous_file_list"

    # Export environment variables with the values from the temporary files
    export previous_modification_time="$(cat "$TMPDIR/previous_modification_time")"
    export previous_file_list="$(cat "$TMPDIR/previous_file_list")"
}

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

format_code() {
    CLANG_DIR="${SCRIPT_DIR}/../../"
    CPP_DIR="${SCRIPT_DIR}/include/eMessages/"
    PYTHON_DIR="${SCRIPT_DIR}/../../tools/api-communication/src/api_communication/proto"

    cd "$CLANG_DIR" || exit 1
    $CLANG_FORMAT -i -style=file "${SRC_PROTO_DIR}"/*.proto
}

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

generate_code() {
    PROTO_DEPS_SRC_DIR=../../../build/_deps/protobuf-src/src

    cd "${SRC_PROTO_DIR}" || exit 1
    protoc --proto_path="$PROTO_DEPS_SRC_DIR" --proto_path="${SRC_PROTO_DIR}" --cpp_out="$CPP_DIR" *.proto
    protoc --proto_path="$PROTO_DEPS_SRC_DIR" --proto_path="${SRC_PROTO_DIR}" --python_out="$PYTHON_DIR" --pyi_out="$PYTHON_DIR" *.proto
}

modify_python_imports() {
    python_files=$(grep -rl '^import .*_pb2' --include="*.py" "$PYTHON_DIR")

    for file in $python_files; do
        sed -i '/^import .*_pb2/s/import \(.*\) as \(.*\)/import api_communication.proto.\1 as _\1/' "$file"
    done
}

# Main script starts here
check_protoc_installed
move_to_script_directory
verify_changes_in_proto_directory
select_clang_format_version
format_code
clean_up_files
generate_code
modify_python_imports

# Go back to the original working directory
cd - || exit 1
