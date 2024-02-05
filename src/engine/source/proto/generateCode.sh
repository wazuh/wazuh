#!/bin/bash

# check if protobuf is installed
if ! [ -x "$(command -v protoc)" ]; then
  echo 'Error: protoc is not installed.' >&2
  exit 1
fi

# Move to the directory of this script
OLD_PWD=$(pwd)
SCRIPT_DIR=$(dirname $(readlink -f $0))
SRC_PROTO_DIR="${SCRIPT_DIR}/src"
PROTO_DEPS_SRC_DIR=../../../build/_deps/protobuf-src/src

target="${1:-cpp}"

if [ "$target" = "cpp" ]; then
  echo "Generating C++ code"
  # Select the clang-format version
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

  CLANG_DIR="${SCRIPT_DIR}/../../"
  CPP_DIR="${SCRIPT_DIR}/include/eMessages/"

  # Format the code
  cd "${CLANG_DIR}"
  $CLANG_FORMAT -i -style=file "${SRC_PROTO_DIR}"/*.proto

  # Get list of modified, new and deleted files
  MODIFIED_FILES=$(git ls-files --modified "${SRC_PROTO_DIR}"/*.proto | cut -f2- | xargs -n1 basename)
  NEW_FILES=$(git ls-files --others --exclude-standard "${SRC_PROTO_DIR}"/*.proto | xargs -n1 basename)
  DELETED_FILES=$(git ls-files --deleted "${SRC_PROTO_DIR}")

  # Change to working directory
  cd "${SRC_PROTO_DIR}"

  # Delete .cc and .h files for deleted/renamed .proto files
  for deleted_file in $DELETED_FILES; do
      base_name=$(basename "$deleted_file" .proto)
      rm -f "${CPP_DIR}${base_name}.pb.cc" "${CPP_DIR}${base_name}.pb.h"
  done

  # Generate CPP code only for modified or new .proto files
  cd "${SRC_PROTO_DIR}"
  protoc --proto_path=$PROTO_DEPS_SRC_DIR --proto_path="${SRC_PROTO_DIR}" --cpp_out=$CPP_DIR $MODIFIED_FILES $NEW_FILES

  # Go back
  cd $OLD_PWD

elif [ "$target" = "py" ]; then
  echo "Generating Python code"
  PYTHON_DIR="${SCRIPT_DIR}/../../tools/api-communication/src/api_communication/proto"

  # Get the list of modified or renamed proto files
  MODIFIED_FILES=$(git diff --name-status "${SRC_PROTO_DIR}"/*.proto | grep -E '^(M|R)' | cut -f2-)

  # Generate Python code only for modified or renamed proto files
  cd "${SRC_PROTO_DIR}"
  protoc --proto_path=$PROTO_DEPS_SRC_DIR --proto_path="${SRC_PROTO_DIR}" --python_out=$PYTHON_DIR --pyi_out=$PYTHON_DIR $MODIFIED_FILES

  # Go back
  cd $OLD_PWD

else
  echo "Unknown target: $target"
  exit 1
fi
