#!bash

# check if protobuf is installed
if ! [ -x "$(command -v protoc)" ]; then
  echo 'Error: protoc is not installed.' >&2
  exit 1
fi

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

# Move to the directory of this script
OLD_PWD=`pwd`
SCRIPT_DIR=$(dirname $(readlink -f $0))

SRC_PROTO_DIR="${SCRIPT_DIR}/src"
CLANG_DIR="${SCRIPT_DIR}/../../"
CPP_DIR="${SCRIPT_DIR}/include/eMessages/"
PROTO_DEPS_SRC_DIR=../../../build/_deps/protobuf-src/src

# Format the code
cd "${CLANG_DIR}"
$CLANG_FORMAT -i -style=file "${SRC_PROTO_DIR}"/*.proto

# Generate CPP code (Move for relative paths)
cd "${SRC_PROTO_DIR}"
protoc --proto_path=$PROTO_DEPS_SRC_DIR --proto_path="${SRC_PROTO_DIR}" --cpp_out=$CPP_DIR *.proto

# Go back
cd $OLD_PWD
