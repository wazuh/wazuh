#!bash

# check if protobuf is installed
if ! [ -x "$(command -v protoc)" ]; then
  echo 'Error: protoc is not installed.' >&2
  exit 1
fi

# Move to the directory of this script
OLD_PWD=`pwd`
SCRIPT_DIR=$(dirname $(readlink -f $0))

SRC_PROTO_DIR="${SCRIPT_DIR}/src"
CPP_DIR="${SCRIPT_DIR}/include/eMessages/"
PROTO_DEPS_SRC_DIR=../../../build/_deps/protobuf-src/src

# Generate CPP code (Move for relative paths)
cd "${SRC_PROTO_DIR}"
protoc --proto_path=$PROTO_DEPS_SRC_DIR --proto_path="${SRC_PROTO_DIR}" --cpp_out=$CPP_DIR *.proto

# Go back
cd $OLD_PWD
