#!bash

# check if protobuf is installed
if ! [ -x "$(command -v protoc)" ]; then
  echo 'Error: protoc is not installed.' >&2
  exit 1
fi

# Move to the directory of this script
OLD_PWD=`pwd`
SCRIPT_DIR=$(dirname $(readlink -f $0))
cd $SCRIPT_DIR
PROTODIR=.
CPP_DIR=../api/src/messages
PROTO_DEPS_SRC_DIR=../../build/_deps/protobuf-src/src

# Generate CPP code
protoc --proto_path=$PROTODIR --cpp_out=$CPP_DIR $PROTODIR/*.proto

# Go back
cd $OLD_PWD
