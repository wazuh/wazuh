#!/bin/bash

if [ $# -lt 1 ]; then
    echo "Usage: $0 <github_working_directory>"
    exit 1
fi

GITHUB_WORKING_DIRECTORY="$1"
CONF_FILE="${2:-general.conf}"

ENGINE_SRC_DIR=$GITHUB_WORKING_DIRECTORY/src/engine
ENVIRONMENT_DIR=$GITHUB_WORKING_DIRECTORY/environment
ENGINE_DIR=$ENVIRONMENT_DIR/engine

echo "--- Folder creation ---"
mkdir -p $ENVIRONMENT_DIR
mkdir -p $ENGINE_DIR
mkdir -p $ENVIRONMENT_DIR/queue/sockets
mkdir $ENVIRONMENT_DIR/logs
touch $ENVIRONMENT_DIR/logs/engine-flood.log


echo "--- Setting up the engine ---"
mkdir -p $ENGINE_DIR/store/schema
mkdir -p $ENVIRONMENT_DIR/etc/kvdb/
mkdir -p $ENVIRONMENT_DIR/etc/kvdb_test/
# Copy needed files in the store so the engine can start
mkdir -p $ENGINE_DIR/store/schema/wazuh-logpar-types
cp $ENGINE_SRC_DIR/ruleset/schemas/wazuh-logpar-types.json $ENGINE_DIR/store/schema/wazuh-logpar-types/0
mkdir -p $ENGINE_DIR/store/schema/wazuh-asset
cp $ENGINE_SRC_DIR/ruleset/schemas/wazuh-asset.json $ENGINE_DIR/store/schema/wazuh-asset/0
mkdir -p $ENGINE_DIR/store/schema/wazuh-policy
cp $ENGINE_SRC_DIR/ruleset/schemas/wazuh-policy.json $ENGINE_DIR/store/schema/wazuh-policy/0
mkdir -p $ENGINE_DIR/store/schema/engine-schema
cp $ENGINE_SRC_DIR/ruleset/schemas/engine-schema.json $ENGINE_DIR/store/schema/engine-schema/0
