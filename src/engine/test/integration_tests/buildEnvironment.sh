#!/bin/bash

if [ $# -ne 2 ]; then
    echo "Usage: $0 <root_dir> <new_path>"
    exit 1
fi

root_dir="$1"
new_path="$2"

#/home/runner/work/wazuh/wazuh
ENGINE_SRC_DIR=$new_path/src/engine
ENVIRONMENT_DIR=$new_path/environment
ENGINE_DIR=$ENVIRONMENT_DIR/engine

if [ ! -f "$root_dir" ]; then
    echo "File not found: $root_dir"
    exit 1
fi

# Reemplazar ocurrencias de /var/ossec con la nueva ruta
sed -i "s,/var/ossec,$ENVIRONMENT_DIR,g" "$root_dir"

echo "--- Folder creation ---"
mkdir -p $ENVIRONMENT_DIR
mkdir -p $ENGINE_DIR

mkdir -p $ENVIRONMENT_DIR/queue/sockets
nc -klU $ENVIRONMENT_DIR/queue/sockets/engine-api &
nc -klU $ENVIRONMENT_DIR/queue/sockets/queue &

mkdir $ENVIRONMENT_DIR/logs
touch $ENVIRONMENT_DIR/logs/engine-flood.log



echo "--- Setting up the engine ---"
echo $ENGINE_SRC_DIR

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

