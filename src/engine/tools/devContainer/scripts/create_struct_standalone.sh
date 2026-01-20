#!/usr/bin/env bash
set -e

# Verify that exist the environment variable
if [ -z "${ENGINE_STANDALONE_DIR}" ] || [ -z "${ENGINE_SRC}" ]; then
    echo "The environment variable ENGINE_STANDALONE_DIR or ENGINE_SRC is not set"
    exit 1
fi


# Base dir (store)
STORE_PATH="${ENGINE_STANDALONE_DIR}/store"
mkdir -p "${STORE_PATH}"

# Empty start directories
mkdir -p "$ENGINE_STANDALONE_DIR/logs"
mkdir -p "$ENGINE_STANDALONE_DIR/tzdb"
mkdir -p "$ENGINE_STANDALONE_DIR/kvdb"
mkdir -p "$ENGINE_STANDALONE_DIR/queue/indexer/" # For rocksdb indexer conector
mkdir -p "$ENGINE_STANDALONE_DIR/outputs" # For cmsync output files

# Copying the store files
echo "Copying store files..."
cp "${ENGINE_SRC}/ruleset/schemas/engine-schema.json" "${STORE_PATH}/schema%2Fengine-schema%2F0.json"
cp "${ENGINE_SRC}/ruleset/schemas/wazuh-logpar-overrides.json" "${STORE_PATH}/schema%2Fwazuh-logpar-overrides%2F0.json"
cp "${ENGINE_SRC}/ruleset/schemas/allowed-fields.json" "${STORE_PATH}/schema%2Fallowed-fields%2F0.json"

echo "Standalone structure created at ${ENGINE_STANDALONE_DIR}"
