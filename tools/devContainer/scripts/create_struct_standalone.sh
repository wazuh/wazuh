#!/usr/bin/env bash
set -e

# Verify that exist the environment variable
if [ -z "${ENGINE_STANDALONE_DIR}" ] || [ -z "${ENGINE_SRC}" ]; then
    echo "The environment variable ENGINE_STANDALONE_DIR or ENGINE_SRC is not set"
    exit 1
fi


# Base dir (store)
STORE_PATH="${ENGINE_STANDALONE_DIR}/store"
SCHEMA_PATH="${STORE_PATH}/schema"
ENGINE_SCHEMA_PATH="${SCHEMA_PATH}/engine-schema/"
ENGINE_LOGPAR_TYPE_PATH="${SCHEMA_PATH}/wazuh-logpar-overrides"
ENGINE_ALLOWED_FIELDS_PATH="${SCHEMA_PATH}/allowed-fields"
mkdir -p "${ENGINE_SCHEMA_PATH}"
mkdir -p "${ENGINE_LOGPAR_TYPE_PATH}"
mkdir -p "${ENGINE_ALLOWED_FIELDS_PATH}"

# Empty start directories
mkdir -p "$ENGINE_STANDALONE_DIR/logs"
mkdir -p "$ENGINE_STANDALONE_DIR/tzdb"
mkdir -p "$ENGINE_STANDALONE_DIR/kvdb"
mkdir -p "$ENGINE_STANDALONE_DIR/queue/indexer/" # For rocksdb indexer conector
mkdir -p "$ENGINE_STANDALONE_DIR/outputs" # For cmsync output files



# Copying the store files
echo "Copying store files..."
cp "${ENGINE_SRC}/ruleset/schemas/engine-schema.json" "${ENGINE_SCHEMA_PATH}/0"
cp "${ENGINE_SRC}/ruleset/schemas/wazuh-logpar-overrides.json" "${ENGINE_LOGPAR_TYPE_PATH}/0"
cp "${ENGINE_SRC}/ruleset/schemas/allowed-fields.json" "${ENGINE_ALLOWED_FIELDS_PATH}/0"

echo "Standalone structure created at ${ENGINE_STANDALONE_DIR}"
