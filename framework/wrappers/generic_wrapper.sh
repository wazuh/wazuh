#!/bin/sh

PYTHON_BIN="python/bin/python3.7"
FRAMEWORK_PATH="framework/scripts"

SCRIPT_PATH_NAME="$0"
# Split the variable using / as delimiter
# and get the last element
SCRIPT_NAME=$(echo ${SCRIPT_PATH_NAME##*/})

# If WAZUH_PATH variable is not defined
if [ -z "${WAZUH_PATH}" ]; then
    WAZUH_PATH="$( cd $(dirname ${SCRIPT_PATH_NAME}) ; pwd -P )/.."
fi

# If WPYTHON_PATH variable is not defined
if [ -z "${WPYTHON_PATH}" ]; then
    WPYTHON_PATH="${WAZUH_PATH}/${PYTHON_BIN}"
fi

${WPYTHON_PATH} ${WAZUH_PATH}/${FRAMEWORK_PATH}/${SCRIPT_NAME}.py $@