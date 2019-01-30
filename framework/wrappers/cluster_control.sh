#!/bin/sh

PYTHON_BIN="python/bin/python3.7"

# If WAZUH_PATH variable is not defined
if [ -z "${WAZUH_PATH}" ]; then
    WAZUH_PATH="$( cd $(dirname $0) ; pwd -P )/.."
fi

PYTHON_PATH="${WAZUH_PATH}/${PYTHON_BIN}"

${PYTHON_PATH} ${WAZUH_PATH}/framework/scripts/cluster_control.py $@