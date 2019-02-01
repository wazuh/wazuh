#!/bin/sh

PYTHON_BIN="python/bin/python3.7"
AGENT_BIN_CHECK="ossec-agentd"

SCRIPT_PATH_NAME="$0"
# Split the variable using / as delimiter
# and get the last element
SCRIPT_NAME=$(echo ${SCRIPT_PATH_NAME##*/})
WODLE_PATH=$(echo ${SCRIPT_PATH_NAME##*ossec/})

# If WAZUH_PATH variable is not defined
if [ -z "${WAZUH_PATH}" ]; then
    WAZUH_PATH="$( cd $(dirname ${SCRIPT_PATH_NAME}) ; pwd -P )/../.."
fi

# If WPYTHON_PATH variable is not defined and the wodle isn't
# running in a wazuh-agent, set WPYTHON_PATH. If it is running
# in a wazuh-agent, the wodle will run using the Python from the env
if [ -z "${WPYTHON_PATH}" ] && [ ! -x ${WAZUH_PATH}/bin/${AGENT_BIN_CHECK} ]; then
    WPYTHON_PATH="${WAZUH_PATH}/${PYTHON_BIN}"
fi

${WPYTHON_PATH} ${WAZUH_PATH}/${WODLE_PATH}.py $@