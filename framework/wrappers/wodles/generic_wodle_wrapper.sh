#!/bin/sh
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

PYTHON_BIN="python/bin/python3.7"
AGENT_BIN_CHECK="ossec-agentd"

SCRIPT_PATH_NAME="$0"
# Eliminate everything from the string until
# it found the string "ossec/"
WODLE_PATH=$(echo ${SCRIPT_PATH_NAME##*ossec/})

# If WAZUH_PATH variable is not defined
# the script will calculate it by remoning
# the relative path of the wodle from the WAZUH_PATH.
#
# Ex: /var/ossec/wodles/aws/aws-s3 => /var/ossec
if [ -z "${WAZUH_PATH}" ]; then
    WAZUH_PATH="$( cd $(dirname ${SCRIPT_PATH_NAME}) ; pwd -P )"
    WAZUH_PATH=${WAZUH_PATH%%/wodles*}
fi

# If WPYTHON_PATH variable is not defined and the wodle isn't
# running in a wazuh-agent, set WPYTHON_PATH. If it is running
# in a wazuh-agent, the wodle will run using the Python from the env
if [ -z "${WPYTHON_PATH}" ] && [ ! -x ${WAZUH_PATH}/bin/${AGENT_BIN_CHECK} ]; then
    WPYTHON_PATH="${WAZUH_PATH}/${PYTHON_BIN}"
fi

# If WPYTHON_PATH is not defined, the wodle will be executed
# using /usr/bin/env python. This means that it will run the python
# binary found in $PATH
${WPYTHON_PATH} ${WAZUH_PATH}/${WODLE_PATH}.py $@