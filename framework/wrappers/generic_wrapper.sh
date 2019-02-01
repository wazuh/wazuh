#!/bin/sh
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

PYTHON_BIN="python/bin/python3.7"
FRAMEWORK_PATH="framework/scripts"

SCRIPT_PATH_NAME="$0"
# Split the variable using / as delimiter
# and get the last element
SCRIPT_NAME=$(echo ${SCRIPT_PATH_NAME##*/})

# If WAZUH_PATH variable is not defined
# the script will calculate it by remoning
# the relative path of the script in bin
# from the WAZUH_PATH.
#
# Ex: /var/ossec/bin/wazuh-clusterd => /var/ossec
if [ -z "${WAZUH_PATH}" ]; then
    WAZUH_PATH="$( cd $(dirname ${SCRIPT_PATH_NAME}) ; pwd -P )"
    WAZUH_PATH=${WAZUH_PATH%%/bin*}
fi

# If WPYTHON_PATH variable is not defined
if [ -z "${WPYTHON_PATH}" ]; then
    WPYTHON_PATH="${WAZUH_PATH}/${PYTHON_BIN}"
fi

${WPYTHON_PATH} ${WAZUH_PATH}/${FRAMEWORK_PATH}/${SCRIPT_NAME}.py $@