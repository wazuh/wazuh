#!/bin/sh
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

WAZUH_SHARE="/usr/share/wazuh-server"
WPYTHON_BIN="${WAZUH_SHARE}/framework/python/bin/python3"

SCRIPT_PATH_NAME="$0"
SCRIPT_NAME="$(basename ${SCRIPT_PATH_NAME})"

PYTHON_SCRIPT="${WAZUH_SHARE}/framework/scripts/${SCRIPT_NAME}.py"

${WPYTHON_BIN} ${PYTHON_SCRIPT} "$@"
