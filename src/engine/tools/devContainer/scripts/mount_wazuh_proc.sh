#!/bin/env bash

# Check if WAZUH_HOME is set
if [ -z "$WAZUH_HOME" ]; then
    WAZUH_HOME="/var/wazuh-manager"
fi

if [ ! -d "$WAZUH_HOME" ]; then
    echo "Wazuh home directory $WAZUH_HOME does not exist."
    exit 1
fi

# Mount proc filesystem if it does not exist (Mounted for development purposes)
if ! mountpoint -q ${WAZUH_HOME}/proc; then
    mkdir -p ${WAZUH_HOME}/proc
    mount -t proc proc ${WAZUH_HOME}/proc
    if [ $? -ne 0 ]; then
        echo "Failed to mount proc filesystem at ${WAZUH_HOME}/proc"
        exit 1
    fi
    echo "Mounted proc filesystem at ${WAZUH_HOME}/proc"
else
    echo "Proc filesystem is already mounted at ${WAZUH_HOME}/proc"
fi
