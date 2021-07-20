#!/bin/bash
# Copyright (C) 2015-2021, Wazuh Inc.

# Get Wazuh installation path
SCRIPT=$(readlink -f "$0")
WAZUH_HOME=$(dirname $(dirname $(dirname "$SCRIPT")))

# Get Wazuh Info
eval $(${WAZUH_HOME}/bin/wazuh-control info 2>/dev/null)
if [ "X${WAZUH_VERSION}" = "X" ] ; then
    . /etc/ossec-init.conf 2> /dev/null
    if [ "X${VERSION}" = "X" ] ; then
        exit 1
    else
        WAZUH_VERSION=${VERSION}
    fi
fi

(sleep 5 && chmod +x ${WAZUH_HOME}/var/upgrade/src/init/*.sh && ${WAZUH_HOME}/var/upgrade/src/init/pkg_installer.sh ${WAZUH_HOME} ${WAZUH_VERSION} && find ${WAZUH_HOME}/var/upgrade/* -not -name upgrade_result -delete) >/dev/null 2>&1 &
