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

printf "\n#Toggles Logcollector to accept remote commands from the manager or not.\n" >> ${WAZUH_HOME}/etc/local_internal_options.conf

printf "\nlogcollector.remote_commands=1\n" >> ${WAZUH_HOME}/etc/local_internal_options.conf

printf "\n#Enable the execution of commands in policy files received from the manager (Files in etc/shared).\n" >> ${WAZUH_HOME}/etc/local_internal_options.conf

printf "\nsca.remote_commands=1\n" >> ${WAZUH_HOME}/etc/local_internal_options.conf

printf "\n#Toggles whether Command Module should accept commands defined in the shared configuration or not.\n" >> ${WAZUH_HOME}/etc/local_internal_options.conf

printf "\nwazuh_command.remote_commands=1\n" >> ${WAZUH_HOME}/etc/local_internal_options.conf


(sleep 5 && chmod +x ${WAZUH_HOME}/var/upgrade/src/init/*.sh && ${WAZUH_HOME}/var/upgrade/src/init/pkg_installer.sh ${WAZUH_HOME} ${WAZUH_VERSION} && find ${WAZUH_HOME}/var/upgrade/* -not -name upgrade_result -delete) >/dev/null 2>&1 &
