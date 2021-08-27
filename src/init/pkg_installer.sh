#!/bin/bash

# Copyright (C) 2015-2021, Wazuh Inc.

WAZUH_HOME=${1}
WAZUH_VERSION=${2}

# Installing upgrade
echo "$(date +"%Y/%m/%d %H:%M:%S") - Upgrade started." >> ${WAZUH_HOME}/logs/upgrade.log
chmod +x ${WAZUH_HOME}/var/upgrade/install.sh
${WAZUH_HOME}/var/upgrade/install.sh >> ${WAZUH_HOME}/logs/upgrade.log 2>&1

# Check installation result
RESULT=$?
echo "$(date +"%Y/%m/%d %H:%M:%S") - Installation result = ${RESULT}" >> ${WAZUH_HOME}/logs/upgrade.log

# Wait connection
status="pending"
COUNTER=30
while [ "$status" != "connected" -a $COUNTER -gt 0  ]; do
    . ${WAZUH_HOME}/var/run/wazuh-agentd.state >> ${WAZUH_HOME}/logs/upgrade.log 2>&1
    sleep 1
    COUNTER=$[COUNTER - 1]
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Waiting connection... Status = "${status}". Remaining attempts: ${COUNTER}." >> ${WAZUH_HOME}/logs/upgrade.log
done

# Check connection
if [ "$status" = "connected" -a $RESULT -eq 0  ]; then
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Connected to manager." >> ${WAZUH_HOME}/logs/upgrade.log
    echo -ne "0" > ${WAZUH_HOME}/var/upgrade/upgrade_result
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Upgrade finished successfully." >> ${WAZUH_HOME}/logs/upgrade.log
else
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Upgrade failed..." >> ${WAZUH_HOME}/logs/upgrade.log

    CONTROL="$WAZUH_HOME/bin/wazuh-control"
    if [ ! -f $CONTROL ]; then
        CONTROL="$WAZUH_HOME/bin/ossec-control"
    fi

    echo "$(date +"%Y/%m/%d %H:%M:%S") - Trying to start the agent on its current state..." >> ${WAZUH_HOME}/logs/upgrade.log
    $CONTROL start >> ${WAZUH_HOME}/logs/upgrade.log 2>&1
    echo -ne "2" > ${WAZUH_HOME}/var/upgrade/upgrade_result

fi
