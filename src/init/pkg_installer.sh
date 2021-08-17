#!/bin/bash

# Copyright (C) 2015-2021, Wazuh Inc.

# Installing upgrade
echo "$(date +"%Y/%m/%d %H:%M:%S") - Upgrade started." >> ./logs/upgrade.log

if [ "X$(uname)" = "XLinux" ] ; then
    chmod +x ./var/upgrade/install.sh
    ./var/upgrade/install.sh >> ./logs/upgrade.log 2>&1
else
    chmod +x ./var/upgrade/wazuh-agent*
    installer -pkg ./var/upgrade/wazuh-agent* -target / >> ./logs/upgrade.log 2>&1
fi

# Check installation result
RESULT=$?
echo "$(date +"%Y/%m/%d %H:%M:%S") - Installation result = ${RESULT}" >> ./logs/upgrade.log

# Wait connection
status="pending"
COUNTER=30
while [ "$status" != "connected" -a $COUNTER -gt 0  ]; do
    . ./var/run/wazuh-agentd.state >> ./logs/upgrade.log 2>&1
    sleep 1
    COUNTER=$[COUNTER - 1]
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Waiting connection... Status = "${status}". Remaining attempts: ${COUNTER}." >> ./logs/upgrade.log
done

# Check connection
if [ "$status" = "connected" -a $RESULT -eq 0  ]; then
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Connected to manager." >> ./logs/upgrade.log
    echo -ne "0" > ./var/upgrade/upgrade_result
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Upgrade finished successfully." >> ./logs/upgrade.log
else
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Upgrade failed..." >> ./logs/upgrade.log

    CONTROL="./bin/wazuh-control"
    if [ ! -f $CONTROL ]; then
        CONTROL="./bin/ossec-control"
    fi

    echo "$(date +"%Y/%m/%d %H:%M:%S") - Trying to start the agent on its current state..." >> ./logs/upgrade.log
    $CONTROL start >> ./logs/upgrade.log 2>&1
    echo -ne "2" > ./var/upgrade/upgrade_result

fi
