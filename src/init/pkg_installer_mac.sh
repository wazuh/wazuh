#!/bin/bash
# Copyright (C) 2015, Wazuh Inc.

WAZUH_HOME=`pwd`
if [ "${WAZUH_HOME}" = "/" ]; then
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Execution path is wrong, interrupting upgrade." >> ./logs/upgrade.log
    exit 1
fi

# Check if there is an upgrade in progress
if [ -e "./var/upgrade/upgrade_in_progress" ]; then
    echo "$(date +"%Y/%m/%d %H:%M:%S") - There is an upgrade in progress. Aborting..." >> ./logs/upgrade.log
    exit 1
fi

# Installing upgrade
touch ./var/upgrade/upgrade_in_progress
echo "$(date +"%Y/%m/%d %H:%M:%S") - Upgrade started." >> ./logs/upgrade.log
installer -pkg ./var/upgrade/wazuh-agent* -target / >> ./logs/upgrade.log 2>&1

# Check installation result
RESULT=$?

echo "$(date +"%Y/%m/%d %H:%M:%S") - Installation result = ${RESULT}" >> ./logs/upgrade.log

# Wait connection
status="pending"
COUNTER=30
while [ "$status" != "connected" -a $COUNTER -gt 0 ]; do
    . ./var/run/wazuh-agentd.state >> ./logs/upgrade.log 2>&1
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Waiting connection... Remaining attempts: ${COUNTER}." >> ./logs/upgrade.log
    sleep 1
    COUNTER=$[COUNTER - 1]
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Status = "${status}". " >> ./logs/upgrade.log
done

# Check connection and update upgrade log
if [ "$status" = "connected" -a $RESULT -eq 0 ]; then
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Connected to manager." >> ./logs/upgrade.log
    echo -ne "0" > ./var/upgrade/upgrade_result
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Upgrade finished successfully." >> ./logs/upgrade.log
else
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Upgrade failed..." >> ./logs/upgrade.log
    echo -ne "2" > ./var/upgrade/upgrade_result
fi

rm -f ./var/upgrade/upgrade_in_progress

exit 0
