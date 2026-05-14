#!/bin/bash
# Copyright (C) 2015, Wazuh Inc.


LOCK=./var/upgrade/upgrade_in_progress_pid
cat /dev/null >> $LOCK
read UPGRADE_PID < $LOCK

# Check if there is an upgrade in progress
if [ ! -z "$UPGRADE_PID" -a -d /proc/$UPGRADE_PID ]; then
    echo "$(date +"%Y/%m/%d %H:%M:%S") - There is an upgrade in progress. Aborting..." >> ./logs/upgrade.log
    exit 1
fi

# Installing upgrade
echo $$ > $LOCK
echo "$(date +"%Y/%m/%d %H:%M:%S") - Upgrade started." >> ./logs/upgrade.log

OS=$(uname)
WAZUH_HOME=$(pwd)

echo "$(date +"%Y/%m/%d %H:%M:%S") - Checking execution path." >> ./logs/upgrade.log

if [[ "$OS" == "Darwin" ]]; then
    if [ "${WAZUH_HOME}" != "/Library/Ossec" ]; then
        echo "$(date +"%Y/%m/%d %H:%M:%S") - Execution path is wrong (it should be /Library/Ossec), interrupting upgrade." >> ./logs/upgrade.log
        echo -ne "2" > ./var/upgrade/upgrade_result
        rm -f $LOCK
        exit 1
    fi
elif [[ "$OS" == "Linux" ]]; then
    if [ "${WAZUH_HOME}" != "/var/ossec" ]; then
        echo "$(date +"%Y/%m/%d %H:%M:%S") - Execution path is wrong (it should be /var/ossec), interrupting upgrade." >> ./logs/upgrade.log
        echo -ne "2" > ./var/upgrade/upgrade_result
        rm -f $LOCK
        exit 1
    fi
else
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Upgrade failed. Unsupported OS." >> ./logs/upgrade.log
    echo -ne "2" > ./var/upgrade/upgrade_result
    rm -f $LOCK
    exit 1
fi

if [[ "$OS" == "Darwin" ]]; then
    installer -pkg ./var/upgrade/wazuh-agent* -target / >> ./logs/upgrade.log 2>&1
elif [[ "$OS" == "Linux" ]]; then
    if find ./var/upgrade/ -mindepth 1 -maxdepth 1 -type f -name "*.rpm" | read; then
        if command -v rpm >/dev/null 2>&1; then
            rpm -UFvh ./var/upgrade/wazuh-agent* >> ./logs/upgrade.log 2>&1
        else
            echo "$(date +"%Y/%m/%d %H:%M:%S") - Upgrade failed. RPM package found but rpm command not found." >> ./logs/upgrade.log
            echo -ne "2" > ./var/upgrade/upgrade_result
            rm -f $LOCK
            exit 1
        fi
    elif find ./var/upgrade/ -mindepth 1 -maxdepth 1 -type f -name "*.deb" | read; then
        if command -v dpkg >/dev/null 2>&1; then
            dpkg -i --force-confdef ./var/upgrade/wazuh-agent* >> ./logs/upgrade.log 2>&1
        else
            echo "$(date +"%Y/%m/%d %H:%M:%S") - Upgrade failed. DEB package found but dpkg command not found." >> ./logs/upgrade.log
            echo -ne "2" > ./var/upgrade/upgrade_result
            rm -f $LOCK
            exit 1
        fi
    elif find ./var/upgrade/ -mindepth 1 -maxdepth 1 -type f -name "*.apk" | read; then
        if command -v apk >/dev/null 2>&1; then
            apk add --allow-untrusted --force ./var/upgrade/wazuh-agent* >> ./logs/upgrade.log 2>&1
        else
            echo "$(date +"%Y/%m/%d %H:%M:%S") - Upgrade failed. APK package found but apk command not found." >> ./logs/upgrade.log
            echo -ne "2" > ./var/upgrade/upgrade_result
            rm -f $LOCK
            exit 1
        fi
    else
        if [ -e ./var/upgrade/install.sh ]; then
            chmod +x ./var/upgrade/install.sh
            ./var/upgrade/install.sh >> ./logs/upgrade.log 2>&1
        else
            echo "$(date +"%Y/%m/%d %H:%M:%S") - Upgrade failed. No package or sources found." >> ./logs/upgrade.log
            echo -ne "2" > ./var/upgrade/upgrade_result
            rm -f $LOCK
            exit 1
        fi
    fi
else
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Upgrade failed. Unsupported OS." >> ./logs/upgrade.log
    echo -ne "2" > ./var/upgrade/upgrade_result
    rm -f $LOCK
    exit 1
fi


# Check installation result
RESULT=$?
echo "$(date +"%Y/%m/%d %H:%M:%S") - Installation result = ${RESULT}" >> ./logs/upgrade.log

# Restart Agent
echo "$(date +"%Y/%m/%d %H:%M:%S") - Checking for Wazuh Agent control script." >> ./logs/upgrade.log

if [ -f "./bin/wazuh-control" ]; then
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Restarting Wazuh Agent." >> ./logs/upgrade.log
    ./bin/wazuh-control restart >> ./logs/upgrade.log 2>&1
elif [ -f "./bin/ossec-control" ]; then
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Upgrade failed: wazuh-control not found. Attempting to restart using ossec-control." >> ./logs/upgrade.log
    ./bin/ossec-control restart >> ./logs/upgrade.log 2>&1
    echo -ne "2" > ./var/upgrade/upgrade_result
    rm -f $LOCK
    exit 1
else
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Upgrade failed: Neither wazuh-control nor ossec-control were found." >> ./logs/upgrade.log
    echo -ne "2" > ./var/upgrade/upgrade_result
    rm -f $LOCK
    exit 1
fi

sleep 1


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

rm -f $LOCK

exit 0
