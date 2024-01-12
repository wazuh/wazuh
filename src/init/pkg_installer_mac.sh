#!/bin/bash
# Copyright (C) 2015, Wazuh Inc.

CURRENT_DIR=`pwd`
if [ "${CURRENT_DIR}" = "/" ]; then
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Execution path is wrong, interrupting upgrade." >> ./logs/upgrade.log
    exit 1
fi

# Check if there is an upgrade in progress
declare -a BACKUP_FOLDERS
[ -d "./backup" ] && BACKUP_FOLDERS+=("./backup")
for dir in "${BACKUP_FOLDERS[@]}"; do
    ATTEMPTS=5
    while [ $ATTEMPTS -gt 0 ]; do
        sleep 10
        ATTEMPTS=$[ATTEMPTS - 1]
        if [[ $("find" "${dir}" "-cmin" "-1") ]]; then
            echo "$(date +"%Y/%m/%d %H:%M:%S") - There is an upgrade in progress. Aborting..." >> ./logs/upgrade.log
            exit 1
        fi
    done
done

# Generate Backup
BDATE=$(date +"%m-%d-%Y_%H-%M-%S")
mkdir -p ./backup

echo "$(date +"%Y/%m/%d %H:%M:%S") - Generating Backup." >> ./logs/upgrade.log

FOLDERS_TO_BACKUP=($CURRENT_DIR/{active-response,bin,etc,lib,queue,ruleset,wodles,agentless,logs/{ossec,wazuh},var/selinux} \
                   /Library/LaunchDaemons/com.wazuh.agent.plist \
                   /Library/StartupItems/WAZUH)
FOLDERS_TO_EXCLUDE=($CURRENT_DIR/queue/diff)
EXCLUDE_ARGUMENT="$(for i in ${FOLDERS_TO_EXCLUDE[@]}; do echo -n "--exclude $i "; done)"

for i in ${FOLDERS_TO_BACKUP[@]}
do
    [ -e $i ] && echo $i
done | xargs tar -C / $EXCLUDE_ARGUMENT -zcvf ./backup/backup_[${BDATE}].tar.gz >> ./logs/upgrade.log 2>&1

# Check Backup creation
RESULT=$?

if [ $RESULT -eq 0 ]; then
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Backup generated in ${CURRENT_DIR}/backup/backup_[${BDATE}].tar.gz" >> ./logs/upgrade.log
else
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Error creating the Backup, interrupting upgrade." >> ./logs/upgrade.log
    rm -rf ./backup/backup_[${BDATE}].tar.gz
    exit 1
fi

# Installing upgrade
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

# Check connection
status="pending"
if [ "$status" = "connected" -a $RESULT -eq 0 ]; then
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Connected to manager." >> ./logs/upgrade.log
    echo -ne "0" > ./var/upgrade/upgrade_result
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Upgrade finished successfully." >> ./logs/upgrade.log
else
    # Restore backup
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Upgrade failed. Restoring..." >> ./logs/upgrade.log

    # Cleanup before restore
    CONTROL="./bin/wazuh-control"
    $CONTROL stop >> ./logs/upgrade.log 2>&1

    echo "$(date +"%Y/%m/%d %H:%M:%S") - Deleting upgrade files..." >> ./logs/upgrade.log
    for dir in "${FOLDERS_TO_BACKUP[@]}"; do
        rm -rf "${dir}" >> ./logs/upgrade.log 2>&1
    done

    # Cleaning for old versions
    [ -d "./ruleset" ] && rm -rf ./ruleset

    # Clean service
    /bin/launchctl unload /Library/LaunchDaemons/com.wazuh.agent.plist >> ./logs/upgrade.log 2>&1
    rm -rf /Library/LaunchDaemons/com.wazuh.agent.plist >> ./logs/upgrade.log 2>&1
    rm -rf /Library/StartupItems/WAZUH/ >> ./logs/upgrade.log 2>&1

    # Restore backup
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Restoring backup...." >> ./logs/upgrade.log
    rm -rf ./backup/restore
    mkdir -p ./backup/restore
    tar -xvf ./backup/backup_[${BDATE}].tar.gz -C ./backup/restore >> ./logs/upgrade.log 2>&1
    RESULT=$?

    if [ $RESULT -eq 0 ] && [ "$(ls -A ./backup/restore/)" ]; then
        for dir in ./backup/restore/*; do
            cp -a ${dir}/* /$(basename ${dir}) >> ./logs/upgrade.log 2>&1
        done
    else
        echo "$(date +"%Y/%m/%d %H:%M:%S") - Error uncompressing the Backup, it has not been possible to restore the installation." >> ./logs/upgrade.log
        rm -rf ./backup/restore
        exit 1
    fi

    rm -rf ./backup/restore

    # Restore diff folder
    install -d -m 0750 -o wazuh -g wazuh $CURRENT_DIR/queue/diff

    echo -ne "2" > ./var/upgrade/upgrade_result

    # Restore service
    /bin/launchctl load /Library/LaunchDaemons/com.wazuh.agent.plist >> ./logs/upgrade.log 2>&1

    $CONTROL start >> ./logs/upgrade.log 2>&1
fi

exit 0
