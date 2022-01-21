#!/bin/bash

# Copyright (C) 2015, Wazuh Inc.

# Generating Backup
CURRENT_DIR=`pwd`
TMP_DIR_BACKUP=./tmp_bkp
rm -rf ./tmp_bkp/

BDATE=$(date +"%m-%d-%Y_%H-%M-%S")
declare -a FOLDERS_TO_BACKUP

echo "$(date +"%Y/%m/%d %H:%M:%S") - Generating Backup." >> ./logs/upgrade.log

# Generate wazuh home directory tree to backup
FOLDERS_TO_BACKUP+=(${CURRENT_DIR}/active-response)
FOLDERS_TO_BACKUP+=(${CURRENT_DIR}/bin)
FOLDERS_TO_BACKUP+=(${CURRENT_DIR}/etc)
FOLDERS_TO_BACKUP+=(${CURRENT_DIR}/lib)
FOLDERS_TO_BACKUP+=(${CURRENT_DIR}/queue)
[ -d "./ruleset" ] && FOLDERS_TO_BACKUP+=(${CURRENT_DIR}/ruleset)
[ -d "./wodles" ] && FOLDERS_TO_BACKUP+=(${CURRENT_DIR}/wodles)
[ -d "./agentless" ] && FOLDERS_TO_BACKUP+=(${CURRENT_DIR}/agentless)
[ -d "./logs/ossec" ] && FOLDERS_TO_BACKUP+=(${CURRENT_DIR}/logs/ossec)
[ -d "./var/selinux" ] && FOLDERS_TO_BACKUP+=(${CURRENT_DIR}/var/selinux)

for dir in "${FOLDERS_TO_BACKUP[@]}"; do
    mkdir -p "${TMP_DIR_BACKUP}${dir}"
    cp -a ${dir}/* "${TMP_DIR_BACKUP}${dir}"
done

# Save service file
mkdir -p "${TMP_DIR_BACKUP}/Library/LaunchDaemons"
cp -a /Library/LaunchDaemons/com.wazuh.agent.plist "${TMP_DIR_BACKUP}/Library/LaunchDaemons"

mkdir -p "${TMP_DIR_BACKUP}/Library/StartupItems/WAZUH"
cp -a /Library/StartupItems/WAZUH/* ${TMP_DIR_BACKUP}/Library/StartupItems/WAZUH

# Saves modes and owners of the directories
BACKUP_LIST_FILES=$(find "${TMP_DIR_BACKUP}/" -type d)

while read -r line; do
    org=$(echo "${line}" | awk "sub(\"${TMP_DIR_BACKUP}\",\"\")")
    owner=$(stat -f %Su ${org})
    group=$(stat -f %Sg ${org})
    mode=$(stat -f %A ${org})
    chown $owner:$group $line
    chmod $mode $line
done <<< "$BACKUP_LIST_FILES"

# Generate Backup
mkdir -p ./backup
tar czf ./backup/backup_[${BDATE}].tar.gz -C ./tmp_bkp . >> ./logs/upgrade.log 2>&1
rm -rf ./tmp_bkp/

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
    sleep 1
    COUNTER=$[COUNTER - 1]
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Waiting connection... Status = "${status}". Remaining attempts: ${COUNTER}." >> ./logs/upgrade.log
done

# Check connection
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
    for dir in ${FOLDERS_TO_BACKUP[@]}; do
        rm -rf ${dir} >> ./logs/upgrade.log 2>&1
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
    tar xzf ./backup/backup_[${BDATE}].tar.gz -C ./backup/restore >> ./logs/upgrade.log 2>&1

    for dir in ./backup/restore/*; do
        cp -a ${dir}/* /$(basename ${dir}) >> ./logs/upgrade.log 2>&1
    done

    rm -rf ./backup/restore

    echo -ne "2" > ./var/upgrade/upgrade_result

    # Restore service
    /bin/launchctl load /Library/LaunchDaemons/com.wazuh.agent.plist >> ./logs/upgrade.log 2>&1

    $CONTROL start >> ./logs/upgrade.log 2>&1
fi
