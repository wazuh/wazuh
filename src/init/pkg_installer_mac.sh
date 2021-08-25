#!/bin/bash

# Copyright (C) 2015-2021, Wazuh Inc.

WAZUH_HOME=${1}
WAZUH_VERSION=${2}

SERVICE=wazuh-agent
# Generating Backup
TMP_DIR_BACKUP=${WAZUH_HOME}/tmp_bkp
rm -rf ${WAZUH_HOME}/tmp_bkp/

BDATE=$(date +"%m-%d-%Y_%H-%M-%S")
declare -a FOLDERS_TO_BACKUP

echo "$(date +"%Y/%m/%d %H:%M:%S") - Generating Backup." > "${WAZUH_HOME}/logs/upgrade.log"

# Generate wazuh home directory tree to backup
FOLDERS_TO_BACKUP+=(${WAZUH_HOME}/active-response)
FOLDERS_TO_BACKUP+=(${WAZUH_HOME}/bin)
FOLDERS_TO_BACKUP+=(${WAZUH_HOME}/etc)
FOLDERS_TO_BACKUP+=(${WAZUH_HOME}/lib)
FOLDERS_TO_BACKUP+=(${WAZUH_HOME}/queue)
[ -d "${WAZUH_HOME}/ruleset" ] && FOLDERS_TO_BACKUP+=(${WAZUH_HOME}/ruleset)
[ -d "${WAZUH_HOME}/wodles" ] && FOLDERS_TO_BACKUP+=(${WAZUH_HOME}/wodles)
[ -d "${WAZUH_HOME}/agentless" ] && FOLDERS_TO_BACKUP+=(${WAZUH_HOME}/agentless)
[ -d "${WAZUH_HOME}/logs/ossec" ] && FOLDERS_TO_BACKUP+=(${WAZUH_HOME}/logs/ossec)
[ -d "${WAZUH_HOME}/var/selinux" ] && FOLDERS_TO_BACKUP+=(${WAZUH_HOME}/var/selinux)

for dir in "${FOLDERS_TO_BACKUP[@]}"; do
    mkdir -p "${TMP_DIR_BACKUP}${dir}"
    cp -a ${dir}/* "${TMP_DIR_BACKUP}${dir}"
done

if [ -f /etc/ossec-init.conf ]; then
    mkdir -p "${WAZUH_HOME}/tmp_bkp/etc"
    cp -p /etc/ossec-init.conf "${WAZUH_HOME}/tmp_bkp/etc"
fi

# Save service file.
# TODO: Check permissions?
mkdir -p "${TMP_DIR_BACKUP}/Library/LaunchDaemons"
cp -a /Library/LaunchDaemons/com.wazuh.agent.plist "${TMP_DIR_BACKUP}/Library/LaunchDaemons"


# Saves modes and owners of the directories
BACKUP_LIST_FILES=$(find "${TMP_DIR_BACKUP}/" -type d)

while read -r line; do
    org=$(echo "${line}" | awk "sub(\"${TMP_DIR_BACKUP}\",\"\")")
    chown --reference=$org $line
    chmod --reference=$org $line
done <<< "$BACKUP_LIST_FILES"

# Generate Backup
tar czf "${WAZUH_HOME}/backup/backup_${WAZUH_VERSION}_[${BDATE}].tar.gz" -C "${WAZUH_HOME}/tmp_bkp" . >>"${WAZUH_HOME}/logs/upgrade.log" 2>&1
rm -rf ${WAZUH_HOME}/tmp_bkp/

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
while [ "$status" != "connected" -a $COUNTER -gt 0 ]; do
    . ${WAZUH_HOME}/var/run/wazuh-agentd.state >> ${WAZUH_HOME}/logs/upgrade.log 2>&1
    sleep 1
    COUNTER=$[COUNTER - 1]
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Waiting connection... Status = "${status}". Remaining attempts: ${COUNTER}." >>${WAZUH_HOME}/logs/upgrade.log
done

# Check connection
if [ "$status" = "connected" -a $RESULT -eq 0 ]; then
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Connected to manager." >> ${WAZUH_HOME}/logs/upgrade.log
    echo -ne "0" >${WAZUH_HOME}/var/upgrade/upgrade_result
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Upgrade finished successfully." >> ${WAZUH_HOME}/logs/upgrade.log
else
    # Restore backup
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Upgrade failed. Restoring..." >> ${WAZUH_HOME}/logs/upgrade.log

    # Cleanup before restore
    CONTROL="$WAZUH_HOME/bin/wazuh-control"
    if [ ! -f $CONTROL ]; then
        CONTROL="$WAZUH_HOME/bin/ossec-control"
    fi
    $CONTROL stop >>${WAZUH_HOME}/logs/upgrade.log 2>&1

    echo "$(date +"%Y/%m/%d %H:%M:%S") - Deleting upgrade files..." >> ${WAZUH_HOME}/logs/upgrade.log
    for dir in ${FOLDERS_TO_BACKUP[@]}; do
        rm -rf ${dir} >> ${WAZUH_HOME}/logs/upgrade.log 2>&1
    done

    # Cleaning for old versions
    [ -d "${WAZUH_HOME}/ruleset" ] && rm -rf ${WAZUH_HOME}/ruleset

    # Clean service
    /bin/launchctl unload /Library/LaunchDaemons/com.wazuh.agent.plist >> ${WAZUH_HOME}/logs/upgrade.log 2>&1
    rm -rf /Library/LaunchDaemons/com.wazuh.agent.plist >> ${WAZUH_HOME}/logs/upgrade.log 2>&1

    # Restore backup
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Restoring backup...."
    tar xzf ${WAZUH_HOME}/backup/backup_${WAZUH_VERSION}_[${BDATE}].tar.gz -C / >> ${WAZUH_HOME}/logs/upgrade.log 2>&1

    echo -ne "2" >${WAZUH_HOME}/var/upgrade/upgrade_result

    # Restore service
    cp -a "${TMP_DIR_BACKUP}/Library/LaunchDaemons" /Library/LaunchDaemons/com.wazuh.agent.plist  >> ${WAZUH_HOME}/logs/upgrade.log 2>&1
    /bin/launchctl load /Library/LaunchDaemons/com.wazuh.agent.plist >> ${WAZUH_HOME}/logs/upgrade.log 2>&1

    CONTROL="$WAZUH_HOME/bin/wazuh-control"
    if [ ! -f $CONTROL ]; then
        CONTROL="$WAZUH_HOME/bin/ossec-control"
    fi

    $CONTROL start >>${WAZUH_HOME}/logs/upgrade.log 2>&1
fi
