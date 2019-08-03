#!/bin/bash

# Copyright (C) 2015-2019, Wazuh Inc.

. /etc/ossec-init.conf

# Generating Backup
BDATE=$(date +"%m-%d-%Y_%H-%M-%S")

echo "$(date +"%Y/%m/%d %H:%M:%S") - Generating Backup." > ${DIRECTORY}/logs/upgrade.log
mkdir -p ${DIRECTORY}/tmp_bkp/${DIRECTORY}/bin
mkdir -p ${DIRECTORY}/tmp_bkp/${DIRECTORY}/etc
mkdir -p ${DIRECTORY}/tmp_bkp/etc

cp -rp ${DIRECTORY}/bin ${DIRECTORY}/tmp_bkp/${DIRECTORY}
cp -rp ${DIRECTORY}/etc ${DIRECTORY}/tmp_bkp/${DIRECTORY}
cp -p /etc/ossec-init.conf ${DIRECTORY}/tmp_bkp/etc

tar czf ${DIRECTORY}/backup/backup_${VERSION}_[${BDATE}].tar.gz -C ${DIRECTORY}/tmp_bkp . >> ${DIRECTORY}/logs/upgrade.log 2>&1
rm -rf ${DIRECTORY}/tmp_bkp

# Installing upgrade
echo "$(date +"%Y/%m/%d %H:%M:%S") - Upgrade started." >> ${DIRECTORY}/logs/upgrade.log
chmod +x ${DIRECTORY}/var/upgrade/install.sh
${DIRECTORY}/var/upgrade/install.sh >> ${DIRECTORY}/logs/upgrade.log 2>&1

# Check installation result
RESULT=$?
echo "$(date +"%Y/%m/%d %H:%M:%S") - Installation result = ${RESULT}" >> ${DIRECTORY}/logs/upgrade.log

# Wait connection
status="pending"
COUNTER=30
while [ "$status" != "connected" -a $COUNTER -gt 0  ]; do
    . ${DIRECTORY}/var/run/ossec-agentd.state >> ${DIRECTORY}/logs/upgrade.log 2>&1
    sleep 1
    COUNTER=$[COUNTER - 1]
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Waiting connection... Status = "${status}". Remaining attempts: ${COUNTER}." >> ${DIRECTORY}/logs/upgrade.log
done

# Check connection
if [ "$status" = "connected" -a $RESULT -eq 0  ]; then
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Connected to manager." >> ${DIRECTORY}/logs/upgrade.log
    echo -ne "0" > ${DIRECTORY}/var/upgrade/upgrade_result
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Upgrade finished successfully." >> ${DIRECTORY}/logs/upgrade.log
else
    # Restoring backup
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Upgrade failed. Restoring..." >> ${DIRECTORY}/logs/upgrade.log
    ${DIRECTORY}/bin/ossec-control stop >> ${DIRECTORY}/logs/upgrade.log 2>&1
    tar xzf ${DIRECTORY}/backup/backup_${VERSION}_[${BDATE}].tar.gz -C / >> ${DIRECTORY}/logs/upgrade.log 2>&1
    echo -ne "2" > ${DIRECTORY}/var/upgrade/upgrade_result
    ${DIRECTORY}/bin/ossec-control start >> ${DIRECTORY}/logs/upgrade.log 2>&1
fi
