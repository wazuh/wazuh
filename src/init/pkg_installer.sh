#!/bin/bash

# Copyright (C) 2015-2020, Wazuh Inc.

WAZUH_HOME=${1}
WAZUH_VERSION=${2} 

# Generating Backup
BDATE=$(date +"%m-%d-%Y_%H-%M-%S")

echo "$(date +"%Y/%m/%d %H:%M:%S") - Generating Backup." > ${WAZUH_HOME}/logs/upgrade.log
mkdir -p ${WAZUH_HOME}/tmp_bkp/${WAZUH_HOME}/bin
mkdir -p ${WAZUH_HOME}/tmp_bkp/${WAZUH_HOME}/etc
mkdir -p ${WAZUH_HOME}/tmp_bkp/etc

cp -rp ${WAZUH_HOME}/bin ${WAZUH_HOME}/tmp_bkp/${WAZUH_HOME}
cp -rp ${WAZUH_HOME}/etc ${WAZUH_HOME}/tmp_bkp/${WAZUH_HOME}
cp -p /etc/ossec-init.conf ${WAZUH_HOME}/tmp_bkp/etc

tar czf ${WAZUH_HOME}/backup/backup_${WAZUH_VERSION}_[${BDATE}].tar.gz -C ${WAZUH_HOME}/tmp_bkp . >> ${WAZUH_HOME}/logs/upgrade.log 2>&1
rm -rf ${WAZUH_HOME}/tmp_bkp

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
    # Restoring backup
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Upgrade failed. Restoring..." >> ${WAZUH_HOME}/logs/upgrade.log
    ${WAZUH_HOME}/bin/ossec-control stop >> ${WAZUH_HOME}/logs/upgrade.log 2>&1
    tar xzf ${WAZUH_HOME}/backup/backup_${WAZUH_VERSION}_[${BDATE}].tar.gz -C / >> ${WAZUH_HOME}/logs/upgrade.log 2>&1
    echo -ne "2" > ${WAZUH_HOME}/var/upgrade/upgrade_result
    ${WAZUH_HOME}/bin/ossec-control start >> ${WAZUH_HOME}/logs/upgrade.log 2>&1
fi
