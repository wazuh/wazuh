#!/bin/bash

. /etc/ossec-init.conf

# Generating Backup
bdate=$(date +"%m-%d-%Y_%H-%M-%S")

mkdir ${DIRECTORY}/ossec
if [ ! -d ${DIRECTORY}/backup ]; then
    mkdir ${DIRECTORY}/backup
fi
cp -R ${DIRECTORY}/bin ${DIRECTORY}/ossec
cp -R ${DIRECTORY}/etc ${DIRECTORY}/ossec
tar -zcf ${DIRECTORY}/backup/backup_${VERSION}_[${bdate}].tar.gz ${DIRECTORY}/ossec
rm -rf ${DIRECTORY}/ossec

# Installing upgrade

echo "UPGRADE DATE: ${bdate}" > ${DIRECTORY}/var/incoming/upgrade.log
${DIRECTORY}/var/incoming/wazuh_pkg/install.sh >> ${DIRECTORY}/var/incoming/upgrade.log
echo $? > ${DIRECTORY}/var/run/upgrade_result
