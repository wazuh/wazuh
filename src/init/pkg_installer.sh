#!/bin/bash

. /etc/ossec-init.conf

# Generating Backup
BDATE=$(date +"%m-%d-%Y_%H-%M-%S")

mkdir -p ${DIRECTORY}/tmp_bkp/${DIRECTORY}/bin
mkdir -p ${DIRECTORY}/tmp_bkp/${DIRECTORY}/etc
mkdir -p ${DIRECTORY}/tmp_bkp/etc

cp -R ${DIRECTORY}/bin ${DIRECTORY}/tmp_bkp/${DIRECTORY}
cp -R ${DIRECTORY}/etc ${DIRECTORY}/tmp_bkp/${DIRECTORY}
cp /etc/ossec-init.conf ${DIRECTORY}/tmp_bkp/etc

tar -zcpf ${DIRECTORY}/backup/backup_${VERSION}_[${BDATE}].tar.gz -C ${DIRECTORY}/tmp_bkp .
rm -rf ${DIRECTORY}/tmp_bkp

# Installing upgrade
echo "UPGRADE DATE: ${BDATE}" > ${DIRECTORY}/logs/upgrade.log
chmod +x ${DIRECTORY}/var/upgrade/install.sh
${DIRECTORY}/var/upgrade/install.sh >> ${DIRECTORY}/logs/upgrade.log 2>&1

# Check upgrade result
STATUS=$?
echo -ne $STATUS > ${DIRECTORY}/var/upgrade/upgrade_result

if [ ! $STATUS = 0 ]; then
    ${DIRECTORY}/bin/ossec-control stop
    tar --same-owner zxf ${DIRECTORY}/backup/backup_${VERSION}_[${BDATE}].tar.gz -C /
    echo -ne " 2" >> ${DIRECTORY}/var/upgrade/upgrade_result
    ${DIRECTORY}/bin/ossec-control start
fi
