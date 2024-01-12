#!/bin/bash
# Copyright (C) 2015, Wazuh Inc.

SERVICE=wazuh-agent
OSSEC_INIT_FILE=/etc/ossec-init.conf
WAZUH_HOME=$(pwd)
if [ "${WAZUH_HOME}" = "/" ]; then
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

WAZUH_REVISION=0
OSSEC_LIST_FILES=""
RESTORE_OSSEC_OWN=0
SYSTEMD_SERVICE_UNIT_PATH=""
INIT_PATH=""

# Create the ossec user and group if they don't exist
function create_ossec_ug {

    exists_group=$(getent group ossec)  2>/dev/null; [ -z "${exists_group}" ] && exists_group=$(id -g ossec 2>/dev/null);
    # Create the ossec group if it doesn't exist
    if [ -z "${exists_group}" ]; then
            echo "$(date +"%Y/%m/%d %H:%M:%S") - Restoring ossec group." >> ./logs/upgrade.log

            if command -v addgroup >/dev/null 2>&1 && command -v dpkg >/dev/null 2>&1; then
                addgroup --system ossec >> ./logs/upgrade.log 2>&1
            else
                groupadd -r ossec >> ./logs/upgrade.log 2>&1
            fi
    fi

    exists_user=$(getent passwd ossec)  2>/dev/null; [ -z "${exists_user}" ] && exists_user=$(id -u ossec 2>/dev/null);
    # Create the ossec user if it doesn't exist
    if [ -z "${exists_user}" ]; then
            echo "$(date +"%Y/%m/%d %H:%M:%S") - Restoring ossec user." >> ./logs/upgrade.log

            NO_SHELL=/sbin/nologin
            if [ ! -f ${NO_SHELL} ]; then
                if [ -f "/bin/false" ]; then
                    NO_SHELL="/bin/false"
                fi
            fi

            if command -v adduser >/dev/null 2>&1 && command -v dpkg >/dev/null 2>&1; then
                adduser --system --home "${WAZUH_HOME}" --shell ${NO_SHELL} --ingroup ossec ossec >> ./logs/upgrade.log 2>&1
            else
                useradd -g ossec -G ossec -d "${WAZUH_HOME}" -r -s ${NO_SHELL} ossec >> ./logs/upgrade.log 2>&1
            fi
    fi

}

# Restore the ownerwhip of the files according to the stored ownership list
function restore_ossec_ownership {
        while read -r line; do
            TFILE_OWN=$(echo $line | cut -d " " -f -1)
            TFILE_PATH=$(echo $line | cut -d " " -f 2-)
            chown $TFILE_OWN "${TFILE_PATH}"
        done <<< "$OSSEC_LIST_FILES"

        # If the list is not empty, then it is assumed that the version to restore is lower than 4.3
        if [ -n "${OSSEC_LIST_FILES}" ]; then
            # If there are files with the group or user wazuh, then they are changed to ossec.
            find ./ -group wazuh -exec chgrp ossec {} \;
            find ./ -user wazuh -exec chown ossec {} \;
            # Delete user and group
            if command -v deluser > /dev/null 2>&1; then
               deluser wazuh > /dev/null 2>&1
            else
               userdel wazuh > /dev/null 2>&1
            fi
            # Delete user and group
            if command -v delgroup > /dev/null 2>&1; then
               delgroup wazuh > /dev/null 2>&1
            else
               groupdel wazuh >/dev/null 2>&1
            fi
        fi
}

# Restore SELinuxPolicy
function restore_selinux_policy {
    if command -v semodule > /dev/null && command -v getenforce > /dev/null; then
        if [ $(getenforce) != "Disabled" ]; then
            if [ -f ./var/selinux/wazuh.pp ]; then
                echo "$(date +"%Y/%m/%d %H:%M:%S") - Restoring SELinux policy." >> ./logs/upgrade.log
                semodule -i ./var/selinux/wazuh.pp >> ./logs/upgrade.log 2>&1
                semodule -e wazuh >> ./logs/upgrade.log 2>&1
            else
                echo "$(date +"%Y/%m/%d %H:%M:%S") - ERROR: Wazuh SELinux module not found." >> ./logs/upgrade.log
            fi
        else
            echo "$(date +"%Y/%m/%d %H:%M:%S") - Wazuh SELinux module installation skipped (SELinux is disabled)." >> ./logs/upgrade.log
        fi
    fi
}

# Search for Agent version
# Agent >= 4.2
eval $(./bin/wazuh-control info 2>/dev/null)
if [ -z "${WAZUH_REVISION}" ] ; then
    # Agent < 4.2
    REVISION=""
    source $OSSEC_INIT_FILE
    if [ -n "${REVISION}" ] ; then
        WAZUH_REVISION="${REVISION}"
    fi
fi

# Check if systemd is used
# RHEL 8 >= services must must be installed in /usr/lib/systemd/system/
if [ -f /usr/lib/systemd/system/${SERVICE}.service ] && [ ! -h /usr/lib/systemd/system ]; then
    SYSTEMD_SERVICE_UNIT_PATH=/usr/lib/systemd/system/${SERVICE}.service
fi
# Others
if [ -f /etc/systemd/system/${SERVICE}.service ] && [ ! -h /etc/systemd/system ]; then
    SYSTEMD_SERVICE_UNIT_PATH=/etc/systemd/system/${SERVICE}.service
fi

# Init backup
# REHL <= 6 / Amazon linux
if [ -f "/etc/rc.d/init.d/${SERVICE}" ] && [ ! -h /etc/rc.d/init.d ]; then
    INIT_PATH="/etc/rc.d/init.d/${SERVICE}"
fi

if [ -f "/etc/init.d/${SERVICE}" ] && [ ! -h /etc/init.d ]; then
    INIT_PATH="/etc/init.d/${SERVICE}"
fi

# Generate Backup
BDATE=$(date +"%m-%d-%Y_%H-%M-%S")
mkdir -p ./backup

echo "$(date +"%Y/%m/%d %H:%M:%S") - Generating Backup." >> ./logs/upgrade.log

FOLDERS_TO_BACKUP=($WAZUH_HOME/{active-response,bin,etc,lib,queue,ruleset,wodles,agentless,logs/{ossec,wazuh},var/selinux} \
                   $OSSEC_INIT_FILE \
                   $SYSTEMD_SERVICE_UNIT_PATH \
                   $INIT_PATH)
FOLDERS_TO_EXCLUDE=($WAZUH_HOME/queue/diff)
EXCLUDE_ARGUMENT="$(for i in ${FOLDERS_TO_EXCLUDE[@]}; do echo -n "--exclude $i "; done)"

for i in ${FOLDERS_TO_BACKUP[@]}
do
    [ -e $i ] && echo $i
done | xargs tar -C / $EXCLUDE_ARGUMENT -zcvf ./backup/backup_[${BDATE}].tar.gz >> ./logs/upgrade.log 2>&1

# Check Backup creation
RESULT=$?

if [ $RESULT -eq 0 ]; then
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Backup generated in ${WAZUH_HOME}/backup/backup_[${BDATE}].tar.gz" >> ./logs/upgrade.log
else
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Error creating the Backup, interrupting upgrade." >> ./logs/upgrade.log
    rm -rf ./backup/backup_[${BDATE}].tar.gz
    exit 1
fi

# If necessary, the list of files is saved with the ossec ownership (Agent < 4.3)
if [ "${WAZUH_REVISION}" -lt "40300" ]; then
    RESTORE_OSSEC_OWN=1
    OSSEC_LIST_FILES=$(find ./ -printf '%u:%g ./%P\n' | grep ':ossec\|^ossec')
fi

# Installing upgrade
echo "$(date +"%Y/%m/%d %H:%M:%S") - Upgrade started." >> ./logs/upgrade.log
chmod +x ./var/upgrade/install.sh
./var/upgrade/install.sh >> ./logs/upgrade.log 2>&1

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
    if [ ! -f $CONTROL ]; then
        CONTROL="./bin/ossec-control"
    fi
    $CONTROL stop >> ./logs/upgrade.log 2>&1

    echo "$(date +"%Y/%m/%d %H:%M:%S") - Deleting upgrade files..." >> ./logs/upgrade.log
    for dir in "${FOLDERS_TO_BACKUP[@]}"; do
        rm -rf "${dir}" >> ./logs/upgrade.log 2>&1
    done

    # Cleaning for old versions
    [ -d "./ruleset" ] && rm -rf ./ruleset

    # Clean systemd unit service
    if [ -f /etc/systemd/system/${SERVICE}.service ]; then
        rm -f /etc/systemd/system/${SERVICE}.service
    fi
    if [ -f /usr/lib/systemd/system/${SERVICE}.service ]; then
        rm -f /usr/lib/systemd/system/${SERVICE}.service
    fi

    # Create user and group ossec, if appropriate
    if [ $RESTORE_OSSEC_OWN -eq 1 ]; then
        create_ossec_ug
    fi

    # Restore backup
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Restoring backup...." >> ./logs/upgrade.log
    tar -xvf ./backup/backup_[${BDATE}].tar.gz -C / >> ./logs/upgrade.log 2>&1
    RESULT=$?

    if [ $RESULT -ne 0 ]; then
        echo "$(date +"%Y/%m/%d %H:%M:%S") - Error uncompressing the Backup, it has not been possible to restore the installation." >> ./logs/upgrade.log
        exit 1
    fi

    # Restore diff folder
    install -d -m 0750 -o wazuh -g wazuh $WAZUH_HOME/queue/diff

    # Assign the ossec ownership, if appropriate
    if [ $RESTORE_OSSEC_OWN -eq 1 ]; then
        restore_ossec_ownership
    fi

    # Restore SELinux policy
    restore_selinux_policy

    echo -ne "2" > ./var/upgrade/upgrade_result

    # Restore service
    if [ -n "${INIT_PATH}" ]; then
        chk=$(which chkconfig)
        if [ -n "$chk" ]; then
            /sbin/chkconfig --add ${SERVICE} >> ./logs/upgrade.log 2>&1
        fi
        systemctl enable ${SERVICE} >> ./logs/upgrade.log 2>&1
    fi

    if [ -n "${SYSTEMD_SERVICE_UNIT_PATH}" ]; then
        systemctl daemon-reload >> ./logs/upgrade.log 2>&1
    fi

    CONTROL="./bin/wazuh-control"
    if [ ! -f $CONTROL ]; then
        CONTROL="./bin/ossec-control"
    fi

    $CONTROL start >> ./logs/upgrade.log 2>&1
fi

exit 0
