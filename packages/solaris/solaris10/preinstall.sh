#!/bin/sh
# preinstall script for wazuh-agent
# Wazuh, Inc 2015

if [ ! -f /etc/ossec-init.conf ]; then
    DIR="/var/ossec"
    ls -la /var/ossec > /dev/null 2>&1
    if [ -d /var/ossec ]; then
        #upgrade
        type=upgrade
    else
        #clean installation
        type=install
    fi
else
    #upgrade
    DIR=`cat $INSTALLATION_FILE | grep DIRECTORY | cut -d'=' -f2 | cut -d'"' -f2`
    type=upgrade
fi

USER="wazuh"
GROUP="wazuh"
OSSEC_HIDS_TMP_DIR="/tmp/wazuh-agent"
OSMYSHELL="/sbin/nologin"

# environment configuration
if [ ! -d ${OSSEC_HIDS_TMP_DIR} ]; then
    mkdir ${OSSEC_HIDS_TMP_DIR}
fi

if [ ! -f ${OSMYSHELL} ]; then
    if [ -f "/bin/false" ]; then
        OSMYSHELL="/bin/false"
    fi
fi

getent group wazuh > /dev/null 2>&1
if [ "$?" -ne 0 ]; then
    groupadd ${GROUP}
fi

getent passwd wazuh > /dev/null 2>&1
if [ "$?" -ne 0 ]; then
    useradd -d ${DIR} -s ${OSMYSHELL} -g ${GROUP} ${USER} > /dev/null 2>&1
fi

case $type in
    upgrade)

    if [ -d "$DIR" ]; then
        if [ -f ${DIR}/etc/ossec.conf ]; then
            cp  ${DIR}/etc/ossec.conf  ${DIR}/etc/ossec.conf.deborig
            chmod 0600 ${DIR}/etc/ossec.conf.deborig
            chown root:root ${DIR}/etc/ossec.conf.deborig
            echo "====================================================================================="
            echo "= Backup from your ossec.conf has been created at /var/ossec/etc/ossec.conf.deborig ="
            echo "= Please verify your ossec.conf configuration at /var/ossec/etc/ossec.conf          ="
            echo "====================================================================================="
        fi
    fi
    # Delete old service
    if [ -f /etc/init.d/wazuh-agent ]; then
        rm /etc/init.d/wazuh-agent
    fi
    # back up the current user rules
    if [ -f ${DIR}/etc/client.keys ]; then
        cp ${DIR}/etc/client.keys ${OSSEC_HIDS_TMP_DIR}/client.keys
    fi
    if [ -f ${DIR}/etc/local_internal_options.conf ]; then
        cp -p ${DIR}/etc/local_internal_options.conf ${OSSEC_HIDS_TMP_DIR}/local_internal_options.conf
    fi
    if [ -f ${DIR}/etc/ossec.conf ]; then
        cp -p ${DIR}/etc/ossec.conf ${OSSEC_HIDS_TMP_DIR}/ossec.conf
    fi

    ;;

    install)

    ;;

    *)

    ;;

esac

exit 0
