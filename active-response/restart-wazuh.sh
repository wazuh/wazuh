#!/bin/sh
# Restarts ossec.
# Requirements: none
# Copyright (C) 2015-2019, Wazuh Inc.
# Author: Daniel B. Cid

ACTION=$1
USER=$2
IP=$3

LOCAL=`dirname $0`;
cd $LOCAL
cd ../../
PWD=`pwd`
UNAME=`uname`


# Logging the call
echo "`date` $0 $1 $2 $3 $4 $5" >> ${PWD}/logs/active-responses.log

function write_tmp {
    echo $1 > ${PWD}/tmp/api_restart
    chown ossec:ossec ${PWD}/tmp/api_restart
    chmod 660 ${PWD}/tmp/api_restart
}

# service updaterc ELSE ossec-control
if [ "x${ACTION}" = "xadd" ]; then

    if /var/ossec/bin/ossec-logtest -t > /dev/null 2>&1; then
        if command -v systemctl > /dev/null 2>&1; then        
            systemctl restart wazuh-manager
        elif command -v service > /dev/null 2>&1; then        
            service restart wazuh-manager
        elif command -v update-rc.d > /dev/null 2>&1; then        
            update-rc.d restart wazuh-manager
        else
            ${PWD}/bin/ossec-control restart
        fi
        # check if restart was successful
        ret=$?
        if [ $ret = 0 ]; then
            confirmation="OK"
            write_tmp $confirmation
        else
            confirmation="KO"
            write_tmp $confirmation
        fi
        exit $ret;
    else
        confirmation="KO"
        write_tmp $confirmation
        exit 1;
    fi

fi

exit 1;
