#!/bin/sh
# Restarts Wazuh.
# Requirements: none
# Copyright (C) 2015-2019, Wazuh Inc.


ACTION=$1
USER=$2
IP=$3

LOCAL=`dirname $0`;
cd $LOCAL
cd ../../
PWD=`pwd`


# Logging the call
echo "`date` $0 $1 $2 $3 $4 $5" >> ${PWD}/logs/active-responses.log


if [ "x${ACTION}" = "xadd" ]; then

    if /var/ossec/bin/ossec-logtest -t > /dev/null 2>&1; then
        if command -v systemctl > /dev/null 2>&1; then        
            systemctl restart wazuh-agent
        elif command -v service > /dev/null 2>&1; then        
            service restart wazuh-agent
        elif command -v update-rc.d > /dev/null 2>&1; then        
            update-rc.d restart wazuh-agent
        else
            ${PWD}/bin/ossec-control restart
        fi
        exit $?;
    else
        exit 1;
    fi

fi

exit 1;