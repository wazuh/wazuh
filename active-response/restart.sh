#!/bin/sh
# Restarts Wazuh.
# Copyright (C) 2015-2020, Wazuh Inc.


PARAM_TYPE=$1

help()
{
    echo "Usage: $0 [manager|agent]"
}

# Usage
if [ "$1" = "-h" ]; then
    help
    exit 0;
fi

# Checking user arguments
if [ "x$PARAM_TYPE" = "xmanager" ]; then
    TYPE="manager"
elif [ "x$PARAM_TYPE" = "xagent" ]; then
    TYPE="agent"
else
    help
    exit 1;
fi

LOCAL=`dirname $0`;
cd $LOCAL
cd ../../
PWD=`pwd`

# Logging the call
echo "`date` $0 $1 $2 $3 $4 $5" >> ${PWD}/logs/active-responses.log

# Run logtest in managers
if [ "$TYPE" = "manager" ]; then
    if !(${PWD}/bin/ossec-logtest -t > /dev/null 2>&1); then
        exit 1;
    fi
fi

# Restart Wazuh
if command -v systemctl > /dev/null 2>&1 && systemctl > /dev/null 2>&1; then
    touch ${PWD}/var/run/.restart
    systemctl restart wazuh-$TYPE
    rm -f ${PWD}/var/run/.restart
elif command -v service > /dev/null 2>&1; then
    touch ${PWD}/var/run/.restart
    service wazuh-$TYPE restart
    rm -f ${PWD}/var/run/.restart
else
    ${PWD}/bin/ossec-control restart
fi

exit $?;
