#!/bin/sh
# Restarts Wazuh.
# Copyright (C) 2015-2019, Wazuh Inc.


PARAM_TYPE=$1

help()
{
    echo "Usage: $0 [manager|agent]"
}

# Usage
if [ "$1" == "-h" ]; then
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
    if !(/var/ossec/bin/ossec-logtest -t > /dev/null 2>&1); then
        exit 1;
    fi
fi

# Restart Wazuh
if command -v systemctl > /dev/null 2>&1; then        
    systemctl restart wazuh-$TYPE
elif command -v service > /dev/null 2>&1; then        
    service restart wazuh-$TYPE
elif command -v update-rc.d > /dev/null 2>&1; then        
    update-rc.d restart wazuh-$TYPE
else
    ${PWD}/bin/ossec-control restart
fi

exit $?;

