#!/bin/sh
# Restarts Wazuh.
# Copyright (C) 2015, Wazuh Inc.


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

# Rules and decoders test
if [ "$TYPE" = "manager" ]; then
    if !(${PWD}/bin/wazuh-logtest-legacy -t > /dev/null 2>&1); then
        exit 1;
    fi
fi

${PWD}/bin/wazuh-control restart

exit $?;
