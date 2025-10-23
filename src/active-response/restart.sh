#!/bin/sh
# Restarts Wazuh.
# Copyright (C) 2015, Wazuh Inc.


PARAM_TYPE=$1
PARAM_ACTION="${2:-restart}"

help()
{
    echo "Usage: $0 [manager|agent] [restart|reload]"
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

if command -v systemctl >/dev/null 2>&1; then
    # If reload is requested, wait for service to be fully active first
    if [ "$PARAM_ACTION" = "reload" ]; then
        # Wait up to 60 seconds for service to be active
        TIMEOUT=60
        ELAPSED=0
        while [ $ELAPSED -lt $TIMEOUT ]; do
            STATE=$(systemctl is-active wazuh-$TYPE 2>/dev/null)

            # Exit immediately if service is in a failed or stopped state
            case "$STATE" in
                inactive|failed)
                    echo "Service wazuh-$TYPE is in state '$STATE', cannot reload" >> ${PWD}/logs/active-responses.log
                    exit 1
                    ;;
                active)
                    break
                    ;;
            esac

            sleep 1
            ELAPSED=$((ELAPSED + 1))
        done

        # Check if service is now active
        if ! systemctl is-active --quiet wazuh-$TYPE; then
            echo "Service wazuh-$TYPE is not active after waiting $TIMEOUT seconds" >> ${PWD}/logs/active-responses.log
            exit 1
        fi
    fi

    systemctl $PARAM_ACTION wazuh-$TYPE
else
    ${PWD}/bin/wazuh-control $PARAM_ACTION
fi

exit $?;
