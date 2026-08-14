#!/bin/bash
# Copyright (C) 2015, Wazuh Inc.


LOCK=./var/upgrade/upgrade_in_progress_pid
cat /dev/null >> $LOCK
read UPGRADE_PID < $LOCK

# Check if there is an upgrade in progress
if [ ! -z "$UPGRADE_PID" -a -d /proc/$UPGRADE_PID ]; then
    echo "$(date +"%Y/%m/%d %H:%M:%S") - There is an upgrade in progress. Aborting..." >> ./logs/upgrade.log
    exit 1
fi

# Installing upgrade
echo $$ > $LOCK
echo "$(date +"%Y/%m/%d %H:%M:%S") - Upgrade started." >> ./logs/upgrade.log

OS=$(uname)
WAZUH_HOME=$(pwd)

if [ -z "${INSTALLDIR}" ]; then
    INSTALLDIR="${WAZUH_HOME}"
fi

# Write the upgrade result and 'reload' modulesd
abort_upgrade() {
    echo -ne "$1" > ./var/upgrade/upgrade_result
    if [ -x ./bin/wazuh-control ]; then
        echo "$(date +"%Y/%m/%d %H:%M:%S") - Reloading the Wazuh agent to report the upgrade result." >> ./logs/upgrade.log
        ./bin/wazuh-control reload >> ./logs/upgrade.log 2>&1
    else
        echo "$(date +"%Y/%m/%d %H:%M:%S") - Cannot reload the Wazuh agent, ./bin/wazuh-control not found. The result will be reported on the next agent restart." >> ./logs/upgrade.log
    fi
    rm -f $LOCK
    exit 1
}

echo "$(date +"%Y/%m/%d %H:%M:%S") - Checking execution path." >> ./logs/upgrade.log


if [[ "$OS" == "Darwin" ]]; then
    if [ "${WAZUH_HOME}" != "/Library/Ossec" ]; then
        echo "$(date +"%Y/%m/%d %H:%M:%S") - Execution path is wrong (it should be /Library/Ossec), interrupting upgrade." >> ./logs/upgrade.log
        abort_upgrade "2"
    fi
elif [[ "$OS" == "Linux" ]]; then
    if [ "${WAZUH_HOME}" != "${INSTALLDIR}" ]; then
        echo "$(date +"%Y/%m/%d %H:%M:%S") - Execution path is wrong (it should be ${INSTALLDIR}), interrupting upgrade." >> ./logs/upgrade.log
        abort_upgrade "2"
    fi
else
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Upgrade failed. Unsupported OS." >> ./logs/upgrade.log
    abort_upgrade "2"
fi

# Read <block><sub><tag> from the agent configuration, taking the last match.
xml_value() {
    tr -d '\n\r' < ./etc/ossec.conf 2>/dev/null | grep -o "<$1>.*</$1>" | \
        grep -o "<$2>.*</$2>" | grep -o "<$3>[^<]*</$3>" | tail -1 | \
        sed -e "s|<$3>||" -e "s|</$3>||" -e 's|^ *||' -e 's| *$||'
}

# Check that the manager answers on the HTTPS control port. GET / is remoted's
# unauthenticated health probe and returns 200 {"status":"ok","module":"remoted"}
probe_server() {
    PROBE_TIMEOUT=5

    if command -v curl > /dev/null 2>&1; then
        curl -k -s -f -m ${PROBE_TIMEOUT} -o /dev/null "https://${1}:${2}/"
        return $?
    fi

    if command -v wget > /dev/null 2>&1; then
        wget -q --no-check-certificate --timeout=${PROBE_TIMEOUT} --tries=1 -O /dev/null "https://${1}:${2}/"
        return $?
    fi

    echo "$(date +"%Y/%m/%d %H:%M:%S") - Neither curl nor wget found, falling back to a TCP connectivity check." >> ./logs/upgrade.log
    ( exec 3<>"/dev/tcp/${1}/${2}" ) > /dev/null 2>&1 &
    PROBE_PID=$!
    WAITED=0
    while kill -0 ${PROBE_PID} 2>/dev/null && [ ${WAITED} -lt ${PROBE_TIMEOUT} ]; do
        sleep 1
        WAITED=$((WAITED + 1))
    done
    if kill -0 ${PROBE_PID} 2>/dev/null; then
        kill -9 ${PROBE_PID} 2>/dev/null
        wait ${PROBE_PID} 2>/dev/null
        return 1
    fi
    wait ${PROBE_PID}
    return $?
}

# The 5x agent reads the server address from the <agent> block, falling back to the <client> block when upgrading from 4x versions.
SERVER_ADDRESS=$(xml_value agent server address)
if [ -z "${SERVER_ADDRESS}" ]; then
    SERVER_ADDRESS=$(xml_value client server address)
fi

# The 5x agent reads the server port from the <agent> block, falling back to 1517 when upgrading from 4x versions.
SERVER_PORT=$(xml_value agent server port)
if [ -z "${SERVER_PORT}" ]; then
    SERVER_PORT=1517
fi

if [ -z "${SERVER_ADDRESS}" ]; then
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Upgrade failed. No manager address found in the configuration." >> ./logs/upgrade.log
    abort_upgrade "2"
fi

echo "$(date +"%Y/%m/%d %H:%M:%S") - Checking connectivity to ${SERVER_ADDRESS}:${SERVER_PORT}." >> ./logs/upgrade.log

if ! probe_server "${SERVER_ADDRESS}" "${SERVER_PORT}"; then
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Upgrade failed. The manager is not reachable at ${SERVER_ADDRESS}:${SERVER_PORT}, interrupting upgrade." >> ./logs/upgrade.log
    abort_upgrade "2"
fi

echo "$(date +"%Y/%m/%d %H:%M:%S") - Manager reachable at ${SERVER_ADDRESS}:${SERVER_PORT}." >> ./logs/upgrade.log

if [[ "$OS" == "Darwin" ]]; then
    installer -pkg ./var/upgrade/wazuh-agent* -target / >> ./logs/upgrade.log 2>&1
elif [[ "$OS" == "Linux" ]]; then
    if find ./var/upgrade/ -mindepth 1 -maxdepth 1 -type f -name "*.rpm" | read; then
        if command -v rpm >/dev/null 2>&1; then
            rpm -UFvh ./var/upgrade/wazuh-agent* >> ./logs/upgrade.log 2>&1
        else
            echo "$(date +"%Y/%m/%d %H:%M:%S") - Upgrade failed. RPM package found but rpm command not found." >> ./logs/upgrade.log
            abort_upgrade "2"
        fi
    elif find ./var/upgrade/ -mindepth 1 -maxdepth 1 -type f -name "*.deb" | read; then
        if command -v dpkg >/dev/null 2>&1; then
            dpkg -i --force-confdef ./var/upgrade/wazuh-agent* >> ./logs/upgrade.log 2>&1
        else
            echo "$(date +"%Y/%m/%d %H:%M:%S") - Upgrade failed. DEB package found but dpkg command not found." >> ./logs/upgrade.log
            abort_upgrade "2"
        fi
    elif find ./var/upgrade/ -mindepth 1 -maxdepth 1 -type f -name "*.apk" | read; then
        if command -v apk >/dev/null 2>&1; then
            apk add --allow-untrusted --force ./var/upgrade/wazuh-agent* >> ./logs/upgrade.log 2>&1
        else
            echo "$(date +"%Y/%m/%d %H:%M:%S") - Upgrade failed. APK package found but apk command not found." >> ./logs/upgrade.log
            abort_upgrade "2"
        fi
    else
        if [ -e ./var/upgrade/install.sh ]; then
            chmod +x ./var/upgrade/install.sh
            ./var/upgrade/install.sh >> ./logs/upgrade.log 2>&1
        else
            echo "$(date +"%Y/%m/%d %H:%M:%S") - Upgrade failed. No package or sources found." >> ./logs/upgrade.log
            abort_upgrade "2"
        fi
    fi
else
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Upgrade failed. Unsupported OS." >> ./logs/upgrade.log
    abort_upgrade "2"
fi


# Check installation result
RESULT=$?
echo "$(date +"%Y/%m/%d %H:%M:%S") - Installation result = ${RESULT}" >> ./logs/upgrade.log

# Restart Agent
echo "$(date +"%Y/%m/%d %H:%M:%S") - Checking for Wazuh Agent control script." >> ./logs/upgrade.log

if [ -f "./bin/wazuh-control" ]; then
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Restarting Wazuh Agent." >> ./logs/upgrade.log
    ./bin/wazuh-control restart >> ./logs/upgrade.log 2>&1
else
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Upgrade failed: wazuh-control not found." >> ./logs/upgrade.log
    abort_upgrade "2"
fi

sleep 1


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

# Check connection and update upgrade log
if [ "$status" = "connected" -a $RESULT -eq 0 ]; then
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Connected to manager." >> ./logs/upgrade.log
    echo -ne "0" > ./var/upgrade/upgrade_result
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Upgrade finished successfully." >> ./logs/upgrade.log
else
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Upgrade failed..." >> ./logs/upgrade.log
    # Only write generic failure code if no specific result was already set by the installer
    if [ ! -s ./var/upgrade/upgrade_result ]; then
        echo -ne "2" > ./var/upgrade/upgrade_result
    fi
fi

rm -f $LOCK

exit 0
