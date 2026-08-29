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

pkg_exists() {
    for file in "$@"; do
        [ -f "$file" ] && return 0
    done
    return 1
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

# True (exit 0) if <block><sub><tag> exists in the config at all, even with empty
# content -- distinct from xml_value, which returns "" both when the tag is absent
# and when it's present but empty, since $(...) can't tell "no output" from "one
# empty line of output" apart. Needed wherever an empty tag is a meaningful,
# deliberate value rather than "unset" (e.g. <endpoint></endpoint>, #38492).
# The self-closing <tag/> form counts as present: OS_XML parses it as exactly
# equivalent to <tag></tag> (see test_simple_nodes3, src/unit_tests/os_xml), so
# the agent reads it as the same empty-content opt-out and this must agree.
xml_tag_present() {
    tr -d '\n\r' < ./etc/ossec.conf 2>/dev/null | grep -o "<$1>.*</$1>" | \
        grep -o "<$2>.*</$2>" | grep -qE "<$3>[^<]*</$3>|<$3[[:space:]]*/>"
}

# Defaults for the components an <endpoint> value leaves out, matching the agent's own
# (DEFAULT_HTTPS_REMOTE_PORT and the manager's default global_prefix, #38491).
DEFAULT_MANAGER_PORT="1517"
DEFAULT_MANAGER_ENDPOINT="/wazuh-manager/"

mep_error() {

    echo "$(date +"%Y/%m/%d %H:%M:%S") - Invalid <endpoint> '${1}': ${2}" >> ./logs/upgrade.log

}

# Split a combined <endpoint> value (#38624) into MEP_HOST / MEP_PORT / MEP_ENDPOINT.
# Same logic as parse_manager_endpoint() in register_configure_agent.sh,
# ParseManagerEndpoint() in inst-functions.sh and its VBScript twin; duplicated because
# this script ships inside the WPK and runs standalone, with nothing to source.
parse_manager_endpoint() {

    mep_raw="$1"
    mep_rest="$mep_raw"
    MEP_HOST=""
    MEP_PORT="${DEFAULT_MANAGER_PORT}"
    MEP_ENDPOINT="${DEFAULT_MANAGER_ENDPOINT}"

    if [ -z "${mep_raw}" ]; then
        mep_error "${mep_raw}" "a manager address is required."
        return 1
    fi

    # Optional scheme. Only treated as one when no '/' precedes the "://", so a
    # path that happens to contain "://" cannot be mistaken for a scheme.
    case "${mep_rest}" in
        *"://"*)
            mep_scheme="${mep_rest%%://*}"
            case "${mep_scheme}" in
                */*) ;;
                *)
                    mep_rest="${mep_rest#*://}"
                    case "${mep_scheme}" in
                        [Hh][Tt][Tt][Pp][Ss]) ;;
                        *)
                            mep_error "${mep_raw}" "unsupported scheme '${mep_scheme}://'; only https is served."
                            return 1
                            ;;
                    esac
                    ;;
            esac
            ;;
    esac

    # Authority up to the first '/', the prefix after it. Whether that '/' was
    # there at all is what separates "default prefix" from "opt-out".
    case "${mep_rest}" in
        */*)
            mep_authority="${mep_rest%%/*}"
            mep_path="${mep_rest#*/}"
            mep_path_given="yes"
            ;;
        *)
            mep_authority="${mep_rest}"
            mep_path=""
            mep_path_given="no"
            ;;
    esac

    # Host and optional port. A bracketed IPv6 literal ends at ']'; brackets exist
    # only to keep its colons apart from the port's and are dropped here, because
    # <address> wants the bare literal (OS_IsValidIP does not match a bracketed one,
    # and ModuleConfig::baseUrl re-brackets it for the URL itself).
    mep_port_given=""
    case "${mep_authority}" in
        "["*)
            case "${mep_authority}" in
                *"]"*) ;;
                *)
                    mep_error "${mep_raw}" "unterminated '[' in the address; a bracketed IPv6 literal needs a closing ']'."
                    return 1
                    ;;
            esac
            MEP_HOST="${mep_authority#[}"
            MEP_HOST="${MEP_HOST%%]*}"
            mep_after="${mep_authority#*]}"
            case "${mep_after}" in
                "") ;;
                ":"*) mep_port_given="${mep_after#:}" ;;
                *)
                    mep_error "${mep_raw}" "unexpected '${mep_after}' after the bracketed address."
                    return 1
                    ;;
            esac
            # A zone id (%25<iface>, percent-encoded inside a URL) stays part of the
            # host: the agent resolves it with if_nametoindex() at startup (#38624).
            ;;
        *:*:*)
            mep_error "${mep_raw}" "an IPv6 address must be bracketed, e.g. [2001:db8::1]:${DEFAULT_MANAGER_PORT}."
            return 1
            ;;
        *:*)
            MEP_HOST="${mep_authority%:*}"
            mep_port_given="${mep_authority##*:}"
            ;;
        *)
            MEP_HOST="${mep_authority}"
            ;;
    esac

    if [ -z "${MEP_HOST}" ]; then
        mep_error "${mep_raw}" "a manager address is required."
        return 1
    fi

    if [ -n "${mep_port_given}" ]; then
        case "${mep_port_given}" in
            ''|*[!0-9]*)
                mep_error "${mep_raw}" "port '${mep_port_given}' is not a number."
                return 1
                ;;
        esac
        if [ "${mep_port_given}" -lt 1 ] || [ "${mep_port_given}" -gt 65535 ]; then
            mep_error "${mep_raw}" "port '${mep_port_given}' is outside 1-65535."
            return 1
        fi
        MEP_PORT="${mep_port_given}"
    elif [ "${mep_authority}" != "${mep_authority%:}" ]; then
        mep_error "${mep_raw}" "trailing ':' with no port."
        return 1
    fi

    if [ "${mep_path_given}" = "yes" ]; then
        while :; do
            case "${mep_path}" in
                /*) mep_path="${mep_path#/}" ;;
                *) break ;;
            esac
        done
        while :; do
            case "${mep_path}" in
                */) mep_path="${mep_path%/}" ;;
                *) break ;;
            esac
        done
        if [ -z "${mep_path}" ]; then
            MEP_ENDPOINT=""
        else
            MEP_ENDPOINT="/${mep_path}/"
        fi
    fi

    return 0

}

# Check that the manager answers on the HTTPS control port. Every endpoint,
# including the health probe, is served under the manager's global_prefix
# (#38491) -- an unprefixed request always gets a 404, so the probe URL must
# include the same endpoint/prefix the agent itself connects with (arg 3).
probe_server() {
    PROBE_TIMEOUT=5

    # MEP_HOST holds an IPv6 literal unbracketed, the way <endpoint> stores it. A URL
    # needs it bracketed again or curl, wget and Invoke-WebRequest all reject the value
    # as malformed and the upgrade aborts with "manager is not reachable".
    PROBE_HOST="${1}"
    case "${PROBE_HOST}" in
        \[*) ;;
        *:*:*) PROBE_HOST="[${PROBE_HOST}]" ;;
    esac

    # An empty endpoint (the <endpoint></endpoint> opt-out, #38492) must probe the
    # bare root: "/${3}/" would emit "//", and the manager's HTTP router does not
    # collapse duplicate slashes -- it 404s them, so the probe would fail against
    # the very unprefixed manager the opt-out exists for. Mirrors do_upgrade.ps1.
    if [ -z "${3}" ]; then
        PROBE_PATH="/"
    else
        PROBE_PATH="/${3}/"
    fi

    if command -v curl > /dev/null 2>&1; then
        curl -k -s -f -m ${PROBE_TIMEOUT} -o /dev/null "https://${PROBE_HOST}:${2}${PROBE_PATH}"
        return $?
    fi

    if command -v wget > /dev/null 2>&1; then
        wget -q --no-check-certificate --timeout=${PROBE_TIMEOUT} --tries=1 -O /dev/null "https://${PROBE_HOST}:${2}${PROBE_PATH}"
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

# A WPK upgrade never rewrites ossec.conf, so this script meets two config shapes and has
# to read both (#38624):
#
#   current  <agent><manager><endpoint>  carrying host[:port][/prefix] in one value
#   upgraded the deprecated <agent><manager><address>/<port>, or a 4.x
#            <client><server><address> -- neither has an endpoint concept
#
# <endpoint> always carries the whole target, so no disambiguation is needed: its presence
# alone decides, exactly as Read_Agent_Manager() does.
if xml_tag_present agent manager endpoint; then
    COMBINED_ENDPOINT=$(xml_value agent manager endpoint)

    # Split the one value the same way the agent's parser does. An empty <endpoint> fails
    # here just as it does there, leaving SERVER_ADDRESS unset for the check below.
    if parse_manager_endpoint "${COMBINED_ENDPOINT}"; then
        SERVER_ADDRESS="${MEP_HOST}"
        SERVER_PORT="${MEP_PORT}"
        SERVER_ENDPOINT="${MEP_ENDPOINT}"
    fi
else
    # Compose the same target the agent composes internally from the deprecated tags:
    # the address, <port> or its 1517 default, and the default prefix.
    SERVER_ADDRESS=$(xml_value agent manager address)
    SERVER_PORT=$(xml_value agent manager port)

    if [ -z "${SERVER_ADDRESS}" ]; then
        # 4.x shape. Its <port> is not read by the agent either, so leave it defaulted.
        SERVER_ADDRESS=$(xml_value client server address)
        SERVER_PORT=""
    fi

    SERVER_ENDPOINT="wazuh-manager"
fi

if [ -z "${SERVER_PORT}" ]; then
    SERVER_PORT=1517
fi

# Strip any leading/trailing '/' so the probe URL never doubles one up.
SERVER_ENDPOINT=$(echo "${SERVER_ENDPOINT}" | sed -e 's|^/*||' -e 's|/*$||')

if [ -z "${SERVER_ADDRESS}" ]; then
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Upgrade failed. No manager address found in the configuration." >> ./logs/upgrade.log
    abort_upgrade "2"
fi

echo "$(date +"%Y/%m/%d %H:%M:%S") - Checking connectivity to ${SERVER_ADDRESS}:${SERVER_PORT}/${SERVER_ENDPOINT}." >> ./logs/upgrade.log

if [ "${WAZUH_UPGRADE_TEST_SKIP_MANAGER_CHECK}" = "1" ]; then
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Manager connectivity check skipped (test mode)." >> ./logs/upgrade.log
elif ! probe_server "${SERVER_ADDRESS}" "${SERVER_PORT}" "${SERVER_ENDPOINT}"; then
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Upgrade failed. The manager is not reachable at ${SERVER_ADDRESS}:${SERVER_PORT}/${SERVER_ENDPOINT}, interrupting upgrade." >> ./logs/upgrade.log
    abort_upgrade "2"
else
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Manager reachable at ${SERVER_ADDRESS}:${SERVER_PORT}/${SERVER_ENDPOINT}." >> ./logs/upgrade.log
fi

if [[ "$OS" == "Darwin" ]]; then
    installer -pkg ./var/upgrade/wazuh-agent* -target / >> ./logs/upgrade.log 2>&1
elif [[ "$OS" == "Linux" ]]; then
    if pkg_exists ./var/upgrade/*.rpm; then
        if command -v rpm >/dev/null 2>&1; then
            rpm -UFvh ./var/upgrade/wazuh-agent* >> ./logs/upgrade.log 2>&1
        else
            echo "$(date +"%Y/%m/%d %H:%M:%S") - Upgrade failed. RPM package found but rpm command not found." >> ./logs/upgrade.log
            abort_upgrade "2"
        fi
    elif pkg_exists ./var/upgrade/*.deb; then
        if command -v dpkg >/dev/null 2>&1; then
            dpkg -i --force-confdef ./var/upgrade/wazuh-agent* >> ./logs/upgrade.log 2>&1
        else
            echo "$(date +"%Y/%m/%d %H:%M:%S") - Upgrade failed. DEB package found but dpkg command not found." >> ./logs/upgrade.log
            abort_upgrade "2"
        fi
    elif pkg_exists ./var/upgrade/*.apk; then
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
