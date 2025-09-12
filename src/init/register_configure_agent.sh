#!/bin/bash

# Copyright (C) 2015, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Global variables
INSTALLDIR=${1}
CONF_FILE="${INSTALLDIR}/etc/ossec.conf"
TMP_ENROLLMENT="${INSTALLDIR}/tmp/enrollment-configuration"
TMP_SERVER="${INSTALLDIR}/tmp/server-configuration"
WAZUH_REGISTRATION_PASSWORD_PATH="etc/authd.pass"
WAZUH_MACOS_AGENT_DEPLOYMENT_VARS="/tmp/wazuh_envs"


# Set default sed alias
sed="sed -ri"

# Update the value of a XML tag inside the ossec.conf
edit_value_tag() {

    file=""

    if [ -z "$3" ]; then
        file="${CONF_FILE}"
    else
        file="${TMP_ENROLLMENT}"
    fi

    if [ -n "$1" ] && [ -n "$2" ]; then
        start_config="$(grep -n "<$1>" "${file}" | cut -d':' -f 1)"
        end_config="$(grep -n "</$1>" "${file}" | cut -d':' -f 1)"
        if [ -z "${start_config}" ] && [ -z "${end_config}" ] && [ "${file}" = "${TMP_ENROLLMENT}" ]; then
            echo "      <$1>$2</$1>" >> "${file}"
        else
            ${sed} "s#<$1>.*</$1>#<$1>$2</$1>#g" "${file}"
        fi
    fi

    if [ "$?" != "0" ]; then
        echo "$(date '+%Y/%m/%d %H:%M:%S') Error updating $2 with variable $1." >> "${INSTALLDIR}/logs/ossec.log"
    fi

}

delete_blank_lines() {

    file=$1
    ${sed} '/^$/d' "${file}"

}

delete_auto_enrollment_tag() {

    # Delete the configuration tag if its value is empty
    # This will allow using the default value
    ${sed} "s#.*<$1>.*</$1>.*##g" "${TMP_ENROLLMENT}"

    cat -s "${TMP_ENROLLMENT}" > "${TMP_ENROLLMENT}.tmp"
    mv "${TMP_ENROLLMENT}.tmp" "${TMP_ENROLLMENT}"

}

# Change address block of the ossec.conf
add_adress_block() {

    # Remove the server configuration
    ${sed} "/<server>/,/\/server>/d" "${CONF_FILE}"

    # Write the client configuration block
    for i in "${!ADDRESSES[@]}";
    do
        {
            echo "    <server>"
            echo "      <address>${ADDRESSES[i]}</address>"
            echo "      <port>1514</port>"
            echo "    </server>"
        } >> "${TMP_SERVER}"
    done

    ${sed} "/<client>/r ${TMP_SERVER}" "${CONF_FILE}"

    rm -f "${TMP_SERVER}"

}

add_parameter () {

    if [ -n "$3" ]; then
        OPTIONS="$1 $2 $3"
    fi
    echo "${OPTIONS}"

}

get_deprecated_vars () {

    if [ -n "${WAZUH_MANAGER_IP}" ] && [ -z "${WAZUH_MANAGER}" ]; then
        WAZUH_MANAGER=${WAZUH_MANAGER_IP}
    fi
    if [ -n "${WAZUH_AUTHD_SERVER}" ] && [ -z "${WAZUH_REGISTRATION_SERVER}" ]; then
        WAZUH_REGISTRATION_SERVER=${WAZUH_AUTHD_SERVER}
    fi
    if [ -n "${WAZUH_AUTHD_PORT}" ] && [ -z "${WAZUH_REGISTRATION_PORT}" ]; then
        WAZUH_REGISTRATION_PORT=${WAZUH_AUTHD_PORT}
    fi
    if [ -n "${WAZUH_PASSWORD}" ] && [ -z "${WAZUH_REGISTRATION_PASSWORD}" ]; then
        WAZUH_REGISTRATION_PASSWORD=${WAZUH_PASSWORD}
    fi
    if [ -n "${WAZUH_NOTIFY_TIME}" ] && [ -z "${WAZUH_KEEP_ALIVE_INTERVAL}" ]; then
        WAZUH_KEEP_ALIVE_INTERVAL=${WAZUH_NOTIFY_TIME}
    fi
    if [ -n "${WAZUH_CERTIFICATE}" ] && [ -z "${WAZUH_REGISTRATION_CA}" ]; then
        WAZUH_REGISTRATION_CA=${WAZUH_CERTIFICATE}
    fi
    if [ -n "${WAZUH_PEM}" ] && [ -z "${WAZUH_REGISTRATION_CERTIFICATE}" ]; then
        WAZUH_REGISTRATION_CERTIFICATE=${WAZUH_PEM}
    fi
    if [ -n "${WAZUH_KEY}" ] && [ -z "${WAZUH_REGISTRATION_KEY}" ]; then
        WAZUH_REGISTRATION_KEY=${WAZUH_KEY}
    fi
    if [ -n "${WAZUH_GROUP}" ] && [ -z "${WAZUH_AGENT_GROUP}" ]; then
        WAZUH_AGENT_GROUP=${WAZUH_GROUP}
    fi

}

set_vars () {

    export WAZUH_MANAGER
    export WAZUH_MANAGER_PORT
    export WAZUH_REGISTRATION_SERVER
    export WAZUH_REGISTRATION_PORT
    export WAZUH_REGISTRATION_PASSWORD
    export WAZUH_KEEP_ALIVE_INTERVAL
    export WAZUH_TIME_RECONNECT
    export WAZUH_REGISTRATION_CA
    export WAZUH_REGISTRATION_CERTIFICATE
    export WAZUH_REGISTRATION_KEY
    export WAZUH_AGENT_NAME
    export WAZUH_AGENT_GROUP
    export ENROLLMENT_DELAY
    # The following variables are yet supported but all of them are deprecated
    export WAZUH_MANAGER_IP
    export WAZUH_NOTIFY_TIME
    export WAZUH_AUTHD_SERVER
    export WAZUH_AUTHD_PORT
    export WAZUH_PASSWORD
    export WAZUH_GROUP
    export WAZUH_CERTIFICATE
    export WAZUH_KEY
    export WAZUH_PEM

    if [ -r "${WAZUH_MACOS_AGENT_DEPLOYMENT_VARS}" ]; then
        . ${WAZUH_MACOS_AGENT_DEPLOYMENT_VARS}
        rm -rf "${WAZUH_MACOS_AGENT_DEPLOYMENT_VARS}"
    fi

}

unset_vars() {

    vars=(WAZUH_MANAGER_IP WAZUH_MANAGER_PORT WAZUH_NOTIFY_TIME \
          WAZUH_TIME_RECONNECT WAZUH_AUTHD_SERVER WAZUH_AUTHD_PORT WAZUH_PASSWORD \
          WAZUH_AGENT_NAME WAZUH_GROUP WAZUH_CERTIFICATE WAZUH_KEY WAZUH_PEM \
          WAZUH_MANAGER WAZUH_REGISTRATION_SERVER WAZUH_REGISTRATION_PORT \
          WAZUH_REGISTRATION_PASSWORD WAZUH_KEEP_ALIVE_INTERVAL WAZUH_REGISTRATION_CA \
          WAZUH_REGISTRATION_CERTIFICATE WAZUH_REGISTRATION_KEY WAZUH_AGENT_GROUP \
          ENROLLMENT_DELAY)

    for var in "${vars[@]}"; do
        unset "${var}"
    done

}

# Function to convert strings to lower version
tolower () {

    echo "$1" | tr '[:upper:]' '[:lower:]'

}


# Add auto-enrollment configuration block
add_auto_enrollment () {

    start_config="$(grep -n "<enrollment>" "${CONF_FILE}" | cut -d':' -f 1)"
    end_config="$(grep -n "</enrollment>" "${CONF_FILE}" | cut -d':' -f 1)"
    if [ -n "${start_config}" ] && [ -n "${end_config}" ]; then
        start_config=$(( start_config + 1 ))
        end_config=$(( end_config - 1 ))
        sed -n "${start_config},${end_config}p" "${INSTALLDIR}/etc/ossec.conf" >> "${TMP_ENROLLMENT}"
    else
        # Write the client configuration block
        {
            echo "    <enrollment>"
            echo "      <enabled>yes</enabled>"
            echo "      <manager_address>MANAGER_IP</manager_address>"
            echo "      <port>1515</port>"
            echo "      <agent_name>agent</agent_name>"
            echo "      <groups>Group1</groups>"
            echo "      <server_ca_path>/path/to/server_ca</server_ca_path>"
            echo "      <agent_certificate_path>/path/to/agent.cert</agent_certificate_path>"
            echo "      <agent_key_path>/path/to/agent.key</agent_key_path>"
            echo "      <authorization_pass_path>/path/to/authd.pass</authorization_pass_path>"
            echo "      <delay_after_enrollment>20</delay_after_enrollment>"
            echo "    </enrollment>"
        } >> "${TMP_ENROLLMENT}"
    fi

}

# Add the auto_enrollment block to the configuration file
concat_conf() {

    ${sed} "/<\/auto_restart>/r ${TMP_ENROLLMENT}" "${CONF_FILE}"

    rm -f "${TMP_ENROLLMENT}"

}

# Set autoenrollment configuration
set_auto_enrollment_tag_value () {

    tag="$1"
    value="$2"

    if [ -n "${value}" ]; then
        edit_value_tag "${tag}" "${value}" "auto_enrollment"
    else
        delete_auto_enrollment_tag "${tag}" "auto_enrollment"
    fi

}

# Main function the script begin here
main () {

    uname_s=$(uname -s)

    # Check what kind of system we are working with
    if [ "${uname_s}" = "Darwin" ]; then
        sed="sed -ire"
        set_vars
    fi

    get_deprecated_vars

    if [ -n "${WAZUH_MANAGER}" ]; then
        if [ ! -f "${INSTALLDIR}/logs/ossec.log" ]; then
            touch -f "${INSTALLDIR}/logs/ossec.log"
            chmod 660 "${INSTALLDIR}/logs/ossec.log"
            chown root:wazuh "${INSTALLDIR}/logs/ossec.log"
        fi

        # Check if multiples IPs are defined in variable WAZUH_MANAGER
        ADDRESSES=( ${WAZUH_MANAGER//,/ } )

        add_adress_block
    fi

    edit_value_tag "port" "${WAZUH_MANAGER_PORT}"

    if [ -n "${WAZUH_REGISTRATION_SERVER}" ] || [ -n "${WAZUH_REGISTRATION_PORT}" ] || [ -n "${WAZUH_REGISTRATION_CA}" ] || [ -n "${WAZUH_REGISTRATION_CERTIFICATE}" ] || [ -n "${WAZUH_REGISTRATION_KEY}" ] || [ -n "${WAZUH_AGENT_NAME}" ] || [ -n "${WAZUH_AGENT_GROUP}" ] || [ -n "${ENROLLMENT_DELAY}" ] || [ -n "${WAZUH_REGISTRATION_PASSWORD}" ]; then
        add_auto_enrollment
        set_auto_enrollment_tag_value "manager_address" "${WAZUH_REGISTRATION_SERVER}"
        set_auto_enrollment_tag_value "port" "${WAZUH_REGISTRATION_PORT}"
        set_auto_enrollment_tag_value "server_ca_path" "${WAZUH_REGISTRATION_CA}"
        set_auto_enrollment_tag_value "agent_certificate_path" "${WAZUH_REGISTRATION_CERTIFICATE}"
        set_auto_enrollment_tag_value "agent_key_path" "${WAZUH_REGISTRATION_KEY}"
        set_auto_enrollment_tag_value "authorization_pass_path" "${WAZUH_REGISTRATION_PASSWORD_PATH}"
        set_auto_enrollment_tag_value "agent_name" "${WAZUH_AGENT_NAME}"
        set_auto_enrollment_tag_value "groups" "${WAZUH_AGENT_GROUP}"
        set_auto_enrollment_tag_value "delay_after_enrollment" "${ENROLLMENT_DELAY}"
        delete_blank_lines "${TMP_ENROLLMENT}"
        concat_conf
    fi


    if [ -n "${WAZUH_REGISTRATION_PASSWORD}" ]; then
        echo "${WAZUH_REGISTRATION_PASSWORD}" > "${INSTALLDIR}/${WAZUH_REGISTRATION_PASSWORD_PATH}"
        chmod 640 "${INSTALLDIR}"/"${WAZUH_REGISTRATION_PASSWORD_PATH}"
        chown root:wazuh "${INSTALLDIR}"/"${WAZUH_REGISTRATION_PASSWORD_PATH}"
    fi

    # Options to be modified in ossec.conf
    edit_value_tag "notify_time" "${WAZUH_KEEP_ALIVE_INTERVAL}"
    edit_value_tag "time-reconnect" "${WAZUH_TIME_RECONNECT}"

    unset_vars

}

# Start script execution
main "$@"
