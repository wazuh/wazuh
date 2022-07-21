#!/bin/bash

# Copyright (C) 2015, Wazuh Inc.
# March 6, 2019.
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


# Set default sed alias
sed="sed -ri"
# By default, use gnu sed (gsed).
use_unix_sed="False"

# Special function to use generic sed
unix_sed() {
    sed_expression="$1"
    target_file="$2"
    special_args="$3"

    sed ${special_args} "${sed_expression}" "${target_file}" > ${target_file}.tmp
    cat "${target_file}.tmp" > "${target_file}"
    rm "${target_file}.tmp"
}

# Update the value of a XML tag inside the ossec.conf
edit_value_tag() {

    file=""

    if [ -z "$3" ]; then
        file="${CONF_FILE}"
    else
        file="${TMP_ENROLLMENT}"
    fi

    if [ ! -z "$1" ] && [ ! -z "$2" ]; then
        start_config="$(grep -n "<$1>" ${file} | cut -d':' -f 1)"
        end_config="$(grep -n "</$1>" ${file} | cut -d':' -f 1)"
        if [ ! -n "${start_config}" ] && [ ! -n "${end_config}" ] && [ "${file}" = "${TMP_ENROLLMENT}" ]; then
            echo "      <$1>$2</$1>" >> ${file}
        elif [ "${use_unix_sed}" = "False" ] ; then
            ${sed} "s#<$1>.*</$1>#<$1>$2</$1>#g" "${file}"
        else
            unix_sed "s#<$1>.*</$1>#<$1>$2</$1>#g" "${file}"
        fi
    fi
    
    if [ "$?" != "0" ]; then
        echo "$(date '+%Y/%m/%d %H:%M:%S') agent-auth: Error updating $2 with variable $1." >> ${INSTALLDIR}/logs/ossec.log
    fi
}

delete_blank_lines() {
    file=$1
    if [ "${use_unix_sed}" = "False" ] ; then
        ${sed} '/^$/d' "${file}"
    else
        unix_sed '/^$/d' "${file}"
    fi
}
delete_auto_enrollment_tag() {
    # Delete the configuration tag if its value is empty
    # This will allow using the default value
    if [ "${use_unix_sed}" = "False" ] ; then
        ${sed} "s#.*<$1>.*</$1>.*##g" "${TMP_ENROLLMENT}"
    else
        unix_sed "s#.*<$1>.*</$1>.*##g" "${TMP_ENROLLMENT}"
    fi

    cat -s "${TMP_ENROLLMENT}" > "${TMP_ENROLLMENT}.tmp"
    mv "${TMP_ENROLLMENT}.tmp" "${TMP_ENROLLMENT}"
}

# Change address block of the ossec.conf
add_adress_block() {
    # Getting function parameters on new variable
    SET_ADDRESSES="$@"

    # Remove the server configuration
    if [ "${use_unix_sed}" = "False" ] ; then
        ${sed} "/<server>/,/\/server>/d" ${CONF_FILE}
    else
        unix_sed "/<server>/,/\/server>/d" "${CONF_FILE}"
    fi

    # Write the client configuration block
    for i in ${SET_ADDRESSES};
    do
        echo "    <server>" >> ${TMP_SERVER}
        echo "      <address>$i</address>" >> ${TMP_SERVER}
        echo "      <port>1514</port>" >> ${TMP_SERVER}
        echo "      <protocol>tcp</protocol>" >> ${TMP_SERVER}
        echo "    </server>" >> ${TMP_SERVER}
    done

    if [ "${use_unix_sed}" = "False" ] ; then
        ${sed} "/<client>/r ${TMP_SERVER}" ${CONF_FILE}
    else
        unix_sed "/<client>/r ${TMP_SERVER}" ${CONF_FILE}
    fi

    rm -f ${TMP_SERVER}

}

add_parameter () {
    if [ ! -z "$3" ]; then
        OPTIONS="$1 $2 $3"
    fi
    echo ${OPTIONS}
}

get_deprecated_vars () {
    if [ ! -z "${WAZUH_MANAGER_IP}" ] && [ -z "${WAZUH_MANAGER}" ]; then
        WAZUH_MANAGER=${WAZUH_MANAGER_IP}
    fi
    if [ ! -z "${WAZUH_AUTHD_SERVER}" ] && [ -z "${WAZUH_REGISTRATION_SERVER}" ]; then
        WAZUH_REGISTRATION_SERVER=${WAZUH_AUTHD_SERVER}
    fi
    if [ ! -z "${WAZUH_AUTHD_PORT}" ] && [ -z "${WAZUH_REGISTRATION_PORT}" ]; then
        WAZUH_REGISTRATION_PORT=${WAZUH_AUTHD_PORT}
    fi
    if [ ! -z "${WAZUH_PASSWORD}" ] && [ -z "${WAZUH_REGISTRATION_PASSWORD}" ]; then
        WAZUH_REGISTRATION_PASSWORD=${WAZUH_PASSWORD}
    fi
    if [ ! -z "${WAZUH_NOTIFY_TIME}" ] && [ -z "${WAZUH_KEEP_ALIVE_INTERVAL}" ]; then
        WAZUH_KEEP_ALIVE_INTERVAL=${WAZUH_NOTIFY_TIME}
    fi
    if [ ! -z "${WAZUH_CERTIFICATE}" ] && [ -z "${WAZUH_REGISTRATION_CA}" ]; then
        WAZUH_REGISTRATION_CA=${WAZUH_CERTIFICATE}
    fi
    if [ ! -z "${WAZUH_PEM}" ] && [ -z "${WAZUH_REGISTRATION_CERTIFICATE}" ]; then
        WAZUH_REGISTRATION_CERTIFICATE=${WAZUH_PEM}
    fi
    if [ ! -z "${WAZUH_KEY}" ] && [ -z "${WAZUH_REGISTRATION_KEY}" ]; then
        WAZUH_REGISTRATION_KEY=${WAZUH_KEY}
    fi
    if [ ! -z "${WAZUH_GROUP}" ] && [ -z "${WAZUH_AGENT_GROUP}" ]; then
        WAZUH_AGENT_GROUP=${WAZUH_GROUP}
    fi
}

set_vars () {
    export WAZUH_MANAGER=$(launchctl getenv WAZUH_MANAGER)
    export WAZUH_MANAGER_PORT=$(launchctl getenv WAZUH_MANAGER_PORT)
    export WAZUH_PROTOCOL=$(launchctl getenv WAZUH_PROTOCOL)
    export WAZUH_REGISTRATION_SERVER=$(launchctl getenv WAZUH_REGISTRATION_SERVER)
    export WAZUH_REGISTRATION_PORT=$(launchctl getenv WAZUH_REGISTRATION_PORT)
    export WAZUH_REGISTRATION_PASSWORD=$(launchctl getenv WAZUH_REGISTRATION_PASSWORD)
    export WAZUH_KEEP_ALIVE_INTERVAL=$(launchctl getenv WAZUH_KEEP_ALIVE_INTERVAL)
    export WAZUH_TIME_RECONNECT=$(launchctl getenv WAZUH_TIME_RECONNECT)
    export WAZUH_REGISTRATION_CA=$(launchctl getenv WAZUH_REGISTRATION_CA)
    export WAZUH_REGISTRATION_CERTIFICATE=$(launchctl getenv WAZUH_REGISTRATION_CERTIFICATE)
    export WAZUH_REGISTRATION_KEY=$(launchctl getenv WAZUH_REGISTRATION_KEY)
    export WAZUH_AGENT_NAME=$(launchctl getenv WAZUH_AGENT_NAME)
    export WAZUH_AGENT_GROUP=$(launchctl getenv WAZUH_AGENT_GROUP)
    export ENROLLMENT_DELAY=$(launchctl getenv ENROLLMENT_DELAY)

    # The following variables are yet supported but all of them are deprecated
    export WAZUH_MANAGER_IP=$(launchctl getenv WAZUH_MANAGER_IP)
    export WAZUH_NOTIFY_TIME=$(launchctl getenv WAZUH_NOTIFY_TIME)
    export WAZUH_AUTHD_SERVER=$(launchctl getenv WAZUH_AUTHD_SERVER)
    export WAZUH_AUTHD_PORT=$(launchctl getenv WAZUH_AUTHD_PORT)
    export WAZUH_PASSWORD=$(launchctl getenv WAZUH_PASSWORD)
    export WAZUH_GROUP=$(launchctl getenv WAZUH_GROUP)
    export WAZUH_CERTIFICATE=$(launchctl getenv WAZUH_CERTIFICATE)
    export WAZUH_KEY=$(launchctl getenv WAZUH_KEY)
    export WAZUH_PEM=$(launchctl getenv WAZUH_PEM)
}

unset_vars() {

    OS=$1

    vars=(WAZUH_MANAGER_IP WAZUH_PROTOCOL WAZUH_MANAGER_PORT WAZUH_NOTIFY_TIME \
          WAZUH_TIME_RECONNECT WAZUH_AUTHD_SERVER WAZUH_AUTHD_PORT WAZUH_PASSWORD \
          WAZUH_AGENT_NAME WAZUH_GROUP WAZUH_CERTIFICATE WAZUH_KEY WAZUH_PEM \
          WAZUH_MANAGER WAZUH_REGISTRATION_SERVER WAZUH_REGISTRATION_PORT \
          WAZUH_REGISTRATION_PASSWORD WAZUH_KEEP_ALIVE_INTERVAL WAZUH_REGISTRATION_CA \
          WAZUH_REGISTRATION_CERTIFICATE WAZUH_REGISTRATION_KEY WAZUH_AGENT_GROUP \
          ENROLLMENT_DELAY)

    for var in "${vars[@]}"; do
        if [ "${OS}" = "Darwin" ]; then
            launchctl unsetenv ${var}
        fi
        unset ${var}
    done
}

# Function to convert strings to lower version
tolower () {
    echo $1 | tr '[:upper:]' '[:lower:]'
}


# Add auto-enrollment configuration block
add_auto_enrollment () {
    start_config="$(grep -n "<enrollment>" ${CONF_FILE} | cut -d':' -f 1)"
    end_config="$(grep -n "</enrollment>" ${CONF_FILE} | cut -d':' -f 1)"
    if [ -n "${start_config}" ] && [ -n "${end_config}" ]; then
        start_config=$(( start_config + 1 ))
        end_config=$(( end_config - 1 ))
        sed -n "${start_config},${end_config}p" ${INSTALLDIR}/etc/ossec.conf >> "${TMP_ENROLLMENT}"
    else
        # Write the client configuration block
        echo "    <enrollment>" >> "${TMP_ENROLLMENT}"
        echo "      <enabled>yes</enabled>" >> "${TMP_ENROLLMENT}"
        echo "      <manager_address>MANAGER_IP</manager_address>" >> "${TMP_ENROLLMENT}"
        echo "      <port>1515</port>" >> "${TMP_ENROLLMENT}"
        echo "      <agent_name>agent</agent_name>" >> "${TMP_ENROLLMENT}"
        echo "      <groups>Group1</groups>" >> "${TMP_ENROLLMENT}"
        echo "      <server_ca_path>/path/to/server_ca</server_ca_path>" >> "${TMP_ENROLLMENT}"
        echo "      <agent_certificate_path>/path/to/agent.cert</agent_certificate_path>" >> "${TMP_ENROLLMENT}"
        echo "      <agent_key_path>/path/to/agent.key</agent_key_path>" >> "${TMP_ENROLLMENT}"
        echo "      <delay_after_enrollment>20</delay_after_enrollment>" >> "${TMP_ENROLLMENT}"
        echo "    </enrollment>" >> "${TMP_ENROLLMENT}"
    fi
}

# Add the auto_enrollment block to the configuration file
concat_conf() {
    if [ "${use_unix_sed}" = "False" ] ; then
        ${sed} "/<\/crypto_method>/r ${TMP_ENROLLMENT}" ${CONF_FILE}
    else
        unix_sed "/<\/crypto_method>/r ${TMP_ENROLLMENT}/" ${CONF_FILE}
    fi

    rm -f ${TMP_ENROLLMENT}
}

# Set autoenrollment configuration
set_auto_enrollment_tag_value () {
    tag="$1"
    value="$2"

    if [ ! -z "${value}" ]; then
        edit_value_tag "${tag}" ${value} "auto_enrollment"
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
    elif [ "${uname_s}" = "AIX" ] || [ "${uname_s}" = "SunOS" ] || [ "${uname_s}" = "HP-UX" ]; then
        use_unix_sed="True"
    fi

    get_deprecated_vars

    edit_value_tag "port" ${WAZUH_MANAGER_PORT}

    if [ ! -z ${WAZUH_REGISTRATION_SERVER} ] || [ ! -z ${WAZUH_REGISTRATION_PORT} ] || [ ! -z ${WAZUH_REGISTRATION_CA} ] || [ ! -z ${WAZUH_REGISTRATION_CERTIFICATE} ] || [ ! -z ${WAZUH_REGISTRATION_KEY} ] || [ ! -z ${WAZUH_AGENT_NAME} ] || [ ! -z ${WAZUH_AGENT_GROUP} ] || [ ! -z ${ENROLLMENT_DELAY} ]; then
        add_auto_enrollment
        set_auto_enrollment_tag_value "manager_address" ${WAZUH_REGISTRATION_SERVER}
        set_auto_enrollment_tag_value "port" ${WAZUH_REGISTRATION_PORT}
        set_auto_enrollment_tag_value "server_ca_path" ${WAZUH_REGISTRATION_CA}
        set_auto_enrollment_tag_value "agent_certificate_path" ${WAZUH_REGISTRATION_CERTIFICATE}
        set_auto_enrollment_tag_value "agent_key_path" ${WAZUH_REGISTRATION_KEY}
        set_auto_enrollment_tag_value "agent_name" ${WAZUH_AGENT_NAME}
        set_auto_enrollment_tag_value "groups" ${WAZUH_AGENT_GROUP}
        set_auto_enrollment_tag_value "delay_after_enrollment" ${ENROLLMENT_DELAY}
        delete_blank_lines ${TMP_ENROLLMENT}
        concat_conf
    fi

            
    if [ ! -z ${WAZUH_REGISTRATION_PASSWORD} ]; then
        echo ${WAZUH_REGISTRATION_PASSWORD} > "${INSTALLDIR}/etc/authd.pass"
    fi

    if [ ! -z ${WAZUH_MANAGER} ]; then
        if [ ! -f ${INSTALLDIR}/logs/ossec.log ]; then
            touch -f ${INSTALLDIR}/logs/ossec.log
            chmod 660 ${INSTALLDIR}/logs/ossec.log
            chown root:wazuh ${INSTALLDIR}/logs/ossec.log
        fi

        # Check if multiples IPs are defined in variable WAZUH_MANAGER
        WAZUH_MANAGER=$(echo ${WAZUH_MANAGER} | sed "s#,#;#g")
        ADDRESSES="$(echo ${WAZUH_MANAGER} | awk '{split($0,a,";")} END{ for (i in a) { print a[i] } }' |  tr '\n' ' ')"
        if echo ${ADDRESSES} | grep ' ' > /dev/null 2>&1 ; then
            # Get uniques values
            ADDRESSES=$(echo "${ADDRESSES}" | tr ' ' '\n' | sort -u | tr '\n' ' ')
            add_adress_block "${ADDRESSES}"
            if [ -z ${WAZUH_REGISTRATION_SERVER} ]; then
                WAZUH_REGISTRATION_SERVER="$(echo $ADDRESSES | cut -d ' ' -f 1)"
            fi
        else
            # Single address
            edit_value_tag "address" ${WAZUH_MANAGER}
            if [ -z ${WAZUH_REGISTRATION_SERVER} ]; then
                WAZUH_REGISTRATION_SERVER="${WAZUH_MANAGER}"
            fi
        fi
    fi

    # Options to be modified in ossec.conf
    edit_value_tag "protocol" "$(tolower ${WAZUH_PROTOCOL})"
    edit_value_tag "notify_time" ${WAZUH_KEEP_ALIVE_INTERVAL}
    edit_value_tag "time-reconnect" ${WAZUH_TIME_RECONNECT}

    unset_vars ${uname_s}
}

# Start script execution
main "$@"
