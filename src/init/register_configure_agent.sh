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
TMP_INSERT="${INSTALLDIR}/tmp/insert-output"
WAZUH_REGISTRATION_PASSWORD_PATH="etc/authd.pass"
WAZUH_MACOS_AGENT_DEPLOYMENT_VARS="/tmp/wazuh_envs"


# Set default sed alias
sed="sed -ri"

# Update the value of a XML tag inside the wazuh configuration file
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

# Insert a file's contents inside the agent configuration block, once.
#
# The opening tag has to be alone on its own line AND outside any comment to be
# matched, so a block someone commented out cannot take the insertion -- which is not
# hypothetical: commenting out the whole <agent> block is how you disable it, and the
# commented copy comes first in the file. A package upgrade keeps the 4.x file, where
# the block is still spelled <client>, hence both names.
#
# Written back through the existing file rather than moved over it, so the
# permissions and ownership ossec.conf was installed with survive.
insert_into_agent_block() {

    awk -v payload_file="$1" '
        BEGIN {
            while ((getline line < payload_file) > 0) {
                payload = payload line "\n"
            }
            close(payload_file)
        }
        in_comment {
            if ($0 ~ /-->/) { in_comment = 0 }
            print
            next
        }
        !inserted && /^[[:space:]]*<(agent|client)>[[:space:]]*$/ {
            print
            printf "%s", payload
            inserted = 1
            next
        }
        {
            if ($0 ~ /<!--/ && $0 !~ /-->/) { in_comment = 1 }
            print
        }
    ' "${CONF_FILE}" > "${TMP_INSERT}" && cat "${TMP_INSERT}" > "${CONF_FILE}"

    rm -f "${TMP_INSERT}"

}

# True when the option is really set, as opposed to appearing inside a comment.
# Commented-out options are exactly how the shipped files used to show an example,
# and editing one leaves the setting the caller asked for unwritten.
agent_option_is_set() {

    awk -v tag="$1" '
        in_comment {
            if ($0 ~ /-->/) { in_comment = 0 }
            next
        }
        $0 ~ "^[[:space:]]*<" tag ">" { found = 1; exit }
        { if ($0 ~ /<!--/ && $0 !~ /-->/) { in_comment = 1 } }
        END { exit found ? 0 : 1 }
    ' "${CONF_FILE}"

}

# Set an option of the agent block, adding it when the shipped configuration does
# not carry it. Options left at their default are no longer written to ossec.conf,
# so edit_value_tag alone would find nothing to substitute and quietly do nothing.
set_agent_option() {

    if [ -z "$2" ]; then
        return
    fi

    if agent_option_is_set "$1"; then
        edit_value_tag "$1" "$2"
        return
    fi

    echo "    <$1>$2</$1>" > "${TMP_SERVER}"
    insert_into_agent_block "${TMP_SERVER}"
    rm -f "${TMP_SERVER}"

}

delete_auto_enrollment_tag() {

    # Delete the configuration tag if its value is empty
    # This will allow using the default value
    ${sed} "s#.*<$1>.*</$1>.*##g" "${TMP_ENROLLMENT}"

    cat -s "${TMP_ENROLLMENT}" > "${TMP_ENROLLMENT}.tmp"
    mv "${TMP_ENROLLMENT}.tmp" "${TMP_ENROLLMENT}"

}

# Change address block of the wazuh configuration file
add_adress_block() {

    # Remove both server and legacy manager configuration blocks
    ${sed} "/<manager>/,/\/manager>/d; /<server>/,/\/server>/d" "${CONF_FILE}"

    # Only one <server> block is supported; if WAZUH_MANAGER carries several
    # comma-separated addresses, the last one prevails (server rotation was
    # removed, #37702 restrictions 2/3), matching the client parser.
    last_index=$(( ${#ADDRESSES[@]} - 1 ))
    {
        echo "    <server>"
        echo "      <address>${ADDRESSES[last_index]}</address>"
        echo "      <port>1517</port>"
        echo "    </server>"
    } >> "${TMP_SERVER}"

    insert_into_agent_block "${TMP_SERVER}"

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

    # Only the children are collected here; concat_conf writes the block around them.
    # The block is taken out as it is read, because concat_conf puts it back: leaving
    # the original in place is what used to give two enrollment blocks on a re-run.
    #
    # One awk pass rather than grep plus a sed range, because both mishandle a block
    # written on a single line. `sed "/<enrollment>/,/<\/enrollment>/d"` only starts
    # looking for the closing pattern on the line AFTER the opening match, so with
    # both tags on one line the range never closes and the delete runs to the end of
    # the file -- </agent>, every block below it and </ossec_config> along with it.
    # The grep line numbers have the mirror problem: start equals end, so the
    # "children" range is inverted and copies out the wrong line.
    #
    # Comments are skipped for the same reason insert_into_agent_block skips them: a
    # block someone commented out is not the one being configured. A second block is
    # dropped rather than left behind, so a re-run cannot accumulate them.
    #
    # Truncated up front: awk only opens the file when the block has children, so a
    # leftover from an interrupted run would otherwise be picked up as this one's.
    : > "${TMP_ENROLLMENT}"

    if awk -v children="${TMP_ENROLLMENT}" '
        in_comment {
            if ($0 ~ /-->/) { in_comment = 0 }
            print
            next
        }
        /<!--/ {
            if ($0 !~ /-->/) { in_comment = 1 }
            print
            next
        }
        in_block {
            if ($0 ~ /<\/enrollment>/) { in_block = 0; next }
            if (capture) { print > children }
            next
        }
        /<enrollment>/ {
            capture = !found
            found = 1
            if ($0 ~ /<\/enrollment>/) {
                # Whole block on one line: keep what sits between the tags.
                inner = $0
                sub(/^.*<enrollment>/, "", inner)
                sub(/<\/enrollment>.*$/, "", inner)
                if (capture && inner ~ /[^[:space:]]/) { print inner > children }
            } else {
                in_block = 1
            }
            next
        }
        { print }
        # An unterminated block means the file is not what we think it is; report it
        # as unusable so the copy is discarded and the original is left untouched.
        # Spelled out rather than with a ternary, which not every awk parses after
        # exit -- the macOS agent runs this through BSD awk.
        END {
            if (found && !in_block) { exit 0 }
            exit 1
        }
    ' "${CONF_FILE}" > "${TMP_INSERT}"; then
        cat "${TMP_INSERT}" > "${CONF_FILE}"
    else
        # No block to reuse. Truncating also drops whatever a half-read one left.
        {
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
        } > "${TMP_ENROLLMENT}"
    fi

    rm -f "${TMP_INSERT}"

}

# Add the auto_enrollment block to the configuration file
concat_conf() {

    # Anchored on the block that opens the agent configuration rather than on any
    # option inside it: the shipped file only carries what an install has to fill
    # in, so no individual option is guaranteed to be there to anchor on.
    #
    # The wrapper goes on here, not when the children are collected, so an option
    # edit_value_tag had to append lands inside the block rather than after it.
    {
        echo "    <enrollment>"
        cat "${TMP_ENROLLMENT}"
        echo "    </enrollment>"
    } > "${TMP_ENROLLMENT}.block"
    mv "${TMP_ENROLLMENT}.block" "${TMP_ENROLLMENT}"

    insert_into_agent_block "${TMP_ENROLLMENT}"

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

    # Options to be modified in wazuh configuration file
    set_agent_option "notify_time" "${WAZUH_KEEP_ALIVE_INTERVAL}"
    edit_value_tag "time-reconnect" "${WAZUH_TIME_RECONNECT}"

    unset_vars

}

# Start script execution
main "$@"
