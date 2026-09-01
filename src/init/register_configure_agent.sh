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

# Defaults substituted for the components WAZUH_MANAGER_ENDPOINT leaves out. The
# prefix mirrors the manager's own default global_prefix (#38491) and the port
# DEFAULT_HTTPS_REMOTE_PORT (src/config/include/client-config.h).
DEFAULT_MANAGER_PORT="1517"
DEFAULT_MANAGER_ENDPOINT="/wazuh-manager/"

mep_error() {

    echo "$(date '+%Y/%m/%d %H:%M:%S') Invalid WAZUH_MANAGER_ENDPOINT '${1}': ${2}" \
        >> "${INSTALLDIR}/logs/ossec.log"
    echo "wazuh-agent: invalid WAZUH_MANAGER_ENDPOINT '${1}': ${2}" >&2

}

# Validate WAZUH_MANAGER_ENDPOINT's value against the <endpoint> grammar (#38624):
#
#   [https://] host [:port] [/[prefix]]
#
# Only the host is mandatory; an omitted port or prefix takes its default at startup.
# <endpoint> now takes this same language, so the value is written into the config
# verbatim and this only decides whether to write it at all -- catching a typo during
# install, with the reason in ossec.log, rather than leaving the agent to fail later.
# MEP_HOST / MEP_PORT / MEP_ENDPOINT are still set, for callers that want the split.
#
# Kept in lockstep with WriteAgent()'s copy in inst-functions.sh and with
# ParseManagerEndpoint() in src/win32/InstallerScripts.vbs; a change here belongs in
# all three. Deliberately parameter-expansion only, no grep/sed/awk: this runs from
# package post-install, before anything guarantees a usable PATH.
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

    {
        echo "    <manager>"
        echo "      <endpoint>${FINAL_ENDPOINT}</endpoint>"
        echo "    </manager>"
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
    export WAZUH_MANAGER_ENDPOINT
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

    vars=(WAZUH_MANAGER_IP WAZUH_MANAGER_PORT WAZUH_MANAGER_ENDPOINT WAZUH_NOTIFY_TIME \
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

    # WAZUH_MANAGER_ENDPOINT carries the whole connection target (#38624) and takes
    # priority over everything else when set. WAZUH_MANAGER and WAZUH_MANAGER_PORT are
    # kept working: an <endpoint> is synthesized from them, so every existing 4.x-era
    # install command and dashboard snippet keeps configuring an agent correctly.
    #
    # ${VAR+x} rather than -n on the endpoint, so an explicitly empty value is rejected
    # instead of silently read as unset: "" used to be the prefix opt-out (#38614), and
    # an operator still passing it deserves the error rather than a default.
    # WAZUH_MANAGER_PORT only ever qualifies an address, so on its own there is nothing
    # to attach it to and no <manager> block gets written at all. Say so instead of
    # accepting the run and leaving the operator to discover the port was ignored.
    if [ -z "${WAZUH_MANAGER_ENDPOINT+x}" ] && [ -z "${WAZUH_MANAGER}" ] && [ -n "${WAZUH_MANAGER_PORT}" ]; then
        echo "WAZUH_MANAGER_PORT was set without WAZUH_MANAGER or WAZUH_MANAGER_ENDPOINT; it has no effect on its own." >&2
    fi

    if [ -n "${WAZUH_MANAGER_ENDPOINT+x}" ] || [ -n "${WAZUH_MANAGER}" ]; then
        if [ ! -f "${INSTALLDIR}/logs/ossec.log" ]; then
            touch -f "${INSTALLDIR}/logs/ossec.log"
            chmod 660 "${INSTALLDIR}/logs/ossec.log"
            chown root:wazuh "${INSTALLDIR}/logs/ossec.log"
        fi

        if [ -n "${WAZUH_MANAGER_ENDPOINT+x}" ]; then
            # Written through as given: <endpoint> takes the same language this variable
            # does, so parsing here only validates it and reports why a bad one was
            # refused. A rejected value writes no <manager> block at all -- leaving the
            # shipped placeholder makes the agent fail loudly at startup rather than
            # silently connect somewhere the operator did not ask for.
            if parse_manager_endpoint "${WAZUH_MANAGER_ENDPOINT}"; then
                FINAL_ENDPOINT="${WAZUH_MANAGER_ENDPOINT}"
                add_adress_block
            fi
        else
            # Only one <manager> block is supported; if WAZUH_MANAGER carries several
            # comma-separated addresses, the last one prevails (server rotation was
            # removed, #37702 restrictions 2/3), matching the client parser.
            ADDRESSES=( ${WAZUH_MANAGER//,/ } )
            FINAL_ENDPOINT="${ADDRESSES[$(( ${#ADDRESSES[@]} - 1 ))]}"

            # A bare IPv6 literal has to be bracketed once it shares a value with the
            # port, or its trailing group reads as one.
            case "${FINAL_ENDPOINT}" in
                # Already bracketed values must be left alone, or "[2001:db8::1]" becomes
                # "[[2001:db8::1]]" and the agent will not start. Matches the guard in
                # InstallerScripts.vbs.
                \[*) ;;
                *:*:*) FINAL_ENDPOINT="[${FINAL_ENDPOINT}]" ;;
            esac

            # Omitting the port leaves it to the agent's own default, so nothing is
            # appended -- the resulting value stays the shortest one that means this.
            if [ -n "${WAZUH_MANAGER_PORT}" ]; then
                FINAL_ENDPOINT="${FINAL_ENDPOINT}:${WAZUH_MANAGER_PORT}"
            fi

            add_adress_block
        fi
    fi

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
