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
# Where WAZUH_ENROLLMENT_TOKEN is left for the agent to finish the bootstrap with at its
# first start. Root-only, unlike authd.pass: the agent reads it before dropping privileges,
# so the wazuh user never needs it.
WAZUH_ENROLLMENT_TOKEN_PATH="etc/enrollment_token"
WAZUH_MACOS_AGENT_DEPLOYMENT_VARS="/tmp/wazuh_envs"


# Set default sed alias
sed="sed -ri"

# The ERR_ codes are refusals, which stop the run; INFO_NO_MANAGER is not, the agent simply
# has no address, which is a supported way to install one that is configured or enrolled later.
WET_INFO_NO_MANAGER="INFO_NO_MANAGER"
WET_ERR_BAD_TOKEN="ERR_BAD_TOKEN"
WET_ERR_NO_DECODER="ERR_NO_DECODER"

# The sixteen names the token replaced. Still read, so an install carrying a 4.x-era command or
# an untouched playbook is told what happened.
REMOVED_VARS=(WAZUH_MANAGER WAZUH_MANAGER_IP WAZUH_MANAGER_PORT WAZUH_MANAGER_ENDPOINT \
              WAZUH_REGISTRATION_PASSWORD WAZUH_PASSWORD \
              WAZUH_REGISTRATION_SERVER WAZUH_REGISTRATION_PORT \
              WAZUH_REGISTRATION_CERTIFICATE WAZUH_REGISTRATION_KEY \
              WAZUH_AUTHD_SERVER WAZUH_AUTHD_PORT WAZUH_PEM WAZUH_KEY \
              WAZUH_REGISTRATION_CA WAZUH_CERTIFICATE)

# A deployment-variable refusal: a named code, in both sinks. The code is what a test greps for
# and what an operator quotes, so it is part of the contract rather than decoration.
deployment_refusal() {

    echo "$(date '+%Y/%m/%d %H:%M:%S') Deployment variables refused [${1}]: ${2}" \
        >> "${INSTALLDIR}/logs/ossec.log"
    echo "wazuh-agent: deployment variables refused [${1}]: ${2}" >&2

}

# Same two sinks and the same named-code contract, for an outcome that is not a refusal: the
# install is complete and correct, it just has nowhere to connect yet.
deployment_notice() {

    echo "$(date '+%Y/%m/%d %H:%M:%S') No manager configured [${1}]: ${2}" \
        >> "${INSTALLDIR}/logs/ossec.log"
    echo "wazuh-agent: no manager configured [${1}]: ${2}" >&2

}

# A deployment variable that no longer does anything: say so, and write nothing. Not a refusal of
# the whole run. One obsolete variable left in a playbook should not stop an install and
# never silent either.
dead_variable() {

    echo "$(date '+%Y/%m/%d %H:%M:%S') ${1} is not supported in 5.0 and was ignored: ${2}" \
        >> "${INSTALLDIR}/logs/ossec.log"
    echo "wazuh-agent: ${1} is not supported in 5.0 and was ignored: ${2}" >&2

}

# Report every removed name that was still passed, and the pre-rename spelling of the one
# variable that survived. Warn-and-ignore rather than silence.
warn_removed_variables() {

    for wrv_name in "${REMOVED_VARS[@]}"; do
        if [ -n "${!wrv_name}" ]; then
            dead_variable "${wrv_name}" "registration is configured by WAZUH_ENROLLMENT_TOKEN alone; this variable no longer has any effect."
        fi
    done

    # Renamed, not removed, and with no alias -- so an install still passing the old spelling
    # would silently get no verification mode at all and fall through the resolution ladder.
    if [ -n "${SSL_VERIFICATION}" ]; then
        dead_variable "SSL_VERIFICATION" "renamed to WAZUH_SSL_VERIFICATION; the old name is not read."
    fi

}

# ossec.log has to exist before anything logs to it, or the first writer creates it root-owned
# and 0644 instead of root:wazuh 0660.
ensure_ossec_log() {

    if [ ! -f "${INSTALLDIR}/logs/ossec.log" ]; then
        touch -f "${INSTALLDIR}/logs/ossec.log"
        chmod 660 "${INSTALLDIR}/logs/ossec.log"
        chown root:wazuh "${INSTALLDIR}/logs/ossec.log"
    fi

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
#
# [ \t] not [[:space:]]: Debian 10's mawk 1.3.3 lacks POSIX bracket expressions and
# silently fails to match them.
insert_into_agent_block() {

    # $2 is the opening-tag pattern to insert right after, e.g. "ssl" for
    # set_agent_verification_mode()'s fresh-block fallback; defaults to <agent>/<client> for
    # every other caller.
    target_tag="${2:-agent|client}"

    awk -v payload_file="$1" -v target_tag="${target_tag}" '
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
        !inserted && $0 ~ ("^[ \t]*<(" target_tag ")>[ \t]*$") {
            print
            printf "%s", payload
            inserted = 1
            next
        }
        {
            if ($0 ~ /<!--/ && $0 !~ /-->/) { in_comment = 1 }
            print
        }
        END { if (!inserted) { exit 1 } }
    ' "${CONF_FILE}" > "${TMP_INSERT}"
    inserted=$?

    if [ "${inserted}" -eq 0 ]; then
        cat "${TMP_INSERT}" > "${CONF_FILE}"
    fi
    rm -f "${TMP_INSERT}"

    return "${inserted}"

}
# True when the option is really set, as opposed to appearing inside a comment.
# Commented-out options are exactly how the shipped files used to show an example,
# and editing one leaves the setting the caller asked for unwritten.
#
# Scoped to <agent> (or <agent><$2> when a second argument is given), mirroring
# xml_tag_present()'s <block><sub><tag> scoping in pkg_installer.sh -- unscoped, this
# would match a same-named tag anywhere else in the file, not just the one this script
# means to edit. $2 omitted means "direct child of <agent>" (e.g. "ssl" itself).
agent_option_is_set() {

    # Matches both <tag> and the self-closing <tag/> -- OS_XML parses the two as
    # equivalent (see test_simple_nodes3, src/unit_tests/os_xml, and xml_tag_present()'s
    # identical convention in pkg_installer.sh), so a self-closing, present-but-empty tag
    # must count as "set" here too, or set_agent_verification_mode() would insert a second,
    # duplicate <verification_mode> right alongside it.
    # $2 is passed to awk as "subtag", not "sub" -- gawk reserves "sub" as its builtin
    # string-substitution function and refuses to bind a variable of that name at all
    # (a fatal error, not a warning; caught empirically, this was the first version).
    awk -v tag="$1" -v subtag="$2" '
        in_comment {
            if ($0 ~ /-->/) { in_comment = 0 }
            next
        }
        $0 ~ /<!--/ && $0 !~ /-->/ { in_comment = 1; next }
        $0 ~ /^[ \t]*<agent>[ \t]*$/ { in_agent = 1; next }
        $0 ~ /^[ \t]*<\/agent>[ \t]*$/ { in_agent = 0; next }
        !in_agent { next }
        subtag != "" && $0 ~ ("^[ \t]*<" subtag ">[ \t]*$") { in_sub = 1; next }
        subtag != "" && $0 ~ ("^[ \t]*</" subtag ">[ \t]*$") { in_sub = 0; next }
        subtag != "" && !in_sub { next }
        $0 ~ "^[ \t]*<" tag "([ \t]*/)?>" { found = 1; exit }
        END { exit found ? 0 : 1 }
    ' "${CONF_FILE}"

}

# Text content of a tag, comment-aware like agent_option_is_set and scoped the same way
# (<agent>, or <agent><$2> when a second argument is given) -- empty if the tag is
# absent, commented out, or present only outside that scope.
agent_option_value() {

    tag="$1"
    sub="$2"

    # Strips comments and flattens newlines first, instead of matching one line ($0) at
    # a time -- mirrors strip_xml_comments() + tr -d '\n\r' in pkg_installer.sh's
    # xml_value(), so a value split across multiple lines is still seen (matching $0
    # alone is blind to it, and set_agent_verification_mode()'s replace-in-place path depends
    # on this returning the real value, not an empty string, to work at all).
    flattened="$(awk '
        in_comment {
            if ($0 ~ /-->/) { in_comment = 0 }
            next
        }
        # A self-contained one-line comment ("<!-- ... -->") must be dropped here too --
        # the grep -o chain below does unanchored substring matching on the flattened
        # result, so a commented-out example left in would otherwise be read as live.
        $0 ~ /<!--/ && $0 ~ /-->/ { next }
        $0 ~ /<!--/ && $0 !~ /-->/ { in_comment = 1; next }
        { print }
    ' "${CONF_FILE}" | tr -d '\n\r')"

    # Same nested grep -o chain as xml_value() in pkg_installer.sh: narrow to <agent>,
    # then to <$2> when given, before looking for $1 -- so a same-named tag outside
    # that scope is never seen.
    scoped="$(printf '%s' "${flattened}" | grep -o "<agent>.*</agent>")"
    if [ -n "${sub}" ]; then
        scoped="$(printf '%s' "${scoped}" | grep -o "<${sub}>.*</${sub}>")"
    fi

    # Takes the last match, not the first -- ReadConfig()'s own "last value wins"
    # semantics, and what xml_value() already does. [[:space:]], not a literal space:
    # a tab-indented, multi-line value would otherwise keep a leading tab after trim.
    printf '%s' "${scoped}" | grep -o "<${tag}>[^<]*</${tag}>" | tail -1 | \
        sed -e "s|<${tag}>||" -e "s|</${tag}>||" -e 's|^[[:space:]]*||' -e 's|[[:space:]]*$||'

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

# Replaces an existing <tag> inside <agent><ssl>, handling the self-closing
# (<tag/>), single-line-paired, and multi-line-paired forms in one pass. Unlike
# edit_value_tag()'s blind whole-file sed, this only ever looks inside <agent><ssl>,
# so a same-named tag elsewhere in the file (e.g. a <localfile> block that happens to
# define one) is never touched -- confirmed empirically: edit_value_tag() alone
# rewrites such a decoy too, since its substitution isn't scoped at all. Only called
# after agent_option_is_set() has confirmed the tag is present within that same scope.
replace_agent_ssl_tag() {

    tag="$1"
    value="$2"

    # Plain string concatenation throughout below (match()+substr(), never sub()'s
    # replacement-text argument) -- deliberately, not an oversight: gawk's own -v
    # assignment already strips a literal backslash out of "\&" before the awk program
    # even runs (confirmed empirically: `awk -v v='A\&B' 'BEGIN{print v}'` prints "A&B"
    # with a warning), so a caller-side sed escape meant to survive sub()'s '&'/'\&'
    # convention never survives to reach it -- and a bare, unescaped '&' in `value`
    # (which XML-escaping itself introduces, as part of "&amp;"/"&lt;"/"&gt;") is
    # completely inert in a plain concatenation, so no escaping of `value` is needed here.
    # Collects (drops) every occurrence of <tag> found inside <agent><ssl> -- self-closing,
    # single-line-paired, or multi-line-paired -- and inserts exactly one, correct
    # occurrence right before </ssl> once the block ends. Rather than stopping at the
    # first match: the real parser applies last-tag-wins (ReadConfig()'s own semantics,
    # the same reasoning agent_option_value() above already honors via tail -1), so a
    # leftover duplicate (e.g. from an interrupted prior install run) sitting after the
    # first, updated one would silently win at runtime if only the first were touched.
    awk -v tag="${tag}" -v value="${value}" '
        in_comment {
            if ($0 ~ /-->/) { in_comment = 0 }
            print
            next
        }
        $0 ~ /<!--/ {
            # A self-contained one-line comment (e.g. "<!-- <tag>x</tag> -->", the
            # shipped-template convention for a commented-out example) must be printed
            # and skipped whole -- the unanchored tag patterns below match anywhere on
            # the line, unlike agent_option_is_set()s ^-anchored check, so without this
            # a commented-out example would be mistaken for the live tag to rewrite.
            print
            if ($0 !~ /-->/) { in_comment = 1 }
            next
        }
        $0 ~ /^[ \t]*<agent>[ \t]*$/ { in_agent = 1; print; next }
        $0 ~ /^[ \t]*<\/agent>[ \t]*$/ { in_agent = 0; print; next }
        !in_agent { print; next }
        $0 ~ /^[ \t]*<ssl>[ \t]*$/ { in_ssl = 1; print; next }
        $0 ~ /^[ \t]*<\/ssl>[ \t]*$/ {
            in_ssl = 0
            if (found) {
                print "      <" tag ">" value "</" tag ">"
                done = 1
            }
            print
            next
        }
        !in_ssl { print; next }
        collecting {
            found = 1
            if ($0 ~ ("</" tag ">")) { collecting = 0 }
            next
        }
        match($0, "<" tag "[ \t]*/>") { found = 1; next }
        match($0, "<" tag ">.*</" tag ">") { found = 1; next }
        $0 ~ ("<" tag ">") && $0 !~ ("</" tag ">") { collecting = 1; found = 1; next }
        { print }
        END { if (!done) { exit 1 } }
    ' "${CONF_FILE}" > "${TMP_SERVER}"
    replaced=$?

    if [ "${replaced}" -eq 0 ]; then
        cat "${TMP_SERVER}" > "${CONF_FILE}"
    fi
    rm -f "${TMP_SERVER}"

    return "${replaced}"

}

# Route WAZUH_SSL_VERIFICATION into <agent><ssl><verification_mode>. The only TLS variable left
# once the token became the sole registration path: nothing writes <certificate_authorities> at
# install time any more, since a token install gets its anchor from the bootstrap and a
# token-less one is being configured by hand anyway.
set_agent_verification_mode() {

    mode="$1"

    if [ -z "${mode}" ]; then
        return
    fi

    # Matches Read_Agent_SSL()'s own case-sensitive strcmp (src/config/src/client-config.c):
    # a value that reads as valid to a human but not to the parser (e.g. 'System',
    # 'None') would install cleanly and then fail at agent startup instead of here,
    # where the operator can still see and fix it immediately.
    case "${mode}" in
        full|certificate|system|none) ;;
        *)
            echo "$(date '+%Y/%m/%d %H:%M:%S') Invalid WAZUH_SSL_VERIFICATION '${mode}': must be exactly one of full, certificate, system, none. Leaving <verification_mode> unset." >> "${INSTALLDIR}/logs/ossec.log"
            return
            ;;
    esac

    if agent_option_is_set "verification_mode" "ssl"; then
        # replace_agent_ssl_tag(), not edit_value_tag(): the latter's substitution is a
        # blind whole-file sed with no <agent><ssl> scoping, and only recognizes the
        # paired <tag>...</tag> form, so it would miss a self-closing or multi-line tag and
        # would happily rewrite a same-named tag somewhere else in the file.
        if ! replace_agent_ssl_tag "verification_mode" "${mode}"; then
            echo "$(date '+%Y/%m/%d %H:%M:%S') Error updating verification_mode with variable ${mode}." >> "${INSTALLDIR}/logs/ossec.log"
        fi
        return
    fi

    if agent_option_is_set "ssl"; then
        echo "      <verification_mode>${mode}</verification_mode>" > "${TMP_SERVER}"
        if ! insert_into_agent_block "${TMP_SERVER}" "ssl"; then
            echo "$(date '+%Y/%m/%d %H:%M:%S') Could not pin WAZUH_SSL_VERIFICATION into <ssl><verification_mode>: an existing <ssl> block was found but not in the expected format (opening tag not alone on its own line)." >> "${INSTALLDIR}/logs/ossec.log"
        fi
        rm -f "${TMP_SERVER}"
        return
    fi

    {
        echo "    <ssl>"
        echo "      <verification_mode>${mode}</verification_mode>"
        echo "    </ssl>"
    } > "${TMP_SERVER}"
    # "agent" only, never the default agent|client: a 4.x <client> block is read by
    # Read_Legacy_Client(), which never looks at <ssl>, so a block pinned there would
    # report success while staying inert.
    if ! insert_into_agent_block "${TMP_SERVER}" "agent"; then
        echo "$(date '+%Y/%m/%d %H:%M:%S') Could not pin WAZUH_SSL_VERIFICATION into a fresh <ssl> block: no <agent> opening tag found to insert after." >> "${INSTALLDIR}/logs/ossec.log"
    fi
    rm -f "${TMP_SERVER}"

}

delete_auto_enrollment_tag() {

    # Delete the configuration tag if its value is empty
    # This will allow using the default value
    ${sed} "s#.*<$1>.*</$1>.*##g" "${TMP_ENROLLMENT}"

    cat -s "${TMP_ENROLLMENT}" > "${TMP_ENROLLMENT}.tmp"
    mv "${TMP_ENROLLMENT}.tmp" "${TMP_ENROLLMENT}"

}

# Decode WAZUH_ENROLLMENT_TOKEN once, into TOKEN_ADR and TOKEN_HAS_KEY.
#
# Decoding is delegated to the agent's own --show-token rather than done in shell: the token is
# base64url of a JSON object, and reusing w_etoken_decode() means a token accepted at install
# time is exactly a token the bootstrap will accept at first start. It goes in on stdin, never
# as an argument -- the credential would otherwise reach ps output and the shell history. What
# comes back never contains the credential, only whether one is present.
decode_enrollment_token() {

    TOKEN_ADR=""
    TOKEN_HAS_KEY="no"

    det_description="$(printf '%s' "${WAZUH_ENROLLMENT_TOKEN}" | "${INSTALLDIR}/bin/wazuh-agentd" --show-token)"
    det_status="$?"

    # A rejected token and a decoder that never ran are different problems and send an operator
    # to different places, so they are reported apart rather than both as a bad token. Only the
    # decoder's own exit code says which: a missing binary or an unresolved shared library exits
    # 127, well away from the status it uses for a token it read and refused. The reason for a
    # refusal is already on stderr, so only the consequence is added here.
    if [ "${det_status}" -eq 2 ]; then
        deployment_refusal "${WET_ERR_BAD_TOKEN}" "WAZUH_ENROLLMENT_TOKEN was refused by the token decoder; no manager was configured from it and no token was stored."
        return 1
    elif [ "${det_status}" -ne 0 ]; then
        deployment_refusal "${WET_ERR_NO_DECODER}" "could not run '${INSTALLDIR}/bin/wazuh-agentd --show-token' (exit ${det_status}); the enrollment token was left unread and no token was stored."
        return 1
    fi

    TOKEN_ADR="$(printf '%s\n' "${det_description}" | sed -n 's/^adr: //p')"

    case "$(printf '%s\n' "${det_description}" | sed -n 's/^credential: //p')" in
        present) TOKEN_HAS_KEY="yes" ;;
    esac

    if [ -z "${TOKEN_ADR}" ]; then
        deployment_refusal "${WET_ERR_BAD_TOKEN}" "WAZUH_ENROLLMENT_TOKEN carries no address; no token was stored."
        return 1
    fi

}

# Settle the deployment variables before anything is written. The enrollment token
# is the only way to register, so there is very little left to conflict: what survives is the
# absence case, and the one variable that can still defeat a token after the install.
#
# Runs ahead of every writer. A token that cannot be honoured must never end in an unverified
# enrollment, and a refusal discovered halfway through would already have written a <manager>
# block. Refusing here leaves the configuration the package shipped.
#
# Returns 1 only when a token was supplied and is unusable -- nothing at all is then written. A
# missing token is reported and returns 0: registration does not happen, but the variables that
# were never about registration (agent name, groups, timers, verification mode) still apply,
# which is what a hand-configured install needs.
#
# Kept in lockstep with config() in src/win32/InstallerScripts.vbs; a change here belongs there.
resolve_deployment_conflicts() {

    TOKEN_PRESENT="no"

    warn_removed_variables

    if [ -z "${WAZUH_ENROLLMENT_TOKEN}" ]; then
        deployment_notice "${WET_INFO_NO_MANAGER}" "WAZUH_ENROLLMENT_TOKEN was not supplied, so the agent does not know where to connect."
        return 0
    fi

    decode_enrollment_token || return 1

    TOKEN_PRESENT="yes"

    return 0

}

# Leave the token where the agent picks it up: w_agent_token_bootstrap() reads
# AGENT_ENROLLMENT_TOKEN_FILE once at the first start, before the privilege drop, fetches the
# CA, checks it against the token's pin, writes the trust anchor and unlinks this file.
#
# Root-only, unlike authd.pass: the agent reads it while still root, so the wazuh user never
# needs it and must not be able to substitute the token that chooses its certificate authority.
store_enrollment_token() {

    set_token_path="${INSTALLDIR}/${WAZUH_ENROLLMENT_TOKEN_PATH}"

    # Created and locked down before the token is written into it, so the credential is never
    # briefly readable -- a reinstall would otherwise keep whatever mode the old file had.
    : > "${set_token_path}"
    chmod 600 "${set_token_path}"
    chown root:root "${set_token_path}"
    printf '%s' "${WAZUH_ENROLLMENT_TOKEN}" > "${set_token_path}"

    echo "$(date '+%Y/%m/%d %H:%M:%S') Enrollment token stored; the manager was set to '${TOKEN_ADR}' and the trust anchor will be bootstrapped at the first agent start." >> "${INSTALLDIR}/logs/ossec.log"

}

# Change address block of the wazuh configuration file
add_adress_block() {

    # Remove both server and legacy manager configuration blocks
    ${sed} "/<manager>/,/\/manager>/d; /<server>/,/\/server>/d" "${CONF_FILE}"

    # A 5.x file is <agent><manager>; a 4.x file preserved across an in-place upgrade is
    # <client><server>, and the 5.x parser reads the address out of <client> only under <server>
    # -- writing <manager> there leaves the agent with nothing it will read. Same rule as
    # config() in src/win32/InstallerScripts.vbs, which picks the wrapper the same way.
    if grep -q "<agent>" "${CONF_FILE}"; then
        aab_wrapper="manager"
    else
        aab_wrapper="server"
    fi

    {
        echo "    <${aab_wrapper}>"
        echo "      <endpoint>${FINAL_ENDPOINT}</endpoint>"
        echo "    </${aab_wrapper}>"
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

# Only the two aliases whose targets survived the collapse. Every other alias named a removed
# variable, so it is reported by warn_removed_variables() rather than mapped onto anything.
get_deprecated_vars () {

    if [ -n "${WAZUH_NOTIFY_TIME}" ] && [ -z "${WAZUH_KEEP_ALIVE_INTERVAL}" ]; then
        WAZUH_KEEP_ALIVE_INTERVAL=${WAZUH_NOTIFY_TIME}
    fi
    if [ -n "${WAZUH_GROUP}" ] && [ -z "${WAZUH_AGENT_GROUP}" ]; then
        WAZUH_AGENT_GROUP=${WAZUH_GROUP}
    fi

}

set_vars () {

    export WAZUH_ENROLLMENT_TOKEN
    export WAZUH_AGENT_NAME
    export WAZUH_AGENT_GROUP
    export WAZUH_KEEP_ALIVE_INTERVAL
    export WAZUH_TIME_RECONNECT
    export ENROLLMENT_DELAY
    export WAZUH_SSL_VERIFICATION
    # Deprecated aliases of variables that survived
    export WAZUH_NOTIFY_TIME
    export WAZUH_GROUP
    # Removed. Exported only so a value still set in /tmp/wazuh_envs reaches
    # warn_removed_variables() and gets reported, rather than being silently invisible here.
    export SSL_VERIFICATION
    # shellcheck disable=SC2163
    for sv_name in "${REMOVED_VARS[@]}"; do
        export "${sv_name}"
    done

    if [ -r "${WAZUH_MACOS_AGENT_DEPLOYMENT_VARS}" ]; then
        . ${WAZUH_MACOS_AGENT_DEPLOYMENT_VARS}
        rm -rf "${WAZUH_MACOS_AGENT_DEPLOYMENT_VARS}"
    fi

}

unset_vars() {

    vars=(WAZUH_ENROLLMENT_TOKEN WAZUH_AGENT_NAME WAZUH_AGENT_GROUP WAZUH_GROUP \
          WAZUH_KEEP_ALIVE_INTERVAL WAZUH_NOTIFY_TIME WAZUH_TIME_RECONNECT \
          ENROLLMENT_DELAY WAZUH_SSL_VERIFICATION SSL_VERIFICATION \
          "${REMOVED_VARS[@]}")

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
            echo "      <agent_name>agent</agent_name>"
            echo "      <groups>Group1</groups>"
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

    # Before anything that might log. Every refusal and every ignored-variable notice lands in
    # ossec.log, and whichever of them fired first would otherwise create it root-owned and 0644
    # instead of root:wazuh 0660.
    ensure_ossec_log

    # Settle every variable against every other one before the first writer runs, so a refusal
    # returns before any of them and no token is stored -- that is what keeps a refused token
    # from ending in an unverified enrollment. It is not a rollback: add_adress_block() further
    # down deletes the existing <manager> block before inserting its replacement, so a file that
    # insert cannot match is left without one whatever this gate decides.
    if ! resolve_deployment_conflicts; then
        unset_vars
        return 1
    fi

    # The token's address is the only thing that reaches <endpoint>, and it is written verbatim.
    # No validation here: w_etoken_decode() checks 'adr' against the same grammar before
    # --show-token will print it at all (ETOKEN_BAD_ADR), so a malformed address never gets past
    # the decoder, and re-checking it in shell would be a second implementation of a rule the
    # codec already owns.
    if [ "${TOKEN_PRESENT}" = "yes" ]; then
        FINAL_ENDPOINT="${TOKEN_ADR}"
        add_adress_block
    fi

    # Honoured in both supported shapes: alongside a token, where it overrides the mode the
    # bootstrapped anchor would have resolved to on its own, and alongside an endpoint, where
    # it is the only TLS input there is.
    set_agent_verification_mode "${WAZUH_SSL_VERIFICATION}"

    # What is left of <enrollment>: the three settings that were never about registration.
    if [ -n "${WAZUH_AGENT_NAME}" ] || [ -n "${WAZUH_AGENT_GROUP}" ] || [ -n "${ENROLLMENT_DELAY}" ]; then
        add_auto_enrollment
        set_auto_enrollment_tag_value "agent_name" "${WAZUH_AGENT_NAME}"
        set_auto_enrollment_tag_value "groups" "${WAZUH_AGENT_GROUP}"
        set_auto_enrollment_tag_value "delay_after_enrollment" "${ENROLLMENT_DELAY}"
        delete_blank_lines "${TMP_ENROLLMENT}"
        concat_conf
    fi

    # Options to be modified in wazuh configuration file
    set_agent_option "notify_time" "${WAZUH_KEEP_ALIVE_INTERVAL}"
    edit_value_tag "time-reconnect" "${WAZUH_TIME_RECONNECT}"

    if [ "${TOKEN_PRESENT}" = "yes" ]; then
        store_enrollment_token
    fi

    unset_vars

}

# Guarded so this file can be sourced by the test suite without running the full
# install flow; every packaged caller invokes it directly as its own process, where
# BASH_SOURCE[0] == $0 either way.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    main "$@"
fi
