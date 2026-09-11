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

# Strips commented-out lines before xml_value/xml_tag_present extract anything, so a
# tag an operator comments out (e.g. to fall back to the default) reads as absent
# here too, matching OS_XML's own comment handling -- same in_comment line-tracking
# technique register_configure_agent.sh's agent_option_value() already uses. Like
# that one, a comment that opens and closes on the same line is not stripped: every
# comment actually shipped in this codebase's XML wraps whole indented lines, so
# that trade-off is accepted here too rather than fixed once and left inconsistent
# elsewhere.
strip_xml_comments() {
    awk '
        in_comment {
            if ($0 ~ /-->/) { in_comment = 0 }
            next
        }
        # A self-contained one-line comment ("<!-- ... -->", both on this line) must be
        # dropped whole here too, not just a comment that opens on this line and closes
        # later -- xml_value()/xml_tag_present() do unanchored substring matching on the
        # output, so a commented-out example left in would be read as live.
        $0 ~ /<!--/ && $0 ~ /-->/ { next }
        $0 ~ /<!--/ && $0 !~ /-->/ { in_comment = 1; next }
        { print }
    ' ./etc/ossec.conf 2>/dev/null
}

# Read <block><sub><tag> from the agent configuration, taking the last match.
xml_value() {
    # [[:space:]], not a literal space: tr -d '\n\r' above collapses a multi-line,
    # tab-indented value onto one line, and a leading tab that survived would make a
    # perfectly valid path fail [ -f ] right after (confirmed empirically).
    strip_xml_comments | tr -d '\n\r' | grep -o "<$1>.*</$1>" | \
        grep -o "<$2>.*</$2>" | grep -o "<$3>[^<]*</$3>" | tail -1 | \
        sed -e "s|<$3>||" -e "s|</$3>||" -e 's|^[[:space:]]*||' -e 's|[[:space:]]*$||'
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
    strip_xml_comments | tr -d '\n\r' | grep -o "<$1>.*</$1>" | \
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
# Shared by probe_server()/probe_server_verified(), which differ only in which curl/wget
# flags decide whether to accept the manager's certificate, not in how the target URL is
# built. Sets PROBE_HOST/PROBE_PATH from ($1=host $2=port $3=endpoint).
probe_build_target() {
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
}

probe_server() {
    PROBE_TIMEOUT=5
    probe_build_target "${1}" "${2}" "${3}"

    if command -v curl > /dev/null 2>&1; then
        curl --tlsv1.3 -k -s -f -m ${PROBE_TIMEOUT} -o /dev/null "https://${PROBE_HOST}:${2}${PROBE_PATH}"
        RC=$?
        [ ${RC} -eq 0 ] && return 0
        # Only exit 2/4 (this curl can't do TLS 1.3, #38607) falls through to TCP; the rest is real.
        [ ${RC} -ne 2 ] && [ ${RC} -ne 4 ] && return ${RC}
        echo "$(date +"%Y/%m/%d %H:%M:%S") - curl lacks TLS 1.3 support, falling back to a TCP connectivity check (manager endpoint not verified)." >> ./logs/upgrade.log
    elif command -v wget > /dev/null 2>&1; then
        wget -q --no-check-certificate --timeout=${PROBE_TIMEOUT} --tries=1 -O /dev/null "https://${PROBE_HOST}:${2}${PROBE_PATH}"
        return $?
    else
        echo "$(date +"%Y/%m/%d %H:%M:%S") - Neither curl nor wget found, falling back to a TCP connectivity check." >> ./logs/upgrade.log
    fi
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

# Same target as probe_server(), but without -k: succeeds only if the system's own
# trust store actually verifies the manager's certificate. probe_server() cannot tell
# us this -- it deliberately skips verification so a plain reachability check never
# depends on TLS trust -- but it is exactly what AGENT_VERIFY_SYSTEM needs to work
# post-upgrade. No TCP fallback here: a client that cannot do the real handshake
# cannot tell us whether the cert is trusted, so treat that as "unverified" rather
# than assume trust -- this deliberately stays fail-closed even for the curl-too-old
# case below, since there is no way to positively confirm trust without the
# handshake; only the log message distinguishes the two causes for the operator.
probe_server_verified() {
    PROBE_TIMEOUT=5
    probe_build_target "${1}" "${2}" "${3}"

    if command -v curl > /dev/null 2>&1; then
        curl --tlsv1.3 -s -f -m ${PROBE_TIMEOUT} -o /dev/null "https://${PROBE_HOST}:${2}${PROBE_PATH}"
        RC=$?
        # Mirrors probe_server()'s own curl-too-old handling (#38607): exit 2/4 means
        # curl itself doesn't recognize --tlsv1.3, not that the handshake was
        # attempted and failed -- worth a distinct log line so an operator doesn't
        # mistake "this curl build is too old" for "the manager's certificate is
        # untrusted".
        if [ ${RC} -eq 2 ] || [ ${RC} -eq 4 ]; then
            echo "$(date +"%Y/%m/%d %H:%M:%S") - curl lacks TLS 1.3 support, so the manager's certificate could not be verified (not the same as an untrusted certificate)." >> ./logs/upgrade.log
        fi
        return ${RC}
    elif command -v wget > /dev/null 2>&1; then
        wget -q --timeout=${PROBE_TIMEOUT} --tries=1 -O /dev/null "https://${PROBE_HOST}:${2}${PROBE_PATH}"
        return $?
    else
        return 1
    fi
}

# Default drop-in location for the manager's CA (mirrored on Windows in
# do_upgrade.ps1): an operator can place it here ahead of an upgrade without having
# to hand-edit ossec.conf, and it also doubles as the on-disk anchor path for a CA
# delivered by the manager (below). Resolves to /var/ossec/etc/certs/root-ca.pem on
# a default install.
DEFAULT_CA_FILE="./etc/certs/root-ca.pem"

# Detect and validate a manager-delivered CA. The manager streams its root
# CA into var/incoming under this reserved filename over the com channel, before
# issuing the upgrade command -- never look in var/upgrade, since
# com upgrade's cldir_ex(UPGRADE_DIR) has already cleared it by the time this script
# runs. Runs at the very start of the script, ahead of the manager connectivity
# check and the <ssl> gate below.
#
# Installing the file is the entire cutover here -- ossec.conf is never edited.
# That is a deliberate, narrower scope than the issue's full "Install the anchor"/
# "Do not override deliberate operator configuration" sections: this build has no
# anchor-driven verification (confirmed against moduleConfig.cpp's validateTls()
# and config.c -- verifyMode/caPath come strictly from parsed config, nothing
# probes a conventional anchor path), so a file placed here does not by itself
# change what mode the upgraded agent boots into. Wiring it into <ssl> is left for
# a separate, explicitly recorded decision rather than done implicitly here.
INCOMING_CA_FILE="./var/incoming/root-ca.pem"

# Set once the delivered CA passes validation; it is installed further down, past
# the last gate that can abort this upgrade.
CA_VALIDATED=0

if [ -L "${INCOMING_CA_FILE}" ]; then
    # var/incoming is written by com's own transfer, but is not exclusively
    # Wazuh-controlled -- reject a symlink outright rather than read or copy
    # through it, same reasoning as this codebase's own w_fopen_nofollow() for
    # this same directory.
    echo "$(date +"%Y/%m/%d %H:%M:%S") - A CA arrived at ${INCOMING_CA_FILE} as a symlink; refusing to follow it, discarding it and continuing the upgrade unverified." >> ./logs/upgrade.log
    rm -f "${INCOMING_CA_FILE}"
elif [ -f "${INCOMING_CA_FILE}" ]; then
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Found a CA delivered by the manager at ${INCOMING_CA_FILE}, validating it." >> ./logs/upgrade.log

    CA_REJECT_REASON=""
    CA_TOOL_MISSING=0
    CA_SNAPSHOT="./var/upgrade/.root-ca.pem.incoming-snapshot.$$"

    # var/incoming is not exclusively Wazuh-controlled: a file that validated as a
    # legitimate CA a moment ago could be swapped for a symlink to a sensitive
    # file (e.g. /etc/shadow) before a later step re-reads the same path. The
    # top-level -L check above and this point are several statements apart --
    # wide enough for that swap -- so re-check immediately adjacent to the only
    # read of this path, not just once at the top of this block: the narrowest
    # window achievable without O_NOFOLLOW-capable tooling. -L again also
    # catches a symlink swapped in since the top-level check; find's own
    # default (physical/lstat) mode would see a freshly-swapped-in symlink's
    # own link count (usually 1), not catch it via -links alone, so both checks
    # run together, immediately before the cp, rather than relying on either
    # alone. Snapshot into our own copy under var/upgrade (not
    # attacker-writable) and validate/install from that snapshot alone from
    # here on, so nothing after this point ever re-opens the attacker-
    # influenced path.
    if [ -L "${INCOMING_CA_FILE}" ] || [ -n "$(find "${INCOMING_CA_FILE}" -links +1 2>/dev/null)" ]; then
        CA_REJECT_REASON="is a symlink or has more than one hard link"
    elif ! cp "${INCOMING_CA_FILE}" "${CA_SNAPSHOT}" 2>/dev/null; then
        CA_REJECT_REASON="could not be read"
    fi

    # A missing openssl is an environment problem, not evidence the delivered file
    # itself is bad -- every openssl invocation below would fail not-found (exit
    # 127) exactly like a real parse failure looks, silently destroying a possibly-
    # valid delivery via the unconditional cleanup further down instead of leaving
    # it for a retry once openssl is available. Reported and handled distinctly so
    # an operator isn't misled into troubleshooting the certificate instead of the
    # missing tool, and so the incoming file isn't deleted for a reason that has
    # nothing to do with its own content.
    if [ -z "${CA_REJECT_REASON}" ] && ! command -v openssl > /dev/null 2>&1; then
        CA_REJECT_REASON="cannot be validated: openssl was not found on this host"
        CA_TOOL_MISSING=1
    fi

    # Cheap bound before invoking openssl at all: empty or implausibly large for
    # a CA certificate is rejected the same way a malformed one is, without ever
    # parsing it.
    if [ -z "${CA_REJECT_REASON}" ]; then
        CA_BYTES=$(wc -c < "${CA_SNAPSHOT}" 2>/dev/null)
        CA_BYTES=${CA_BYTES:-0}

        if [ "${CA_BYTES}" -eq 0 ] || [ "${CA_BYTES}" -gt 65536 ]; then
            CA_REJECT_REASON="is empty or larger than the 64 KiB a CA certificate should ever need"
        elif [ "$(grep -c -- "-----BEGIN CERTIFICATE-----" "${CA_SNAPSHOT}" 2>/dev/null)" -gt 1 ]; then
            # openssl x509 parses only the first certificate in a multi-cert PEM file
            # and silently ignores the rest -- a manager delivery is expected to be
            # exactly one self-signed root, never a bundle/chain, so reject this
            # shape explicitly rather than silently act on only part of the file.
            CA_REJECT_REASON="contains more than one certificate (expected exactly one self-signed root)"
        elif ! openssl x509 -in "${CA_SNAPSHOT}" -noout > /dev/null 2>&1; then
            CA_REJECT_REASON="does not parse as a PEM certificate"
        elif ! openssl x509 -in "${CA_SNAPSHOT}" -noout -text 2>/dev/null | grep -A1 "X509v3 Basic Constraints" | grep -q "CA:TRUE"; then
            CA_REJECT_REASON="is not a CA certificate (no X509v3 Basic Constraints CA:TRUE)"
        else
            CA_NOT_BEFORE=$(openssl x509 -in "${CA_SNAPSHOT}" -noout -startdate 2>/dev/null | cut -d= -f2-)
            CA_NOT_AFTER=$(openssl x509 -in "${CA_SNAPSHOT}" -noout -enddate 2>/dev/null | cut -d= -f2-)
            NOW_EPOCH=$(date +%s)
            # openssl's notBefore/notAfter come out as "Mon D HH:MM:SS YYYY TZ" (e.g.
            # "Sep 10 19:55:53 2026 GMT"). GNU date -d parses that directly; BSD date
            # (macOS) has no -d and needs strptime-style -j -f instead, or every valid
            # CA is silently rejected here as having an "unparsable validity period".
            #
            # TZ=UTC on these two calls specifically: BSD date -j converts the parsed
            # struct tm via mktime(), which always interprets it in the process's own
            # local timezone regardless of what %Z matched in the input string --
            # openssl's output is unconditionally GMT, so without forcing TZ=UTC here,
            # a host west of UTC would compute an epoch shifted later than the real
            # notBefore/notAfter (east of UTC, shifted earlier), silently rejecting a
            # genuinely-valid, freshly-issued CA as "not yet valid".
            if [[ "$OS" == "Darwin" ]]; then
                CA_NOT_BEFORE_EPOCH=$(TZ=UTC date -j -f "%b %e %T %Y %Z" "${CA_NOT_BEFORE}" +%s 2>/dev/null)
                CA_NOT_AFTER_EPOCH=$(TZ=UTC date -j -f "%b %e %T %Y %Z" "${CA_NOT_AFTER}" +%s 2>/dev/null)
            else
                CA_NOT_BEFORE_EPOCH=$(date -d "${CA_NOT_BEFORE}" +%s 2>/dev/null)
                CA_NOT_AFTER_EPOCH=$(date -d "${CA_NOT_AFTER}" +%s 2>/dev/null)
            fi

            if [ -z "${CA_NOT_BEFORE_EPOCH}" ] || [ -z "${CA_NOT_AFTER_EPOCH}" ]; then
                CA_REJECT_REASON="has an unparsable validity period"
            elif [ "${NOW_EPOCH}" -lt "${CA_NOT_BEFORE_EPOCH}" ]; then
                CA_REJECT_REASON="is not yet valid (notBefore ${CA_NOT_BEFORE})"
            elif [ "${NOW_EPOCH}" -gt "${CA_NOT_AFTER_EPOCH}" ]; then
                CA_REJECT_REASON="has expired (notAfter ${CA_NOT_AFTER})"
            fi
        fi
    fi

    if [ "${CA_TOOL_MISSING}" = "1" ]; then
        # Left in place rather than removed (see the cleanup below): this isn't a bad
        # delivery, just an environment that couldn't validate it this run, so a
        # later upgrade attempt (with openssl available) should still get to try.
        echo "$(date +"%Y/%m/%d %H:%M:%S") - Delivered CA at ${INCOMING_CA_FILE} ${CA_REJECT_REASON}; leaving it in place for a later upgrade attempt and continuing unverified." >> ./logs/upgrade.log
    elif [ -n "${CA_REJECT_REASON}" ]; then
        # A malformed/expired/non-CA file must not break the upgrade, nor be left
        # behind for a later upgrade to pick up -- remove it below same as on success.
        echo "$(date +"%Y/%m/%d %H:%M:%S") - Delivered CA at ${INCOMING_CA_FILE} ${CA_REJECT_REASON}; refusing to install it and continuing without it." >> ./logs/upgrade.log
    else
        # Written only once the remaining gates have passed (see below).
        CA_VALIDATED=1
        echo "$(date +"%Y/%m/%d %H:%M:%S") - Delivered CA at ${INCOMING_CA_FILE} is valid; holding it until this script's remaining checks pass, then installing it at ${DEFAULT_CA_FILE}." >> ./logs/upgrade.log
    fi

    # Kept while an install is still pending: the snapshot is its source, and leaving
    # the delivered file lets an aborted upgrade retry against the same delivery.
    if [ "${CA_VALIDATED}" != "1" ]; then
        rm -f "${CA_SNAPSHOT}"
        if [ "${CA_TOOL_MISSING}" != "1" ]; then
            rm -f "${INCOMING_CA_FILE}"
        fi
    fi
else
    echo "$(date +"%Y/%m/%d %H:%M:%S") - No CA delivered by the manager at ${INCOMING_CA_FILE} this run." >> ./logs/upgrade.log
fi

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
else
    # Retry a couple times in case the manager is briefly unreachable.
    PROBE_OK=1
    for PROBE_ATTEMPT in 1 2 3; do
        if probe_server "${SERVER_ADDRESS}" "${SERVER_PORT}" "${SERVER_ENDPOINT}"; then
            PROBE_OK=0
            break
        fi
        sleep 1
    done
    if [ ${PROBE_OK} -ne 0 ]; then
        echo "$(date +"%Y/%m/%d %H:%M:%S") - Upgrade failed. The manager is not reachable at ${SERVER_ADDRESS}:${SERVER_PORT}/${SERVER_ENDPOINT}, interrupting upgrade." >> ./logs/upgrade.log
        abort_upgrade "2"
    fi
    echo "$(date +"%Y/%m/%d %H:%M:%S") - Manager reachable at ${SERVER_ADDRESS}:${SERVER_PORT}/${SERVER_ENDPOINT}." >> ./logs/upgrade.log
fi

# The upgrade replaces the agent's binaries but not its ossec.conf, so the TLS
# posture the new agent boots under is exactly what's on disk now. A verifying mode
# with no readable CA can never connect -- mirrors
# w_agent_validate_ssl_ca() in config.c -- so catch it here, before the old agent
# is gone, rather than leaving a freshly-upgraded host silently offline.
SSL_VERIFICATION_MODE=$(xml_value agent ssl verification_mode)
SSL_CA=$(xml_value agent ssl certificate_authorities)
SSL_VERIFICATION_MODE_EXPLICIT=0
xml_tag_present agent ssl verification_mode && SSL_VERIFICATION_MODE_EXPLICIT=1

if [ -z "${SSL_VERIFICATION_MODE}" ]; then
    if [ "${SSL_VERIFICATION_MODE_EXPLICIT}" = "1" ]; then
        # <verification_mode/> (or <verification_mode></verification_mode>) is present
        # but carries no value -- xml_tag_present() counts it as present, same as
        # OS_XML does, but Read_Agent_SSL() rejects empty content as an unrecognized
        # value (XML_VALUEERR) same as any other typo. Treat it the same way here
        # instead of silently substituting the default on a config the new binary is
        # about to refuse to parse.
        echo "$(date +"%Y/%m/%d %H:%M:%S") - Upgrade failed. <ssl><verification_mode> is present but empty, interrupting upgrade." >> ./logs/upgrade.log
        abort_upgrade "2"
    elif [ -n "${SSL_CA}" ]; then
        SSL_VERIFICATION_MODE="certificate"
    else
        SSL_VERIFICATION_MODE="system"
    fi
fi

# Whether the currently-installed (pre-upgrade) agent predates 5.0, queried now
# because the package below replaces it. A genuine 4.x config is always
# <client>-only -- Read_Legacy_Client_Address() (config.c) never reads <ssl> under
# <client> -- so that agent cannot express TLS verification via ossec.conf, edit or
# not. It also does not need to for safety: under implicit 'system' mode,
# w_agent_validate_ssl_ca() (config.c) only refuses to start when no OS CA bundle
# exists at all, never when that bundle simply fails to verify this particular
# manager -- so letting a legacy upgrade proceed past that specific failure below
# does not risk the fail-closed outage this gate exists to prevent. An
# already-5.x agent gets no such pass: it has had every chance to be configured
# correctly, so the strict check remains in force for it.
CURRENT_AGENT_VERSION=""
if command -v dpkg-query > /dev/null 2>&1; then
    CURRENT_AGENT_VERSION=$(dpkg-query -W -f='${Version}' wazuh-agent 2>/dev/null)
fi
if [ -z "${CURRENT_AGENT_VERSION}" ] && command -v rpm > /dev/null 2>&1; then
    CURRENT_AGENT_VERSION=$(rpm -q --qf '%{VERSION}' wazuh-agent 2>/dev/null)
fi

CURRENT_AGENT_MAJOR="${CURRENT_AGENT_VERSION%%.*}"
IS_LEGACY_AGENT=0
case "${CURRENT_AGENT_MAJOR}" in
    ''|*[!0-9]*) ;; # unknown or unparsable (e.g. macOS, no package manager match) -- never assume legacy from a guess
    *) [ "${CURRENT_AGENT_MAJOR}" -lt 5 ] && IS_LEGACY_AGENT=1 ;;
esac

# Same path as AGENT_ANCHOR_CA (src/shared/include/defs.h), which the agent now reads
# directly: a present, readable file here supplies the verification state for anything
# <ssl> left unsaid, so the resolution this gate mirrors above is no longer the one the
# upgraded binary applies. Two rows diverge: an unset <verification_mode>, which this gate
# resolves to 'system' and the new binary to 'full' with the anchor present or 'none'
# without it; and a config with no readable <certificate_authorities>, which this gate
# aborts on and the new binary starts with. An explicit mode is honoured unchanged.
# Reconciling the rest is still open; no verdict below was changed for it, but the state
# that drives the divergence is logged.

# One already on disk and one validated this run but not yet written reach the same
# post-upgrade state, so the checks below ask this instead of testing the file.
ANCHOR_AVAILABLE=0
if { [ -f "${DEFAULT_CA_FILE}" ] && [ -r "${DEFAULT_CA_FILE}" ]; } || [ "${CA_VALIDATED}" = "1" ]; then
    ANCHOR_AVAILABLE=1
fi

if [ "${ANCHOR_AVAILABLE}" = "1" ]; then
    echo "$(date +"%Y/%m/%d %H:%M:%S") - A trust anchor will be in place at ${DEFAULT_CA_FILE} for the upgraded agent. It verifies with 'full' against that file when <ssl> names no <verification_mode>, and uses it as the default <certificate_authorities>. An explicit <verification_mode> is honoured unchanged." >> ./logs/upgrade.log
else
    # No anchor at all -- neither delivered this run nor left over from a previous
    # one -- and <ssl> left unset resolves to 'none' without it: the upgraded agent
    # will run unverified. Say so plainly, since this is the one remaining path to
    # an unverified 5.0 agent and it must be obvious, not silent.
    echo "$(date +"%Y/%m/%d %H:%M:%S") - No trust anchor is present at ${DEFAULT_CA_FILE}; the upgraded agent will run unverified unless <ssl><verification_mode> and <certificate_authorities> are configured explicitly. To enable verification: place the manager's CA at ${DEFAULT_CA_FILE} and re-run the upgrade, or configure <certificate_authorities> explicitly and restart the agent." >> ./logs/upgrade.log
fi

case "${SSL_VERIFICATION_MODE}" in
    full|certificate)
        if [ -z "${SSL_CA}" ] || [ ! -f "${SSL_CA}" ] || [ ! -r "${SSL_CA}" ]; then
            echo "$(date +"%Y/%m/%d %H:%M:%S") - Upgrade failed. <ssl><verification_mode> is '${SSL_VERIFICATION_MODE}' but <certificate_authorities> ('${SSL_CA}') is missing or unreadable, interrupting upgrade." >> ./logs/upgrade.log
            abort_upgrade "2"
        fi
        ;;
    system)
        # verification_mode=system with a certificate_authorities also set is rejected
        # outright at runtime (validateTls() in moduleConfig.cpp) regardless of
        # whether the manager's certificate happens to verify against the OS store --
        # catch the config error itself here rather than let a live probe that
        # happens to pass mask a daemon that will refuse to start.
        if [ -n "${SSL_CA}" ]; then
            echo "$(date +"%Y/%m/%d %H:%M:%S") - Upgrade failed. <ssl><verification_mode> is 'system' but <certificate_authorities> ('${SSL_CA}') is also set; 'system' trusts the OS store, not a configured CA, and the agent refuses to start with both set. Remove <certificate_authorities>, or switch to <verification_mode>certificate</verification_mode>, interrupting upgrade." >> ./logs/upgrade.log
            abort_upgrade "2"
        fi

        # 'system' trusts the OS store, not a configured CA -- probe_server() above
        # cannot tell us whether that store actually trusts THIS manager's
        # certificate, since it deliberately skips verification (-k) so the plain
        # reachability check never depends on TLS trust. Find out for real before
        # assuming the freshly-upgraded agent will still be able to connect.
        if [ "${WAZUH_UPGRADE_TEST_SKIP_MANAGER_CHECK}" = "1" ]; then
            echo "$(date +"%Y/%m/%d %H:%M:%S") - System CA trust check skipped (test mode)." >> ./logs/upgrade.log
        elif probe_server_verified "${SERVER_ADDRESS}" "${SERVER_PORT}" "${SERVER_ENDPOINT}"; then
            echo "$(date +"%Y/%m/%d %H:%M:%S") - The system trust store already verifies the manager's certificate; proceeding under verify_mode=system." >> ./logs/upgrade.log
        elif [ "${SSL_VERIFICATION_MODE_EXPLICIT}" = "1" ]; then
            # <verification_mode>system</verification_mode> was set explicitly:
            # pinning a CA here would be rejected at runtime (validateTls() in
            # moduleConfig.cpp refuses system+certificate_authorities together), so
            # there is nothing this script can safely fix on the operator's behalf.
            echo "$(date +"%Y/%m/%d %H:%M:%S") - Upgrade failed. <ssl><verification_mode> is explicitly 'system' but the system trust store does not verify the manager's certificate at ${SERVER_ADDRESS}:${SERVER_PORT}. Import it into the OS trust store, or switch to <verification_mode>certificate</verification_mode> with a <certificate_authorities> path, interrupting upgrade." >> ./logs/upgrade.log
            abort_upgrade "2"
        elif [ "${ANCHOR_AVAILABLE}" = "1" ]; then
            # <verification_mode> was left unset (not explicit), so the new binary
            # resolves purely from anchor presence -- 'full' against DEFAULT_CA_FILE --
            # regardless of what this gate's own 'system' resolution or the OS trust
            # store say (see the divergence noted above). A usable
            # anchor is available (validated this run and installed once the gates pass,
            # or left over from a previous delivery), which is a different, equally
            # sufficient path to a working post-upgrade connection -- this is precisely
            # the scenario this feature exists for. Checked ahead of IS_LEGACY_AGENT
            # since an already-5.x agent needs this path too: without it, a 5.x agent
            # receiving its manager's CA for the first time would have the anchor
            # installed and then abort anyway, never reaching a state where it takes
            # effect.
            echo "$(date +"%Y/%m/%d %H:%M:%S") - The system trust store does not verify the manager's certificate at ${SERVER_ADDRESS}:${SERVER_PORT}, but a trust anchor is present at ${DEFAULT_CA_FILE} and <ssl><verification_mode> is unset -- the upgraded agent resolves to 'full' against that anchor regardless of the OS trust store, so proceeding." >> ./logs/upgrade.log
        elif [ "${IS_LEGACY_AGENT}" = "1" ]; then
            # The currently-installed agent (pre-upgrade) predates 5.0: its <client>-only
            # config cannot express TLS verification regardless of what this script does
            # (see CURRENT_AGENT_VERSION above), and 'system' mode's real fail-closed
            # condition -- no OS CA bundle at all -- does not apply here. Proceed rather
            # than block a legacy migration over a check that agent was never able to
            # pass in the first place.
            echo "$(date +"%Y/%m/%d %H:%M:%S") - The system trust store does not verify the manager's certificate at ${SERVER_ADDRESS}:${SERVER_PORT}, but the currently-installed agent (${CURRENT_AGENT_VERSION}) predates 5.0 and its config cannot express TLS verification either way -- proceeding unverified. No trust anchor is present at ${DEFAULT_CA_FILE}; place one there and re-run the upgrade, or configure <certificate_authorities> explicitly after the upgrade, to enable verification." >> ./logs/upgrade.log
        else
            # Reached only when no usable anchor is present at all (the branch above
            # already handles the case where one is) -- ossec.conf is never modified
            # by this script, so there is genuinely nothing more it can do here.
            echo "$(date +"%Y/%m/%d %H:%M:%S") - Upgrade failed. The system trust store does not verify the manager's certificate at ${SERVER_ADDRESS}:${SERVER_PORT}, and no trust anchor is present at ${DEFAULT_CA_FILE}. Place the manager's CA there and retry, or configure <certificate_authorities> explicitly; interrupting upgrade." >> ./logs/upgrade.log
            abort_upgrade "2"
        fi
        ;;
    none)
        # Nothing for this gate to check: 'none' needs no CA and reaches no trust store, and
        # the upgraded binary honours it whether or not an anchor is on disk.
        ;;
    *)
        # Neither ReadConfig() nor this gate's own default-resolution above can produce
        # anything but full/certificate/system/none, so getting here means ossec.conf
        # carries something else (a typo, wrong case, hand-edited garbage). Read_Agent_SSL()
        # rejects that value case-sensitively too, so letting the upgrade proceed would just
        # trade this loud failure for the new binary refusing to start after the old one is
        # already gone.
        echo "$(date +"%Y/%m/%d %H:%M:%S") - Upgrade failed. <ssl><verification_mode> is '${SSL_VERIFICATION_MODE}', which is not a value this agent recognizes (full, certificate, system, or none); interrupting upgrade." >> ./logs/upgrade.log
        abort_upgrade "2"
        ;;
esac

# Installed only past the last gate that can abort: with <verification_mode> unset the
# anchor's mere presence flips the agent to 'full' on its next restart, so writing it
# earlier left an aborted upgrade with a changed trust posture on the old version.
if [ "${CA_VALIDATED}" = "1" ]; then
    # An operator can point <certificate_authorities> at this exact default path
    # themselves (rather than relying on manager delivery) -- comparing resolved
    # paths where possible, since the config value and DEFAULT_CA_FILE are rarely
    # written the same way (absolute vs. relative) even when they name the same
    # file. Overwriting still proceeds either way (the manager is authoritative
    # for its own CA), but a collision with an operator's own explicit pin is a
    # more consequential event than routine anchor rotation and deserves its own,
    # louder log line rather than reading identically to one.
    OPERATOR_CA_PATH=$(xml_value agent ssl certificate_authorities)
    CA_PINNED_HERE=0
    if [ -n "${OPERATOR_CA_PATH}" ]; then
        if command -v readlink > /dev/null 2>&1 \
            && [ -n "$(readlink -f "${OPERATOR_CA_PATH}" 2>/dev/null)" ] \
            && [ "$(readlink -f "${OPERATOR_CA_PATH}" 2>/dev/null)" = "$(readlink -f "${DEFAULT_CA_FILE}" 2>/dev/null)" ]; then
            CA_PINNED_HERE=1
        elif [ "${OPERATOR_CA_PATH}" = "${DEFAULT_CA_FILE}" ]; then
            CA_PINNED_HERE=1
        fi
    fi

    # Replacing an already-present anchor is a bigger event than a first install --
    # the manager is authoritative for its own CA, so this always proceeds, but the
    # operator should be able to grep for the distinction rather than see the same
    # "Installed" line either way.
    if [ "${CA_PINNED_HERE}" = "1" ]; then
        CA_INSTALL_VERB="Overwrote the operator-pinned (<certificate_authorities>${OPERATOR_CA_PATH}</certificate_authorities>)"
    elif [ -f "${DEFAULT_CA_FILE}" ]; then
        CA_INSTALL_VERB="Replaced the existing"
    else
        CA_INSTALL_VERB="Installed the delivered"
    fi

    DEFAULT_CA_DIR="$(dirname "${DEFAULT_CA_FILE}")"
    mkdir -p "${DEFAULT_CA_DIR}" 2>/dev/null
    # mkdir -p's mode is whatever the umask leaves it -- looser than the rest
    # of etc/, which is root:wazuh 0770. Match that convention explicitly
    # rather than let a first-ever delivery leave a world-traversable certs
    # directory.
    chown root:wazuh "${DEFAULT_CA_DIR}" 2>/dev/null
    chmod 750 "${DEFAULT_CA_DIR}" 2>/dev/null

    # Install atomically: write to a temp file in the same directory, then
    # rename over the target, so a reader never observes a partially-written
    # anchor, and a failed cp/mv is caught here instead of silently logging
    # success with nothing actually installed. Sourced from the snapshot, not
    # INCOMING_CA_FILE, for the same TOCTOU reason noted above.
    CA_TMP="${DEFAULT_CA_DIR}/.root-ca.pem.$$"
    if cp "${CA_SNAPSHOT}" "${CA_TMP}" 2>/dev/null && mv -f "${CA_TMP}" "${DEFAULT_CA_FILE}" 2>/dev/null; then
        # root:wazuh 640, matching the existing wpk_root.pem trust anchor: readable by
        # the wazuh group the daemon runs under, but owned (and only writable) by root
        # -- a daemon that can rewrite its own anchor is not a boundary at all.
        chown root:wazuh "${DEFAULT_CA_FILE}" 2>/dev/null
        chmod 640 "${DEFAULT_CA_FILE}" 2>/dev/null

        # A present, readable anchor here is picked up automatically at agent startup
        # and resolves an unset <verification_mode> to 'full' against it -- so this
        # alone is sufficient to activate verification; no <ssl> edit is needed.
        echo "$(date +"%Y/%m/%d %H:%M:%S") - ${CA_INSTALL_VERB} CA at ${DEFAULT_CA_FILE}. ossec.conf is not modified, but this alone is sufficient to activate certificate verification: the agent resolves an unset <verification_mode> to 'full' against a present, readable anchor at this path." >> ./logs/upgrade.log
    else
        echo "$(date +"%Y/%m/%d %H:%M:%S") - Could not install the delivered CA at ${DEFAULT_CA_FILE} (write failure); leaving any existing anchor untouched and continuing the upgrade." >> ./logs/upgrade.log
        rm -f "${CA_TMP}" 2>/dev/null
    fi

    rm -f "${CA_SNAPSHOT}"
    rm -f "${INCOMING_CA_FILE}"
fi

# Whether the package manager's own install hooks can be trusted to have already
# stopped and restarted the daemon (deb's preinst/postinst, rpm's %pre/%post -- both
# confirmed in this repo to use a wazuh.restart marker + an explicit stop-then-restart).
# Left 0 for apk and the install.sh fallback: install.sh's own stop helper never
# restarts, so wazuh-control status already reports "not running" there regardless, but
# no equivalent packaging/install hooks for apk exist anywhere in this codebase to
# confirm the same restart behavior -- treat it the same as the fallback rather than
# assume an unconfirmed package format behaves like deb/rpm.
PACKAGE_MANAGER_HANDLES_RESTART=0

if [[ "$OS" == "Darwin" ]]; then
    installer -pkg ./var/upgrade/wazuh-agent* -target / >> ./logs/upgrade.log 2>&1
elif [[ "$OS" == "Linux" ]]; then
    if pkg_exists ./var/upgrade/*.rpm; then
        if command -v rpm >/dev/null 2>&1; then
            # Set before, not after, the actual install command: RESULT=$? below reads
            # the exit status of the LAST command in whichever branch ran, and a plain
            # assignment always returns 0 -- placing this after rpm -UFvh would make
            # RESULT always read as success regardless of whether the package install
            # itself actually failed.
            PACKAGE_MANAGER_HANDLES_RESTART=1
            rpm -UFvh ./var/upgrade/wazuh-agent* >> ./logs/upgrade.log 2>&1
        else
            echo "$(date +"%Y/%m/%d %H:%M:%S") - Upgrade failed. RPM package found but rpm command not found." >> ./logs/upgrade.log
            abort_upgrade "2"
        fi
    elif pkg_exists ./var/upgrade/*.deb; then
        if command -v dpkg >/dev/null 2>&1; then
            # Same ordering reason as the rpm branch above.
            PACKAGE_MANAGER_HANDLES_RESTART=1
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
    if [[ "$OS" == "Darwin" ]]; then
        echo "$(date +"%Y/%m/%d %H:%M:%S") - Restarting Wazuh Agent." >> ./logs/upgrade.log
        launchctl bootstrap system /Library/LaunchDaemons/com.wazuh.agent.plist >> ./logs/upgrade.log 2>&1 || true
    elif [ "${PACKAGE_MANAGER_HANDLES_RESTART}" = "1" ] && ./bin/wazuh-control status 2>/dev/null | grep -q "wazuh-agentd is running"; then
        # deb's postinst / rpm's %post already stopped the pre-upgrade agent (preinst/%pre)
        # and restarted it after install -- via systemctl when the host runs systemd -- when
        # it finds the wazuh.restart marker those scripts drop. Calling wazuh-control restart
        # again here bypasses systemd and kills the daemon set it's still supervising as
        # wazuh-agent.service; systemd then marks the unit "deactivated" with nothing left to
        # bring it back up, and this script's own wait-for-connection loop below times out
        # against a dead agent. If wazuh-agentd is already up, trust that restart instead of
        # racing it.
        #
        # Gated on PACKAGE_MANAGER_HANDLES_RESTART (deb/rpm only): without it, a leftover
        # pre-upgrade wazuh-agentd process from an install method that does NOT restart on
        # its own (apk has no confirmed install hooks in this codebase; see where that flag
        # is set) would be misread as "already restarted," silently skipping the restart and
        # leaving the OLD binary running despite a logged success.
        echo "$(date +"%Y/%m/%d %H:%M:%S") - Wazuh Agent is already running (restarted by the package installer); skipping redundant restart." >> ./logs/upgrade.log
    else
        echo "$(date +"%Y/%m/%d %H:%M:%S") - Restarting Wazuh Agent." >> ./logs/upgrade.log
        ./bin/wazuh-control restart >> ./logs/upgrade.log 2>&1
    fi
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
