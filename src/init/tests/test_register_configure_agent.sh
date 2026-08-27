#!/bin/bash

# Copyright (C) 2015, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Drives register_configure_agent.sh against a throwaway INSTALLDIR and checks what
# it leaves in ossec.conf. The script rewrites the file the packages ship, so the
# cases that matter are the destructive ones: nothing it does may drop a block it was
# not asked to touch.
#
#   ./test_register_configure_agent.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${SCRIPT_DIR}/../register_configure_agent.sh"

failures=0
checks=0

# Run the target against ${1} as the starting ossec.conf, with the caller's
# WAZUH_* variables already exported. Echoes the resulting file.
run_target() {

    local conf_body="$1"
    local installdir

    installdir="$(mktemp -d)"
    mkdir -p "${installdir}/etc" "${installdir}/tmp" "${installdir}/logs"
    printf '%s' "${conf_body}" > "${installdir}/etc/ossec.conf"

    # The script chowns ossec.log to root:wazuh when WAZUH_MANAGER is set; pre-create
    # it so an unprivileged run does not stop there.
    touch "${installdir}/logs/ossec.log"

    bash "${TARGET}" "${installdir}" >/dev/null 2>&1

    cat "${installdir}/etc/ossec.conf"
    rm -rf "${installdir}"

}

check() {

    local name="$1" expected="$2" actual="$3"

    checks=$(( checks + 1 ))
    if [ "${expected}" = "${actual}" ]; then
        echo "ok   - ${name}"
    else
        failures=$(( failures + 1 ))
        echo "FAIL - ${name}"
        echo "--- expected ---"
        echo "${expected}"
        echo "--- actual ---"
        echo "${actual}"
        echo "---"
    fi

}

# Everything except the enrollment block, which the script owns and rewrites. What is
# left is the part no run is allowed to touch.
outside_enrollment() {

    awk '
        in_block { if ($0 ~ /<\/enrollment>/) { in_block = 0 } ; next }
        /<enrollment>/ { if ($0 !~ /<\/enrollment>/) { in_block = 1 } ; next }
        /^[[:space:]]*$/ { next }
        { print }
    '

}

# Reports every surrounding line the run dropped, so a truncation shows up as the
# tags it ate rather than as a diff of the whole file.
missing_lines() {

    local before after line

    before="$(printf '%s\n' "$1" | outside_enrollment)"
    after="$(printf '%s\n' "$2" | outside_enrollment)"

    while IFS= read -r line; do
        if ! printf '%s\n' "${after}" | grep -qF -- "${line}"; then
            printf '%s\n' "${line}"
        fi
    done <<< "${before}"

}

MULTILINE_CONF='<ossec_config>
  <agent>
    <manager>
      <address>MANAGER_IP</address>
    </manager>
    <enrollment>
      <enabled>yes</enabled>
      <port>1515</port>
    </enrollment>
    <config-profile>CONFIG_PROFILE</config-profile>
  </agent>
  <rootcheck>
    <disabled>no</disabled>
  </rootcheck>
</ossec_config>
'

SINGLE_LINE_CONF='<ossec_config>
  <agent>
    <manager><address>MANAGER_IP</address></manager>
    <enrollment><enabled>yes</enabled><port>1515</port></enrollment>
    <config-profile>CONFIG_PROFILE</config-profile>
  </agent>
  <rootcheck>
    <disabled>no</disabled>
  </rootcheck>
</ossec_config>
'

NO_ENROLLMENT_CONF='<ossec_config>
  <agent>
    <manager>
      <address>MANAGER_IP</address>
    </manager>
  </agent>
  <rootcheck>
    <disabled>no</disabled>
  </rootcheck>
</ossec_config>
'

COMMENTED_CONF='<ossec_config>
  <!--
  <agent>
    <enrollment>
      <enabled>no</enabled>
    </enrollment>
  </agent>
  -->
  <agent>
    <manager>
      <address>MANAGER_IP</address>
    </manager>
  </agent>
</ossec_config>
'

export WAZUH_REGISTRATION_SERVER="10.0.0.2"

# The regression the review caught: with the block on one line, the sed range never
# closed and the delete ran to EOF.
actual="$(run_target "${SINGLE_LINE_CONF}")"
check "a single-line enrollment block keeps the rest of the file" \
      "" "$(missing_lines "${SINGLE_LINE_CONF}" "${actual}")"

actual="$(run_target "${MULTILINE_CONF}")"
check "a multi-line enrollment block keeps the rest of the file" \
      "" "$(missing_lines "${MULTILINE_CONF}" "${actual}")"

# Whatever the layout was, exactly one block comes back, inside <agent>.
for name in SINGLE_LINE_CONF MULTILINE_CONF NO_ENROLLMENT_CONF; do
    actual="$(run_target "${!name}")"
    check "${name}: exactly one <enrollment> opening tag" \
          "1" "$(printf '%s\n' "${actual}" | grep -c "<enrollment>")"
    check "${name}: the configured registration server is written" \
          "1" "$(printf '%s\n' "${actual}" | grep -c "<manager_address>10.0.0.2</manager_address>")"
done

# Running twice must converge: the second pass rewrites the block the first wrote
# instead of adding another one.
first="$(run_target "${SINGLE_LINE_CONF}")"
second="$(run_target "${first}")"
check "a second run does not add a second block" \
      "1" "$(printf '%s\n' "${second}" | grep -c "<enrollment>")"
check "a second run keeps the rest of the file" \
      "" "$(missing_lines "${first}" "${second}")"

# A commented-out block is not the one being configured, and must survive untouched.
actual="$(run_target "${COMMENTED_CONF}")"
check "the commented-out block is left alone" \
      "1" "$(printf '%s\n' "${actual}" | grep -c "<enabled>no</enabled>")"
check "the commented-out block does not absorb the insertion" \
      "" "$(missing_lines "${COMMENTED_CONF}" "${actual}")"

unset WAZUH_REGISTRATION_SERVER

# WAZUH_MANAGER_ENDPOINT (#38624) carries the whole connection target --
# host[:port][/prefix] -- which the script splits back into the three tags the agent
# reads. Only the host is mandatory; an omitted port or prefix takes its default.
#
# Collapses the emitted block to one line so a case reads as the tags it produced.
manager_block() {

    printf '%s\n' "$1" | awk '
        /<manager>/ { inside = 1 }
        inside { gsub(/^[[:space:]]+/, ""); printf "%s", $0 }
        /<\/manager>/ { if (inside) { exit } }
    '

}

endpoint_case() {

    local desc="$1" value="$2" expected="$3"

    export WAZUH_MANAGER_ENDPOINT="${value}"
    check "WAZUH_MANAGER_ENDPOINT='${value}' ${desc}" \
          "${expected}" "$(manager_block "$(run_target "${NO_ENROLLMENT_CONF}")")"
    unset WAZUH_MANAGER_ENDPOINT

}

# One row per accepted shape, asserting all three tags together rather than <endpoint>
# alone -- the split is the thing under test, so a case that got the prefix right and
# the port wrong has to fail.
endpoint_case "takes both defaults" "5.5.5.5" \
    '<manager><address>5.5.5.5</address><port>1517</port><endpoint>/wazuh-manager/</endpoint></manager>'
endpoint_case "accepts a hostname" "dasd.net" \
    '<manager><address>dasd.net</address><port>1517</port><endpoint>/wazuh-manager/</endpoint></manager>'
endpoint_case "takes an explicit port" "5.5.5.5:8443" \
    '<manager><address>5.5.5.5</address><port>8443</port><endpoint>/wazuh-manager/</endpoint></manager>'
endpoint_case "takes an explicit prefix" "5.5.5.5/proxy" \
    '<manager><address>5.5.5.5</address><port>1517</port><endpoint>/proxy/</endpoint></manager>'
endpoint_case "takes a multi-segment prefix" "5.5.5.5:8443/a/b" \
    '<manager><address>5.5.5.5</address><port>8443</port><endpoint>/a/b/</endpoint></manager>'
endpoint_case "tolerates an https:// scheme" "https://5.5.5.5:8443/proxy/" \
    '<manager><address>5.5.5.5</address><port>8443</port><endpoint>/proxy/</endpoint></manager>'
endpoint_case "matches the scheme case-insensitively" "HTTPS://5.5.5.5/proxy" \
    '<manager><address>5.5.5.5</address><port>1517</port><endpoint>/proxy/</endpoint></manager>'
endpoint_case "drops the brackets from an IPv6 literal" "[2001:db8::1]:8443/proxy" \
    '<manager><address>2001:db8::1</address><port>8443</port><endpoint>/proxy/</endpoint></manager>'
endpoint_case "accepts a bracketed IPv6 literal with no port" "[2001:db8::1]" \
    '<manager><address>2001:db8::1</address><port>1517</port><endpoint>/wazuh-manager/</endpoint></manager>'

# The distinction the whole grammar turns on, and the one a naive split loses: no '/'
# at all means "default prefix", a trailing '/' with nothing after it is the operator's
# deliberate opt-out (#38614) and has to survive as an empty tag.
endpoint_case "with a trailing slash opts out of the prefix" "5.5.5.5/" \
    '<manager><address>5.5.5.5</address><port>1517</port><endpoint></endpoint></manager>'
endpoint_case "opts out with an explicit port too" "5.5.5.5:1517/" \
    '<manager><address>5.5.5.5</address><port>1517</port><endpoint></endpoint></manager>'

# Grammar violations write no <manager> block, leaving the shipped one in place so the
# agent fails loudly at startup instead of connecting somewhere unintended.
untouched='<manager><address>MANAGER_IP</address></manager>'
endpoint_case "is rejected when empty" "" "${untouched}"
endpoint_case "is rejected with no host" "/wazuh-manager/" "${untouched}"
endpoint_case "is rejected for a non-https scheme" "http://5.5.5.5/" "${untouched}"
endpoint_case "is rejected for an out-of-range port" "5.5.5.5:99999" "${untouched}"
endpoint_case "is rejected for a non-numeric port" "5.5.5.5:abc" "${untouched}"
endpoint_case "is rejected for a trailing colon" "5.5.5.5:" "${untouched}"
endpoint_case "is rejected for an unbracketed IPv6 literal" "2001:db8::1" "${untouched}"
endpoint_case "is rejected for an IPv6 zone id" "[fe80::1%25eth0]" "${untouched}"

# WAZUH_MANAGER keeps working exactly as before when the combined value is not set --
# this is what leaves every existing install command and documented example alone.
export WAZUH_MANAGER="10.0.0.5"
actual="$(run_target "${NO_ENROLLMENT_CONF}")"
check "WAZUH_MANAGER alone still writes the block with both defaults" \
      '<manager><address>10.0.0.5</address><port>1517</port><endpoint>/wazuh-manager/</endpoint></manager>' \
      "$(manager_block "${actual}")"

export WAZUH_MANAGER_PORT="8443"
actual="$(run_target "${NO_ENROLLMENT_CONF}")"
check "WAZUH_MANAGER_PORT alone still sets the port" \
      '<manager><address>10.0.0.5</address><port>8443</port><endpoint>/wazuh-manager/</endpoint></manager>' \
      "$(manager_block "${actual}")"

# The combined value wins over both, and WAZUH_MANAGER_PORT must not clobber the port
# it parsed out.
export WAZUH_MANAGER_ENDPOINT="6.6.6.6:9999/proxy"
actual="$(run_target "${NO_ENROLLMENT_CONF}")"
check "WAZUH_MANAGER_ENDPOINT supersedes WAZUH_MANAGER and WAZUH_MANAGER_PORT" \
      '<manager><address>6.6.6.6</address><port>9999</port><endpoint>/proxy/</endpoint></manager>' \
      "$(manager_block "${actual}")"
unset WAZUH_MANAGER_ENDPOINT
unset WAZUH_MANAGER_PORT
unset WAZUH_MANAGER

echo
echo "${checks} checks, ${failures} failed"
[ "${failures}" -eq 0 ]
