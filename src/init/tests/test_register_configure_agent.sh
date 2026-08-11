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
    <server>
      <address>MANAGER_IP</address>
    </server>
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
    <server><address>MANAGER_IP</address></server>
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
    <server>
      <address>MANAGER_IP</address>
    </server>
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
    <server>
      <address>MANAGER_IP</address>
    </server>
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

echo
echo "${checks} checks, ${failures} failed"
[ "${failures}" -eq 0 ]
