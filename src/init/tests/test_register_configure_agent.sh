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

# Same as run_target, but leaves the tree in place and echoes its path: the #39064 cases below
# assert on files BESIDE ossec.conf (etc/authd.pass, logs/ossec.log), which run_target deletes.
# The caller is responsible for removing what it gets back.
run_target_keep() {

    local conf_body="$1"
    local installdir

    installdir="$(mktemp -d)"
    mkdir -p "${installdir}/etc" "${installdir}/tmp" "${installdir}/logs"
    printf '%s' "${conf_body}" > "${installdir}/etc/ossec.conf"
    touch "${installdir}/logs/ossec.log"

    bash "${TARGET}" "${installdir}" >/dev/null 2>&1

    printf '%s' "${installdir}"

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

# Any live <enrollment> child will do to make the block appear; agent_name is the one with the
# fewest interactions of its own. It used to be WAZUH_REGISTRATION_SERVER, which no longer
# writes anything -- 5.0 enrolls over <manager><endpoint> and <enrollment> has no address.
export WAZUH_AGENT_NAME="test-agent"

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
    check "${name}: the configured enrollment value is written" \
          "1" "$(printf '%s\n' "${actual}" | grep -c "<agent_name>test-agent</agent_name>")"
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

unset WAZUH_AGENT_NAME

# --- Removed names are reported, and write nothing --------------------------------------------
# Sixteen registration variables went with #39063. Each is still read so an install carrying an
# old playbook is told, rather than quietly producing an agent that never registers.

removed() {

    local name="$1" value="$2" installdir actual

    installdir="$(mktemp -d)"
    mkdir -p "${installdir}/etc" "${installdir}/tmp" "${installdir}/logs"
    printf '%s' "${NO_ENROLLMENT_CONF}" > "${installdir}/etc/ossec.conf"
    touch "${installdir}/logs/ossec.log"

    export "${name}=${value}"
    bash "${TARGET}" "${installdir}" >/dev/null 2>"${installdir}/stderr"
    unset "${name}"

    actual="$(grep -c "${name} is not supported in 5.0" "${installdir}/stderr")"
    check "${name} is reported as removed" "1" "${actual}"

    check "${name} leaves the shipped placeholder" \
          '<manager><address>MANAGER_IP</address></manager>' \
          "$(manager_block "$(cat "${installdir}/etc/ossec.conf")")"

    rm -rf "${installdir}"

}

manager_block() {

    printf '%s\n' "$1" | awk '
        /<manager>/ { inside = 1 }
        inside { gsub(/^[[:space:]]+/, ""); printf "%s", $0 }
        /<\/manager>/ { if (inside) { exit } }
    '

}

removed "WAZUH_MANAGER"                   "10.0.0.5"
removed "WAZUH_MANAGER_IP"                "10.0.0.5"
removed "WAZUH_MANAGER_PORT"              "8443"
removed "WAZUH_MANAGER_ENDPOINT"          "10.0.0.5:8443/proxy"
removed "WAZUH_REGISTRATION_PASSWORD"     "hunter2"
removed "WAZUH_PASSWORD"                  "hunter2"
removed "WAZUH_REGISTRATION_SERVER"       "10.0.0.2"
removed "WAZUH_REGISTRATION_PORT"         "1515"
removed "WAZUH_REGISTRATION_CERTIFICATE"  "/tmp/agent.pem"
removed "WAZUH_REGISTRATION_KEY"          "/tmp/agent.key"
removed "WAZUH_AUTHD_SERVER"              "10.0.0.2"
removed "WAZUH_AUTHD_PORT"                "1515"
removed "WAZUH_PEM"                       "/tmp/agent.pem"
removed "WAZUH_KEY"                       "/tmp/agent.key"
removed "WAZUH_REGISTRATION_CA"           "/tmp/ca.pem"

removed "WAZUH_CERTIFICATE"               "/tmp/ca.pem"

# The pre-rename spelling has no alias, so it has to say so or it fails only in behaviour.
removed "SSL_VERIFICATION"                "full"

# A removed credential variable must not leave the secret behind either.
installdir="$(mktemp -d)"
mkdir -p "${installdir}/etc" "${installdir}/tmp" "${installdir}/logs"
printf '%s' "${NO_ENROLLMENT_CONF}" > "${installdir}/etc/ossec.conf"
touch "${installdir}/logs/ossec.log"
export WAZUH_REGISTRATION_PASSWORD="hunter2"
bash "${TARGET}" "${installdir}" >/dev/null 2>&1
unset WAZUH_REGISTRATION_PASSWORD
check "a removed WAZUH_REGISTRATION_PASSWORD writes no authd.pass" "absent" \
      "$([ -e "${installdir}/etc/authd.pass" ] && echo present || echo absent)"
rm -rf "${installdir}"

# --- The surviving non-registration variables still apply ---------------------------------------

export WAZUH_SSL_VERIFICATION="system"
actual="$(run_target "${NO_ENROLLMENT_CONF}")"
check "WAZUH_SSL_VERIFICATION still writes <verification_mode>" "1" \
      "$(printf '%s\n' "${actual}" | grep -c "<verification_mode>system</verification_mode>")"
unset WAZUH_SSL_VERIFICATION

export WAZUH_KEEP_ALIVE_INTERVAL="45"
actual="$(run_target "${NO_ENROLLMENT_CONF}")"
check "WAZUH_KEEP_ALIVE_INTERVAL still writes <notify_time>" "1" \
      "$(printf '%s\n' "${actual}" | grep -c "<notify_time>45</notify_time>")"
unset WAZUH_KEEP_ALIVE_INTERVAL

export WAZUH_GROUP="alpha"
actual="$(run_target "${NO_ENROLLMENT_CONF}")"
check "WAZUH_GROUP still aliases WAZUH_AGENT_GROUP" "1" \
      "$(printf '%s\n' "${actual}" | grep -c "<groups>alpha</groups>")"
unset WAZUH_GROUP

# ---- #39064: the fleet-wide enrollment password ----
#
# The write itself stays (the password is supported for one more release, and on Windows it is
# still the only credential path). What changed is that <authorization_pass_path> is no longer
# emitted -- it only ever named the compiled default -- and that an operator is told once what the
# file is.

export WAZUH_REGISTRATION_SERVER="10.0.0.2"
export WAZUH_REGISTRATION_PASSWORD="fleet-secret"

installdir="$(run_target_keep "${NO_ENROLLMENT_CONF}")"

check "the enrollment password is still written" \
      "fleet-secret" "$(cat "${installdir}/etc/authd.pass" 2>/dev/null)"
check "the enrollment password file is not world-readable" \
      "640" "$(stat -c '%a' "${installdir}/etc/authd.pass" 2>/dev/null)"
check "<authorization_pass_path> is not written into ossec.conf" \
      "0" "$(grep -c 'authorization_pass_path' "${installdir}/etc/ossec.conf")"
check "the deprecation is recorded in the agent log" \
      "1" "$(grep -c 'deprecated in favour of WAZUH_ENROLLMENT_TOKEN' "${installdir}/logs/ossec.log")"

rm -rf "${installdir}"
unset WAZUH_REGISTRATION_PASSWORD

# The template placeholder went with the write: an enrollment block created without a password
# must not be left holding "/path/to/authd.pass", which is what would happen if the placeholder
# stayed behind once nothing filled it in.
installdir="$(run_target_keep "${NO_ENROLLMENT_CONF}")"
check "no password: no authorization_pass_path placeholder is left behind" \
      "0" "$(grep -c 'authorization_pass_path' "${installdir}/etc/ossec.conf")"
check "no password: no authd.pass is created" \
      "absent" "$([ -e "${installdir}/etc/authd.pass" ] && echo present || echo absent)"
rm -rf "${installdir}"

unset WAZUH_REGISTRATION_SERVER

# An operator who configured the tag by hand owns it: the run must honour their value, not delete
# it. Deleting a value named in someone else's template is how a converge becomes an outage.
OPERATOR_PASS_CONF='<ossec_config>
  <agent>
    <manager>
      <address>MANAGER_IP</address>
    </manager>
    <enrollment>
      <enabled>yes</enabled>
      <authorization_pass_path>/shared/mount/authd.pass</authorization_pass_path>
    </enrollment>
  </agent>
</ossec_config>
'

export WAZUH_REGISTRATION_SERVER="10.0.0.2"
actual="$(run_target "${OPERATOR_PASS_CONF}")"
check "an explicitly configured authorization_pass_path survives the run" \
      "1" "$(printf '%s\n' "${actual}" | grep -c '<authorization_pass_path>/shared/mount/authd.pass</authorization_pass_path>')"
unset WAZUH_REGISTRATION_SERVER

echo
echo "${checks} checks, ${failures} failed"
[ "${failures}" -eq 0 ]
