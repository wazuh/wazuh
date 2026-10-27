#!/bin/bash

# Copyright (C) Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Drives register_configure_agent.sh against a throwaway INSTALLDIR to check what
# resolve_deployment_conflicts() accepts, what it refuses, and what a refusal leaves behind.
# Since #39063 the token is the only way to register, so the cases are the absence of one, the
# decoder's own failures, the one variable that can still defeat a token, and the address
# grammar -- which now reaches <endpoint> only through the token.
#
# Black-box: the token is decoded by the agent's own --show-token, so a stub binary stands in
# for wazuh-agentd and the cases run without a build.
#
#   ./test_enrollment_token.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${SCRIPT_DIR}/../register_configure_agent.sh"

failures=0
checks=0

# The shipped placeholder, as etc/ossec-agent.conf carries it. A refusal must leave this.
PLACEHOLDER_CONF='<ossec_config>
  <agent>
    <manager>
      <endpoint>IP:1517/wazuh-manager/</endpoint>
    </manager>
  </agent>
</ossec_config>
'

# A token is an opaque string to the installer -- only the stub decoder reads it -- so the
# cases use a recognisable literal rather than real base64url.
TOKEN="eyJ2ZXIiOjEsImFkciI6InNpZW0uZXhhbXBsZS5sb2NhbCJ9"

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

file_mode() {

    stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"

}

file_owner() {

    stat -c '%u:%g' "$1" 2>/dev/null || stat -f '%u:%g' "$1"

}

# Build an INSTALLDIR whose bin/wazuh-agentd answers --show-token with ${1} and exits ${2}.
# Echoes the directory; the caller removes it.
make_installdir() {

    local description="$1" status="$2" installdir

    installdir="$(mktemp -d)"
    mkdir -p "${installdir}/etc" "${installdir}/tmp" "${installdir}/logs" "${installdir}/bin" \
             "${installdir}/packages_files"
    chmod 750 "${installdir}/packages_files"
    printf '%s' "${PLACEHOLDER_CONF}" > "${installdir}/etc/ossec.conf"
    touch "${installdir}/logs/ossec.log"

    {
        echo '#!/bin/bash'
        echo 'cat > /dev/null'
        printf 'printf %s "%s"\n' "'%s'" "${description}"
        echo "exit ${status}"
    } > "${installdir}/bin/wazuh-agentd"
    chmod 755 "${installdir}/bin/wazuh-agentd"

    printf '%s' "${installdir}"

}

# Run the target against a fresh INSTALLDIR with the caller's WAZUH_* already exported, and
# leave the result in RUN_DIR / RUN_STATUS for the assertions. The caller removes RUN_DIR.
run_target() {

    local description="$1" status="$2"

    RUN_DIR="$(make_installdir "${description}" "${status}")"
    bash "${TARGET}" "${RUN_DIR}" >/dev/null 2>"${RUN_DIR}/stderr"
    RUN_STATUS="$?"

}

endpoint_of() {

    sed -n 's:.*<endpoint>\(.*\)</endpoint>.*:\1:p' "${RUN_DIR}/etc/ossec.conf"

}

refusal_code() {

    sed -n 's/.*\[\([A-Z_]*\)\].*/\1/p' "${RUN_DIR}/stderr" | head -1

}

# Every element the 5.x agent parses, logs at INFO and then ignores. Nothing the installer
# writes may contain one: an operator reading the file sees configuration that does nothing.
DEAD_ELEMENTS="manager_address|<port>|server_ca_path|agent_certificate_path|agent_key_path|authorization_pass_path"

# A refusal must leave the configuration the package shipped and nothing of its own, and it must
# say so in its exit status -- the status is the only part a packaging change could start acting
# on, and without asserting it the whole suite would still pass if refusals became warnings.
check_refused() {

    local name="$1" expected_code="$2"

    check "${name}: names ${expected_code}" "${expected_code}" "$(refusal_code)"
    check "${name}: exits non-zero" "1" "${RUN_STATUS}"
    check "${name}: leaves the shipped placeholder" "IP:1517/wazuh-manager/" "$(endpoint_of)"
    check "${name}: stores no token" "absent" \
          "$([ -e "${RUN_DIR}/etc/enrollment_token" ] && echo present || echo absent)"

}

# Asserts on the file the run left behind, whatever the run was.
check_no_dead_elements() {

    check "$1: writes no element the agent logs at INFO and ignores" "0" \
          "$(grep -cE "${DEAD_ELEMENTS}" "${RUN_DIR}/etc/ossec.conf")"

}

DESC_WITH_KEY='ver: 1
adr: siem.example.local
pin: 6091dc3665ed5e833c8d945f93ebbf14b37020ccee77334e4497ac2ef3590aa2
credential: present'

DESC_NO_KEY='ver: 1
adr: siem.example.local
pin: 6091dc3665ed5e833c8d945f93ebbf14b37020ccee77334e4497ac2ef3590aa2
credential: absent'

DESC_PORT_PREFIX='ver: 1
adr: siem.example.local:8443/proxy
pin: 6091dc3665ed5e833c8d945f93ebbf14b37020ccee77334e4497ac2ef3590aa2
credential: present'

# --- A token on its own -------------------------------------------------------------------

export WAZUH_ENROLLMENT_TOKEN="${TOKEN}"

run_target "${DESC_WITH_KEY}" 0
check "a token alone writes its address into <endpoint>" "siem.example.local" "$(endpoint_of)"
check "a token alone stores the token verbatim" "${TOKEN}" "$(cat "${RUN_DIR}/etc/enrollment_token")"
check "the stored token is root-only" "600" "$(file_mode "${RUN_DIR}/etc/enrollment_token")"
if [ "${EUID}" -eq 0 ]; then
    check "the stored token is owned by uid 0 and gid 0" "0:0" "$(file_owner "${RUN_DIR}/etc/enrollment_token")"
    check "storing the token reports no chown error" "" "$(grep 'chown' "${RUN_DIR}/stderr")"
fi
check "a token alone succeeds" "0" "${RUN_STATUS}"
check "a token alone writes no authd.pass" "absent" \
      "$([ -e "${RUN_DIR}/etc/authd.pass" ] && echo present || echo absent)"
check_no_dead_elements "a token alone"
rm -rf "${RUN_DIR}"

run_target "${DESC_NO_KEY}" 0
check "a credential-less token is not an error" "siem.example.local" "$(endpoint_of)"
rm -rf "${RUN_DIR}"

# --- The decoder's own failures -------------------------------------------------------------

run_target "" 2
check_refused "a token the decoder refuses" "ERR_BAD_TOKEN"
rm -rf "${RUN_DIR}"

run_target "" 127
check_refused "a decoder that cannot run" "ERR_NO_DECODER"
rm -rf "${RUN_DIR}"

run_target 'ver: 1
credential: absent' 0
check_refused "a token carrying no address" "ERR_BAD_TOKEN"
rm -rf "${RUN_DIR}"

# --- A token and an explicit mode ------------------------------------------------------------
# Supported together: the mode is what the operator wants the bootstrapped anchor resolved to,
# so it is honoured rather than refused, and the token still supplies the address.

for mode in full certificate system none; do
    export WAZUH_SSL_VERIFICATION="${mode}"
    run_target "${DESC_WITH_KEY}" 0
    check "a token with WAZUH_SSL_VERIFICATION=${mode} succeeds" "0" "${RUN_STATUS}"
    check "a token with WAZUH_SSL_VERIFICATION=${mode} still writes the token's address" \
          "siem.example.local" "$(endpoint_of)"
    check "a token with WAZUH_SSL_VERIFICATION=${mode} writes that mode" "1" \
          "$(grep -c "<verification_mode>${mode}</verification_mode>" "${RUN_DIR}/etc/ossec.conf")"
    check "a token with WAZUH_SSL_VERIFICATION=${mode} still stores the token" "present" \
          "$([ -e "${RUN_DIR}/etc/enrollment_token" ] && echo present || echo absent)"
    rm -rf "${RUN_DIR}"
    unset WAZUH_SSL_VERIFICATION
done

unset WAZUH_ENROLLMENT_TOKEN

# --- No token at all --------------------------------------------------------------------------
# Registration does not happen and says so, but the settings that were never about registration
# still apply: that is what an install configured by hand afterwards needs.

run_target "${DESC_WITH_KEY}" 0
check "no token and no endpoint names the missing manager" "INFO_NO_MANAGER" "$(refusal_code)"
check "no token leaves the shipped placeholder" "IP:1517/wazuh-manager/" "$(endpoint_of)"
check "no token stores no token" "absent" \
      "$([ -e "${RUN_DIR}/etc/enrollment_token" ] && echo present || echo absent)"
rm -rf "${RUN_DIR}"

export WAZUH_SSL_VERIFICATION="system"
export WAZUH_AGENT_NAME="hand-configured"
run_target "${DESC_WITH_KEY}" 0
check "no token still writes <verification_mode>" "1" \
      "$(grep -c "<verification_mode>system</verification_mode>" "${RUN_DIR}/etc/ossec.conf")"
check "no token still writes <agent_name>" "1" \
      "$(grep -c "<agent_name>hand-configured</agent_name>" "${RUN_DIR}/etc/ossec.conf")"
rm -rf "${RUN_DIR}"
unset WAZUH_SSL_VERIFICATION
unset WAZUH_AGENT_NAME

# The address grammar is not retested here: w_etoken_decode() rejects a malformed 'adr'
# (ETOKEN_BAD_ADR) before --show-token prints anything, so the installer never sees one, and
# src/unit_tests/shared/test_enrollment_token.c already covers that grammar against the codec
# itself rather than against a stub.

# The <enrollment> block is created from a template when one is absent, and a template carrying
# removed elements puts them in every file that block is written into -- including a plain
# name-only install that never mentioned them.
export WAZUH_AGENT_NAME="name-only"
run_target "${DESC_WITH_KEY}" 0
check_no_dead_elements "a name-only install with no token"
rm -rf "${RUN_DIR}"
unset WAZUH_AGENT_NAME

export WAZUH_ENROLLMENT_TOKEN="${TOKEN}"
export WAZUH_AGENT_GROUP="linux"
run_target "${DESC_WITH_KEY}" 0
check_no_dead_elements "a token install that also sets a group"
rm -rf "${RUN_DIR}"
unset WAZUH_AGENT_GROUP
unset WAZUH_ENROLLMENT_TOKEN

export WAZUH_ENROLLMENT_TOKEN="${TOKEN}"

# --- A 4.x file preserved across an upgrade -------------------------------------------------
# The 5.x parser reads the address out of <client> only under <server>, so a <manager> written
# there is configuration the agent will not read. config() picks the wrapper the same way.

LEGACY_CONF='<ossec_config>
  <client>
    <server>
      <address>MANAGER_IP</address>
      <port>1514</port>
    </server>
  </client>
</ossec_config>'

RUN_DIR="$(make_installdir "${DESC_WITH_KEY}" 0)"
printf '%s' "${LEGACY_CONF}" > "${RUN_DIR}/etc/ossec.conf"
bash "${TARGET}" "${RUN_DIR}" >/dev/null 2>&1
check "a 4.x file gets the token's address" "siem.example.local" "$(endpoint_of)"
check "a 4.x file keeps <server> as the wrapper" "1" \
      "$(grep -c "<server>" "${RUN_DIR}/etc/ossec.conf")"
check "a 4.x file is not given a <manager> the parser will not read there" "0" \
      "$(grep -c "<manager>" "${RUN_DIR}/etc/ossec.conf")"
rm -rf "${RUN_DIR}"
unset WAZUH_ENROLLMENT_TOKEN

# --- An in-place upgrade (the packages pass "upgrade") ----------------------------------------
# The configuration the agent had is kept: only the token is applied, so an agent enrolled before
# 5.0 gets the address and the token its first start installs the trust anchor with.

run_upgrade() {

    RUN_DIR="$(make_installdir "$1" "$2")"
    printf '%s' "${LEGACY_CONF}" > "${RUN_DIR}/etc/ossec.conf"
    bash "${TARGET}" "${RUN_DIR}" upgrade >/dev/null 2>"${RUN_DIR}/stderr"
    RUN_STATUS="$?"

}

export WAZUH_ENROLLMENT_TOKEN="${TOKEN}"
export WAZUH_AGENT_NAME="not-on-upgrade"
run_upgrade "${DESC_WITH_KEY}" 0
check "an upgrade with a token succeeds" "0" "${RUN_STATUS}"
check "an upgrade with a token writes its address" "siem.example.local" "$(endpoint_of)"
check "an upgrade keeps the 4.x <server> wrapper" "1" "$(grep -c "<server>" "${RUN_DIR}/etc/ossec.conf")"
check "an upgrade stores the token verbatim" "${TOKEN}" "$(cat "${RUN_DIR}/etc/enrollment_token")"
check "the token stored on upgrade is root-only" "600" "$(file_mode "${RUN_DIR}/etc/enrollment_token")"
check "an upgrade applies nothing but the token" "0" \
      "$(grep -c "not-on-upgrade" "${RUN_DIR}/etc/ossec.conf")"
rm -rf "${RUN_DIR}"
unset WAZUH_AGENT_NAME

run_upgrade "" 2
check "an upgrade with a refused token names ERR_BAD_TOKEN" "ERR_BAD_TOKEN" "$(refusal_code)"
check "an upgrade with a refused token exits non-zero" "1" "${RUN_STATUS}"
check "an upgrade with a refused token keeps the configuration" "${LEGACY_CONF}" \
      "$(cat "${RUN_DIR}/etc/ossec.conf")"
check "an upgrade with a refused token stores no token" "absent" \
      "$([ -e "${RUN_DIR}/etc/enrollment_token" ] && echo present || echo absent)"
rm -rf "${RUN_DIR}"
unset WAZUH_ENROLLMENT_TOKEN

run_upgrade "${DESC_WITH_KEY}" 0
check "an upgrade with no token keeps the configuration" "${LEGACY_CONF}" "$(cat "${RUN_DIR}/etc/ossec.conf")"
check "an upgrade with no token is not a missing manager" "" "$(refusal_code)"
check "an upgrade with no token and no anchor says how to get one" "1" \
      "$(grep -c -- "--certs-only" "${RUN_DIR}/stderr")"
rm -rf "${RUN_DIR}"

RUN_DIR="$(make_installdir "${DESC_WITH_KEY}" 0)"
mkdir -p "${RUN_DIR}/etc/certs"
touch "${RUN_DIR}/etc/certs/root-ca.pem"
bash "${TARGET}" "${RUN_DIR}" upgrade >/dev/null 2>"${RUN_DIR}/stderr"
check "an upgrade with no token and an anchor says nothing" "" "$(cat "${RUN_DIR}/stderr")"
rm -rf "${RUN_DIR}"

# An anchor means the token would never be used, so the address stays where it was.
export WAZUH_ENROLLMENT_TOKEN="${TOKEN}"
run_upgrade_with_anchor() {

    RUN_DIR="$(make_installdir "${DESC_WITH_KEY}" 0)"
    printf '%s' "${LEGACY_CONF}" > "${RUN_DIR}/etc/ossec.conf"
    mkdir -p "${RUN_DIR}/etc/certs"
    touch "${RUN_DIR}/etc/certs/root-ca.pem"
    bash "${TARGET}" "${RUN_DIR}" upgrade >/dev/null 2>"${RUN_DIR}/stderr"
    RUN_STATUS="$?"

}
run_upgrade_with_anchor
check "an upgrade with a token and an anchor keeps the configuration" "${LEGACY_CONF}" \
      "$(cat "${RUN_DIR}/etc/ossec.conf")"
check "an upgrade with a token and an anchor stores no token" "absent" \
      "$([ -e "${RUN_DIR}/etc/enrollment_token" ] && echo present || echo absent)"
check "an upgrade with a token and an anchor says the token was ignored" "1" \
      "$(grep -c "WAZUH_ENROLLMENT_TOKEN was ignored" "${RUN_DIR}/stderr")"
rm -rf "${RUN_DIR}"
unset WAZUH_ENROLLMENT_TOKEN

# A 4.x playbook still passing a removed variable is told on upgrade too.
export WAZUH_MANAGER="10.0.0.5"
run_upgrade "${DESC_WITH_KEY}" 0
check "an upgrade reports a removed variable" "1" \
      "$(grep -c "WAZUH_MANAGER is not supported in 5.0" "${RUN_DIR}/stderr")"
check "an upgrade with a removed variable keeps the configuration" "${LEGACY_CONF}" \
      "$(cat "${RUN_DIR}/etc/ossec.conf")"
rm -rf "${RUN_DIR}"
unset WAZUH_MANAGER

# --- An upgrade writes nothing by path where the wazuh account can write -----------------------

export WAZUH_ENROLLMENT_TOKEN="${TOKEN}"

run_upgrade "${DESC_WITH_KEY}" 0
check "an upgrade writes nothing to logs/ossec.log" "" "$(cat "${RUN_DIR}/logs/ossec.log")"
check "an upgrade tells the operator the token was applied" "1" \
      "$(grep -c "WAZUH_ENROLLMENT_TOKEN applied" "${RUN_DIR}/stderr")"
check "an upgrade leaves no staging directory behind" "" "$(ls "${RUN_DIR}/packages_files")"
rm -rf "${RUN_DIR}"

# A link at the token's name is replaced, never written through.
RUN_DIR="$(make_installdir "${DESC_WITH_KEY}" 0)"
printf '%s' "${LEGACY_CONF}" > "${RUN_DIR}/etc/ossec.conf"
printf 'victim' > "${RUN_DIR}/victim"
ln -s "${RUN_DIR}/victim" "${RUN_DIR}/etc/enrollment_token"
bash "${TARGET}" "${RUN_DIR}" upgrade >/dev/null 2>&1
check "a link at etc/enrollment_token is not written through" "victim" "$(cat "${RUN_DIR}/victim")"
check "a link at etc/enrollment_token is replaced by the token" "regular:${TOKEN}" \
      "$([ -L "${RUN_DIR}/etc/enrollment_token" ] && echo link || echo regular):$(cat "${RUN_DIR}/etc/enrollment_token")"
rm -rf "${RUN_DIR}"

# A link at ossec.conf is refused: neither its target nor the token is written.
RUN_DIR="$(make_installdir "${DESC_WITH_KEY}" 0)"
printf '%s' "${LEGACY_CONF}" > "${RUN_DIR}/victim"
rm -f "${RUN_DIR}/etc/ossec.conf"
ln -s "${RUN_DIR}/victim" "${RUN_DIR}/etc/ossec.conf"
bash "${TARGET}" "${RUN_DIR}" upgrade >/dev/null 2>"${RUN_DIR}/stderr"
RUN_STATUS="$?"
check "a link at etc/ossec.conf is refused" "1" "${RUN_STATUS}"
check "a link at etc/ossec.conf is not written through" "${LEGACY_CONF}" "$(cat "${RUN_DIR}/victim")"
check "a link at etc/ossec.conf stores no token" "absent" \
      "$([ -e "${RUN_DIR}/etc/enrollment_token" ] && echo present || echo absent)"
rm -rf "${RUN_DIR}"

# A staging parent anyone else can write would let them swap the staging directory.
RUN_DIR="$(make_installdir "${DESC_WITH_KEY}" 0)"
printf '%s' "${LEGACY_CONF}" > "${RUN_DIR}/etc/ossec.conf"
chmod 770 "${RUN_DIR}/packages_files"
bash "${TARGET}" "${RUN_DIR}" upgrade >/dev/null 2>"${RUN_DIR}/stderr"
RUN_STATUS="$?"
check "a group-writable packages_files/ is refused" "1" "${RUN_STATUS}"
check "a group-writable packages_files/ keeps the configuration" "${LEGACY_CONF}" \
      "$(cat "${RUN_DIR}/etc/ossec.conf")"
rm -rf "${RUN_DIR}"

# --- An upgrade rewrites the admin's own file: what it cannot rewrite cleanly is left alone ----

ONE_LINE_SERVER='<ossec_config>
  <client>
    <server><address>MANAGER_IP</address></server>
  </client>
  <logging>
    <log_format>plain</log_format>
  </logging>
</ossec_config>'

UNCLOSED_SERVER='<ossec_config>
  <client>
    <server>
      <address>MANAGER_IP</address>
  </client>
</ossec_config>'

COMMENTED_CLIENT='<ossec_config>
  <client> <!-- managers -->
    <server>
      <address>MANAGER_IP</address>
    </server>
  </client>
</ossec_config>'

for shape in ONE_LINE_SERVER UNCLOSED_SERVER COMMENTED_CLIENT; do
    RUN_DIR="$(make_installdir "${DESC_WITH_KEY}" 0)"
    printf '%s' "${!shape}" > "${RUN_DIR}/etc/ossec.conf"
    bash "${TARGET}" "${RUN_DIR}" upgrade >/dev/null 2>"${RUN_DIR}/stderr"
    RUN_STATUS="$?"
    check "an upgrade over ${shape} fails" "1" "${RUN_STATUS}"
    check "an upgrade over ${shape} keeps the configuration" "${!shape}" "$(cat "${RUN_DIR}/etc/ossec.conf")"
    check "an upgrade over ${shape} stores no token" "absent" \
          "$([ -e "${RUN_DIR}/etc/enrollment_token" ] && echo present || echo absent)"
    check "an upgrade over ${shape} does not say applied" "0" "$(grep -c "applied:" "${RUN_DIR}/stderr")"
    check "an upgrade over ${shape} leaves no staging directory behind" "" "$(ls "${RUN_DIR}/packages_files")"
    rm -rf "${RUN_DIR}"
done

# A FIFO at ossec.conf is refused rather than read, which would block the upgrade.
RUN_DIR="$(make_installdir "${DESC_WITH_KEY}" 0)"
rm -f "${RUN_DIR}/etc/ossec.conf"
mkfifo "${RUN_DIR}/etc/ossec.conf"
timeout 10 bash "${TARGET}" "${RUN_DIR}" upgrade >/dev/null 2>"${RUN_DIR}/stderr"
RUN_STATUS="$?"
check "a FIFO at etc/ossec.conf is refused without blocking" "1" "${RUN_STATUS}"
check "a FIFO at etc/ossec.conf stores no token" "absent" \
      "$([ -e "${RUN_DIR}/etc/enrollment_token" ] && echo present || echo absent)"
rm -rf "${RUN_DIR}"

# A FIFO renamed over ossec.conf between the checks and the copy is not what gets copied.
RUN_DIR="$(make_installdir "${DESC_WITH_KEY}" 0)"
printf '%s' "${LEGACY_CONF}" > "${RUN_DIR}/etc/ossec.conf"
mkdir -p "${RUN_DIR}/shim"
{
    echo '#!/bin/bash'
    echo "conf='${RUN_DIR}/etc/ossec.conf'"
    echo '[ -p "${conf}" ] || { rm -f "${conf}"; mkfifo "${conf}"; }'
    echo 'exec /bin/cp "$@"'
} > "${RUN_DIR}/shim/cp"
chmod 755 "${RUN_DIR}/shim/cp"
PATH="${RUN_DIR}/shim:${PATH}" timeout 10 bash "${TARGET}" "${RUN_DIR}" upgrade >/dev/null 2>"${RUN_DIR}/stderr"
RUN_STATUS="$?"
check "a FIFO swapped in before the copy does not block the upgrade" "0" "${RUN_STATUS}"
check "a FIFO swapped in before the copy does not change what is rewritten" "siem.example.local" \
      "$([ -p "${RUN_DIR}/etc/ossec.conf" ] && echo fifo || endpoint_of)"
rm -rf "${RUN_DIR}"

# ossec.conf failing to move into place takes the token back with it.
RUN_DIR="$(make_installdir "${DESC_WITH_KEY}" 0)"
printf '%s' "${LEGACY_CONF}" > "${RUN_DIR}/etc/ossec.conf"
mkdir -p "${RUN_DIR}/shim"
{
    echo '#!/bin/bash'
    echo 'case "${!#}" in */etc/ossec.conf) exit 1 ;; esac'
    echo 'exec /bin/mv "$@"'
} > "${RUN_DIR}/shim/mv"
chmod 755 "${RUN_DIR}/shim/mv"
PATH="${RUN_DIR}/shim:${PATH}" bash "${TARGET}" "${RUN_DIR}" upgrade >/dev/null 2>"${RUN_DIR}/stderr"
RUN_STATUS="$?"
check "an ossec.conf that cannot be moved fails the upgrade" "1" "${RUN_STATUS}"
check "an ossec.conf that cannot be moved keeps the configuration" "${LEGACY_CONF}" \
      "$(cat "${RUN_DIR}/etc/ossec.conf")"
check "an ossec.conf that cannot be moved leaves no token" "absent" \
      "$([ -e "${RUN_DIR}/etc/enrollment_token" ] && echo present || echo absent)"

# And a token that cannot be stored leaves ossec.conf pointing where it did.
sed -i 's:\*/etc/ossec.conf:*/etc/enrollment_token:' "${RUN_DIR}/shim/mv"
PATH="${RUN_DIR}/shim:${PATH}" bash "${TARGET}" "${RUN_DIR}" upgrade >/dev/null 2>"${RUN_DIR}/stderr"
RUN_STATUS="$?"
check "a token that cannot be stored fails the upgrade" "1" "${RUN_STATUS}"
check "a token that cannot be stored keeps the configuration" "${LEGACY_CONF}" \
      "$(cat "${RUN_DIR}/etc/ossec.conf")"
rm -rf "${RUN_DIR}"

unset WAZUH_ENROLLMENT_TOKEN

# No anchor yet is expected while a token waits for the first start, or after a remote upgrade.
for pending in etc/enrollment_token var/incoming/root-ca.pem; do
    RUN_DIR="$(make_installdir "${DESC_WITH_KEY}" 0)"
    mkdir -p "${RUN_DIR}/$(dirname "${pending}")"
    touch "${RUN_DIR}/${pending}"
    bash "${TARGET}" "${RUN_DIR}" upgrade >/dev/null 2>"${RUN_DIR}/stderr"
    check "an upgrade with ${pending} present does not warn about the anchor" "0" \
          "$(grep -c "no trust anchor" "${RUN_DIR}/stderr")"
    rm -rf "${RUN_DIR}"
done

echo
echo "${checks} checks, ${failures} failed"
[ "${failures}" -eq 0 ]
