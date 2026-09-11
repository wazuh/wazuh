#!/bin/bash

# Copyright (C) 2015, Wazuh Inc.
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

# Build an INSTALLDIR whose bin/wazuh-agentd answers --show-token with ${1} and exits ${2}.
# Echoes the directory; the caller removes it.
make_installdir() {

    local description="$1" status="$2" installdir

    installdir="$(mktemp -d)"
    mkdir -p "${installdir}/etc" "${installdir}/tmp" "${installdir}/logs" "${installdir}/bin"
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

    sed -n 's/.*refused \[\([A-Z_]*\)\].*/\1/p' "${RUN_DIR}/stderr" | head -1

}

# A refusal must leave the configuration the package shipped and nothing of its own.
check_refused() {

    local name="$1" expected_code="$2"

    check "${name}: names ${expected_code}" "${expected_code}" "$(refusal_code)"
    check "${name}: leaves the shipped placeholder" "IP:1517/wazuh-manager/" "$(endpoint_of)"
    check "${name}: stores no token" "absent" \
          "$([ -e "${RUN_DIR}/etc/enrollment_token" ] && echo present || echo absent)"
    check "${name}: writes no authd.pass" "absent" \
          "$([ -e "${RUN_DIR}/etc/authd.pass" ] && echo present || echo absent)"

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
check "a token alone succeeds" "0" "${RUN_STATUS}"
check "a token alone writes no authd.pass" "absent" \
      "$([ -e "${RUN_DIR}/etc/authd.pass" ] && echo present || echo absent)"
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

# --- The one variable that can still defeat a token -------------------------------------------
# An explicit mode always wins over the anchor the bootstrap is about to write, so any value
# here either changes nothing or silently undoes the token this install just consumed.

for mode in full certificate system none; do
    export WAZUH_SSL_VERIFICATION="${mode}"
    run_target "${DESC_WITH_KEY}" 0
    check_refused "WAZUH_SSL_VERIFICATION=${mode} alongside a token" "ERR_MODE_WITH_TOKEN"
    rm -rf "${RUN_DIR}"
    unset WAZUH_SSL_VERIFICATION
done

unset WAZUH_ENROLLMENT_TOKEN

# --- No token at all --------------------------------------------------------------------------
# Registration does not happen and says so, but the settings that were never about registration
# still apply: that is what an install configured by hand afterwards needs.

run_target "${DESC_WITH_KEY}" 0
check "no token names the token in its refusal" "ERR_NO_TOKEN" "$(refusal_code)"
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

echo
echo "${checks} checks, ${failures} failed"
[ "${failures}" -eq 0 ]
