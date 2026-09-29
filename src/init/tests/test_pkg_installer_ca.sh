#!/bin/bash

# Copyright (C) 2015, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Drives pkg_installer.sh's handling of a manager-delivered CA against a throwaway install
# directory. curl and rpm are stubs, so no manager or network is needed: each case chooses what
# the probe of the manager answers. No package is staged, so every run stops after the gates,
# which is past every decision about the CA.
#
#   ./test_pkg_installer_ca.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${SCRIPT_DIR}/../pkg_installer.sh"

failures=0
checks=0

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

LEGACY_CONF='<ossec_config>
  <client>
    <server>
      <address>127.0.0.1</address>
    </server>
  </client>
</ossec_config>
'

CERTIFICATE_CONF='<ossec_config>
  <client>
    <server>
      <address>127.0.0.1</address>
    </server>
  </client>
  <agent>
    <ssl>
      <verification_mode>certificate</verification_mode>
    </ssl>
  </agent>
</ossec_config>
'

# A self-signed CA:TRUE certificate, which is the only shape the manager delivers.
make_ca() {

    printf '[req]\ndistinguished_name=dn\n[dn]\n[v3_ca]\nbasicConstraints=critical,CA:TRUE\n' > "${WORK}/ca.cnf"
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "${WORK}/ca.key" -out "${WORK}/ca.pem" \
        -days 30 -subj "/CN=test-ca" -config "${WORK}/ca.cnf" -extensions v3_ca > /dev/null 2>&1

}

# A PATH holding the system's tools, with openssl left out when ${1} is "no", and stubs for:
#   rpm   answers the installed agent version (${2})
#   curl  answers --cacert with STUB_CACERT_RC, the first -k call (the connectivity check) with 0
#         and any later -k call with STUB_RETRY_RC, and the system-store check with 60
make_path() {

    local with_openssl="$1" agent_version="$2" bin="$3"

    mkdir -p "${bin}"
    for tool in /usr/bin/* /bin/* /usr/sbin/* /sbin/*; do
        [ -x "${tool}" ] && [ ! -e "${bin}/$(basename "${tool}")" ] && ln -s "${tool}" "${bin}/" 2>/dev/null
    done
    rm -f "${bin}/curl" "${bin}/wget" "${bin}/rpm" "${bin}/dpkg-query"
    [ "${with_openssl}" = "no" ] && rm -f "${bin}/openssl"

    printf '#!/bin/sh\necho %s\n' "${agent_version}" > "${bin}/rpm"
    cat > "${bin}/curl" <<'EOF'
#!/bin/bash
for arg in "$@"; do
    case "${arg}" in
        --cacert) exit "${STUB_CACERT_RC:-0}" ;;
    esac
done
for arg in "$@"; do
    if [ "${arg}" = "-k" ]; then
        if [ -e "${STUB_STATE}/connectivity-done" ]; then
            exit "${STUB_RETRY_RC:-0}"
        fi
        touch "${STUB_STATE}/connectivity-done"
        exit 0
    fi
done
exit 60
EOF
    chmod +x "${bin}/rpm" "${bin}/curl"

}

# Runs the target against a fresh tree and leaves it at ${WORK}/<case>.
#   $1 case name   $2 ossec.conf   $3 with openssl (yes|no)   $4 installed version
#   $5 pre-existing anchor (yes|no)
run_case() {

    local name="$1" conf="$2" with_openssl="$3" version="$4" anchor="$5"
    local dir="${WORK}/${name}"

    mkdir -p "${dir}/etc" "${dir}/logs" "${dir}/var/upgrade" "${dir}/var/incoming" "${dir}/state"
    printf '%s' "${conf}" > "${dir}/etc/ossec.conf"
    cp "${WORK}/ca.pem" "${dir}/var/incoming/root-ca.pem"
    if [ "${anchor}" = "yes" ]; then
        mkdir -p "${dir}/etc/certs"
        cp "${WORK}/ca.pem" "${dir}/etc/certs/root-ca.pem"
    fi
    make_path "${with_openssl}" "${version}" "${dir}/bin"

    (cd "${dir}" && env -i PATH="${dir}/bin" HOME="${dir}" INSTALLDIR="${dir}" STUB_STATE="${dir}/state" \
        STUB_CACERT_RC="${STUB_CACERT_RC:-0}" STUB_RETRY_RC="${STUB_RETRY_RC:-0}" \
        bash "${TARGET}" > /dev/null 2>&1)

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

log_count() {

    grep -c -E -- "$2" "${WORK}/$1/logs/upgrade.log"

}

present() {

    [ -e "${WORK}/$1/$2" ] && echo yes || echo no

}

if ! command -v openssl > /dev/null 2>&1; then
    echo "openssl is required to build the test CA"
    exit 1
fi
make_ca

# A CA that verifies the manager is installed.
STUB_CACERT_RC=0 run_case verified "${LEGACY_CONF}" yes 4.14.7 no
check "a CA that verifies the manager is logged as such" "1" "$(log_count verified "Delivered CA verifies the manager")"
check "a CA that verifies the manager is installed" "yes" "$(present verified etc/certs/root-ca.pem)"
check "an installed CA is removed from var/incoming" "no" "$(present verified var/incoming/root-ca.pem)"

# A CA the manager's certificate does not chain to is refused and removed.
STUB_CACERT_RC=60 run_case rejected "${LEGACY_CONF}" yes 4.14.7 no
check "a CA that does not verify the manager is refused" "1" "$(log_count rejected "Delivered CA at .* does not verify the manager")"
check "a refused CA is not installed" "no" "$(present rejected etc/certs/root-ca.pem)"
check "a refused CA is removed from var/incoming" "no" "$(present rejected var/incoming/root-ca.pem)"

# A handshake error is a refusal when the same handshake succeeds without verification.
STUB_CACERT_RC=35 STUB_RETRY_RC=0 run_case handshake_ca "${LEGACY_CONF}" yes 4.14.7 no
check "a handshake error that -k does not reproduce is a refusal" "1" "$(log_count handshake_ca "Delivered CA at .* does not verify the manager")"
check "that CA is not installed" "no" "$(present handshake_ca etc/certs/root-ca.pem)"

# ...and "could not check" when it fails without verification too.
STUB_CACERT_RC=35 STUB_RETRY_RC=35 run_case handshake_any "${LEGACY_CONF}" yes 4.14.7 no
check "a handshake error that -k reproduces cannot tell" "1" "$(log_count handshake_any "Could not check the delivered CA")"
check "that CA is installed on its own validation" "yes" "$(present handshake_any etc/certs/root-ca.pem)"

# Under 'certificate' the agent does not check the hostname, so the probe does not run.
STUB_CACERT_RC=60 run_case certificate "${CERTIFICATE_CONF}" yes 4.14.7 no
check "the probe is skipped under certificate mode" "0" \
      "$(log_count certificate "Delivered CA verifies|Delivered CA at .* does not verify|Could not check the delivered CA")"
check "the CA is installed under certificate mode" "yes" "$(present certificate etc/certs/root-ca.pem)"

# Without openssl and without an anchor the CA is kept for (4126), and the hint is printed once.
run_case no_openssl "${LEGACY_CONF}" no 4.14.7 no
check "without openssl the CA is left in var/incoming" "yes" "$(present no_openssl var/incoming/root-ca.pem)"
check "the recovery hint is printed once" "1" "$(log_count no_openssl "wazuh-agent-auth --token-file <file> --certs-only")"
check "the hint names --no-credential" "1" "$(log_count no_openssl "create-enrollment-token --no-credential")"
check "the legacy line points back to the hint" "1" "$(log_count no_openssl "See the 'No trust anchor' line above")"

# Without openssl but with an anchor, the delivered copy is discarded.
run_case no_openssl_anchor "${LEGACY_CONF}" no 4.14.7 yes
check "with an anchor, the delivered copy is discarded" "1" "$(log_count no_openssl_anchor "so the delivered copy is discarded")"
check "the discarded copy is gone from var/incoming" "no" "$(present no_openssl_anchor var/incoming/root-ca.pem)"
check "the existing anchor is kept" "yes" "$(present no_openssl_anchor etc/certs/root-ca.pem)"

# A 5.x agent with no anchor aborts at the trust check, pointing back to the hint.
run_case no_openssl_5x "${LEGACY_CONF}" no 5.0.0 no
check "a 5.x agent with no anchor aborts and points back to the hint" "1" \
      "$(log_count no_openssl_5x "Upgrade failed. The system trust store does not verify.*See the 'No trust anchor' line above")"

echo
echo "${checks} checks, ${failures} failed"
[ "${failures}" -eq 0 ]
