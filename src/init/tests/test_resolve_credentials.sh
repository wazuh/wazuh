#!/bin/bash

# Copyright (C) 2015, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Drives resolve-credentials.sh against a throwaway installation directory whose two tools are stubs that
# record how they were called. The check names say what each case pins down.
#
#   ./test_resolve_credentials.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${SCRIPT_DIR}/../resolve-credentials.sh"

failures=0
checks=0

check() {

    local description="$1"
    local expected="$2"
    local actual="$3"

    checks=$((checks + 1))
    if [ "${expected}" = "${actual}" ]; then
        echo "ok   - ${description}"
    else
        echo "FAIL - ${description}"
        echo "       expected: ${expected}"
        echo "       actual:   ${actual}"
        failures=$((failures + 1))
    fi
}

# An installation directory whose keystore records '<args>|<stdin>' and whose rbac_control succeeds or
# fails on demand.
make_installdir() {

    local rbac_status="${1:-0}"
    local installdir
    installdir="$(mktemp -d)"
    mkdir -p "${installdir}/bin"

    cat > "${installdir}/bin/wazuh-manager-keystore" <<'STUB'
#!/bin/sh
read -r secret
echo "$*|${secret}" >> "$(dirname "$0")/../keystore.log"
STUB

    cat > "${installdir}/bin/rbac_control" <<STUB
#!/bin/sh
echo "\$*" >> "\$(dirname "\$0")/../rbac.log"
echo "	wazuh: GENERATED"
exit ${rbac_status}
STUB

    chmod +x "${installdir}/bin/wazuh-manager-keystore" "${installdir}/bin/rbac_control"
    echo "${installdir}"
}

# Sets OUTPUT and STATUS rather than echoing, so the caller can assert on both. Not called from a command
# substitution for that reason: it would run in a subshell and the assignments would not survive it.
run_target() {

    OUTPUT="$(sh "${TARGET}" "$@" 2>&1)"
    STATUS=$?
}

echo "== Everything resolves =="
DIR="$(make_installdir)"
INDEXER_PASSWORD="Ind3xer-Pass." run_target "${DIR}"
check "exit status 0" "0" "${STATUS}"
check "the user name is piped in" "-f indexer -k username|wazuh-manager" "$(sed -n '1p' "${DIR}/keystore.log")"
check "the password is piped in" "-f indexer -k password|Ind3xer-Pass." "$(sed -n '2p' "${DIR}/keystore.log")"
check "no password on a command line" "0" \
    "$(cut -d'|' -f1 "${DIR}/keystore.log" | grep -c 'Ind3xer-Pass\.')"
check "no password anywhere in the output" "0" "$(echo "${OUTPUT}" | grep -c 'Ind3xer-Pass\.')"
check "the owned accounts are provisioned" "provision-passwords" "$(cat "${DIR}/rbac.log")"
check "nothing is reported missing" "0" "$(echo "${OUTPUT}" | grep -c 'MISSING')"
check "two accounts resolved" "2" "$(echo "${OUTPUT}" | grep -c 'resolved')"
rm -rf "${DIR}"

echo "== The consumed credential is missing =="
DIR="$(make_installdir)"
INDEXER_PASSWORD="" run_target "${DIR}"
check "still exits 0 on a package install" "0" "${STATUS}"
check "the keystore is not written" "1" "$([ -f "${DIR}/keystore.log" ]; echo $?)"
check "the owned accounts are still provisioned" "provision-passwords" "$(cat "${DIR}/rbac.log")"
check "it names the variable" "1" "$(echo "${OUTPUT}" | grep -c 'INDEXER_PASSWORD')"
check "it says the service was not started" "1" "$(echo "${OUTPUT}" | grep -c 'service was not started')"
check "it points at the documentation" "1" "$(echo "${OUTPUT}" | grep -c 'documentation.wazuh.com')"
rm -rf "${DIR}"

echo "== The same case in a container =="
DIR="$(make_installdir)"
INDEXER_PASSWORD="" run_target "${DIR}" --container
check "exits non-zero" "1" "${STATUS}"
rm -rf "${DIR}"

DIR="$(make_installdir)"
INDEXER_PASSWORD="Ind3xer-Pass." run_target "${DIR}" --container
check "a container that resolves everything exits 0" "0" "${STATUS}"
rm -rf "${DIR}"

echo "== A keystore that refuses, and owned accounts that cannot be provisioned =="
DIR="$(make_installdir)"
rm "${DIR}/bin/wazuh-manager-keystore"
INDEXER_PASSWORD="Ind3xer-Pass." run_target "${DIR}"
check "a missing keystore is reported, not fatal" "0" "${STATUS}"
check "and it is named as missing" "1" "$(echo "${OUTPUT}" | grep -c 'MISSING.*indexer password')"
rm -rf "${DIR}"

DIR="$(make_installdir 1)"
INDEXER_PASSWORD="Ind3xer-Pass." run_target "${DIR}"
check "rbac_control failing is reported, not fatal" "0" "${STATUS}"
check "and it is named as missing" "1" "$(echo "${OUTPUT}" | grep -c 'MISSING.*Server API passwords')"
rm -rf "${DIR}"

echo "== INDEXER_USERNAME overrides the account =="
DIR="$(make_installdir)"
INDEXER_PASSWORD="Ind3xer-Pass." INDEXER_USERNAME="other-user" run_target "${DIR}"
check "the override is used" "-f indexer -k username|other-user" "$(sed -n '1p' "${DIR}/keystore.log")"
rm -rf "${DIR}"

echo
echo "${checks} checks, ${failures} failures"
[ "${failures}" -eq 0 ]
