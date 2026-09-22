#!/bin/bash

# Copyright (C) 2015, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Drives ValidateIndexerVars() and StoreIndexerCredentials() from inst-functions.sh against a
# throwaway INSTALLDIR whose keystore tool is a stub that records how it was called. What matters
# is that the password reaches the keystore through the standard input and never through an
# argument: the process list is readable by every account on the host.
#
#   ./test_indexer_credentials.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

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

# Build an INSTALLDIR whose wazuh-manager-keystore appends '<args>|<stdin>' to calls.log.
make_installdir() {

    local installdir
    installdir="$(mktemp -d)"
    mkdir -p "${installdir}/bin"

    cat > "${installdir}/bin/wazuh-manager-keystore" <<'STUB'
#!/bin/sh
read -r secret
echo "$*|${secret}" >> "$(dirname "$0")/../calls.log"
STUB
    chmod +x "${installdir}/bin/wazuh-manager-keystore"

    echo "${installdir}"
}

# Run one of the functions from the repository root, which is where inst-functions.sh resolves its
# own includes from, with TEST_INSTYPE and TEST_INSTALLDIR applied after the sources: shared.sh sets
# INSTYPE and INSTALLDIR unconditionally. Echoes the exit status.
run_target() {

    local function_name="$1"

    (
        cd "${REPO_ROOT}" || exit 1
        . ./src/init/shared.sh > /dev/null 2>&1
        . ./src/init/inst-functions.sh > /dev/null 2>&1

        INSTYPE="${TEST_INSTYPE}"
        [ -n "${TEST_INSTALLDIR}" ] && INSTALLDIR="${TEST_INSTALLDIR}"

        "${function_name}" > /dev/null 2>&1
    )
    echo "$?"
}

export TEST_INSTYPE TEST_INSTALLDIR INDEXER_USER_PASSWORD INDEXER_USER_NAME

echo "== ValidateIndexerVars =="
TEST_INSTYPE="manager" INDEXER_USER_PASSWORD="" INDEXER_USER_NAME=""
check "a manager with no indexer password is refused" "1" "$(run_target ValidateIndexerVars)"

TEST_INSTYPE="agent"
check "an agent has no indexer connection to configure" "0" "$(run_target ValidateIndexerVars)"

TEST_INSTYPE="manager" INDEXER_USER_PASSWORD="Ind3xer-Pass."
check "a manager with the password set is accepted" "0" "$(run_target ValidateIndexerVars)"

echo "== StoreIndexerCredentials =="
TEST_INSTALLDIR="$(make_installdir)"
check "it exits 0" "0" "$(run_target StoreIndexerCredentials)"
check "the user name is piped in" "-f indexer -k username|wazuh-manager" \
    "$(sed -n '1p' "${TEST_INSTALLDIR}/calls.log")"
check "the password is piped in" "-f indexer -k password|Ind3xer-Pass." \
    "$(sed -n '2p' "${TEST_INSTALLDIR}/calls.log")"
check "no password reaches a command line" "0" \
    "$(cut -d'|' -f1 "${TEST_INSTALLDIR}/calls.log" | grep -c 'Ind3xer-Pass\.')"
rm -rf "${TEST_INSTALLDIR}"

TEST_INSTALLDIR="$(make_installdir)"
INDEXER_USER_NAME="other-user"
run_target StoreIndexerCredentials > /dev/null
check "INDEXER_USER_NAME overrides the user name" "-f indexer -k username|other-user" \
    "$(sed -n '1p' "${TEST_INSTALLDIR}/calls.log")"
rm -rf "${TEST_INSTALLDIR}"
INDEXER_USER_NAME=""

TEST_INSTALLDIR="$(mktemp -d)"
mkdir -p "${TEST_INSTALLDIR}/bin"
printf '#!/bin/sh\nexit 1\n' > "${TEST_INSTALLDIR}/bin/wazuh-manager-keystore"
chmod +x "${TEST_INSTALLDIR}/bin/wazuh-manager-keystore"
check "a keystore that fails stops the installation" "1" "$(run_target StoreIndexerCredentials)"
rm -rf "${TEST_INSTALLDIR}"

TEST_INSTALLDIR="$(mktemp -d)"
check "a missing keystore tool stops the installation" "1" "$(run_target StoreIndexerCredentials)"
rm -rf "${TEST_INSTALLDIR}"

echo
echo "${checks} checks, ${failures} failures"
[ "${failures}" -eq 0 ]
