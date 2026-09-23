#!/bin/bash

# Copyright (C) 2015, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Drives src/init/credentials/resolve-credentials.sh: the manager's half of the credential
# resolution ladder -- which keys it owns, which it consumes, what it does at each of the two
# moments, and what it reports when something is missing.
#
# The shared helpers it stands on (wazuh-credentials.sh, wazuh-manager-certificates.sh) have their
# own suite, test-wazuh-helpers.sh, which covers the file format, locking, permissions, SAN
# discovery and the certificate states in far more depth. Nothing here re-tests those; the cases
# below are about the orchestration on top.
#
# Must run as root, like the resolver itself. The helpers refuse any base directory with a
# group- or world-writable ancestor, so the throwaway tree goes under /root rather than /tmp --
# the same reason test-wazuh-helpers.sh uses /root. Override with WAZUH_TEST_PARENT only to
# another secure root-owned directory.
#
# The keystore and rbac_control are stubs, so the cases run without a build. OpenSSL is real, so
# the certificates produced are verified against the CA that signed them.
#
#   sudo ./test_resolve_credentials.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRED_SRC="${SCRIPT_DIR}/../credentials"
TEST_PARENT="${WAZUH_TEST_PARENT:-/root}"

failures=0
checks=0

if [ "$(id -u)" -ne 0 ]; then
    echo "This suite must run as root: the helpers require a root-owned base directory." >&2
    exit 1
fi

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

# A throwaway manager tree: stub keystore (a file per family.key), stub rbac_control (records the
# JSON it was given on stdin and creates rbac.db), and the real shared helpers. Echoes the root.
make_tree() {

    local root
    root="$(mktemp -d "${TEST_PARENT}/wazuh-resolver-tests.XXXXXX")"
    chmod 0700 "${root}"

    mkdir -p "${root}/base" "${root}/home/bin" "${root}/home/lib" \
             "${root}/home/api/configuration/security" "${root}/store"
    chmod 0700 "${root}/base"

    # 1770 root:<group> is what InstallServer() creates and what the certificate helper insists on.
    install -d -m 1770 -o root -g root "${root}/home/etc/certs"

    cp "${CRED_SRC}/wazuh-credentials.sh" "${CRED_SRC}/wazuh-manager-certificates.sh" "${root}/home/lib/"
    cp "${CRED_SRC}/resolve-credentials.sh" "${root}/home/bin/resolve-credentials"
    chmod +x "${root}/home/bin/resolve-credentials"

    cat > "${root}/home/bin/wazuh-manager-keystore" <<'STUB'
#!/bin/sh
S="$(dirname "$0")/../../store"
f=""; k=""; g=0
while [ -n "$1" ]; do
    case "$1" in
        -f) f="$2"; shift 2 ;;
        -k) k="$2"; shift 2 ;;
        -g) g=1; shift ;;
        *)  shift ;;
    esac
done
if [ "${g}" -eq 1 ]; then
    [ -s "${S}/${f}.${k}" ] && cat "${S}/${f}.${k}" && exit 0
    exit 1
fi
cat > "${S}/${f}.${k}"
exit 0
STUB

    cat > "${root}/home/bin/rbac_control" <<'STUB'
#!/bin/sh
[ "$1" = "seed" ] || exit 2
D="$(dirname "$0")/../api/configuration/security"
cat > "${D}/seeded.json"
cp "${D}/seeded.json" "${D}/rbac.db"
exit 0
STUB

    chmod +x "${root}/home/bin/wazuh-manager-keystore" "${root}/home/bin/rbac_control"
    echo "${root}"

}

# Run the resolver against a tree. Sets RC and leaves the combined output in ${RESOLVER_OUT},
# which callers read with resolver_output.
#
# Deliberately not "echo the output and let the caller capture it": command substitution runs the
# function in a subshell, so the RC it sets there never reaches the caller and every exit-status
# check silently reads 0.
#
# root:root stands in for the service identity, as test-wazuh-helpers.sh does: the certificate
# helper requires the user and group to exist and creates neither.
RESOLVER_OUT="$(mktemp)"
trap 'rm -f "${RESOLVER_OUT}"' EXIT

run_resolver() {

    local root="$1"; shift

    WAZUH_BASE_DIR="${root}/base" \
    WAZUH_MANAGER_USER=root WAZUH_MANAGER_GROUP=root \
        "${root}/home/bin/resolve-credentials" "$@" -H "${root}/home" > "${RESOLVER_OUT}" 2>&1
    RC=$?

}

resolver_output() {

    cat "${RESOLVER_OUT}"

}

seeded_password() {

    sed -n "s/.*\"$2\": \"\([^\"]*\)\".*/\1/p" "$1/home/api/configuration/security/seeded.json" 2>/dev/null

}

# A value the manager published, read from inside the managed block only: a key the operator wrote
# outside it may carry the same name, and reading that back would make "the manager published
# nothing" indistinguishable from "the manager published what was already there".
published() {

    awk -v key="$2" '
        /^# >>> wazuh generated/ { inblock = 1; next }
        /^# >>> end wazuh generated/ { inblock = 0; next }
        inblock && index($0, key "=") == 1 { print substr($0, length(key) + 2) }
    ' "$1/base/credentials.env" 2>/dev/null | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//"

}

write_credentials() {

    printf '%s\n' "$2" > "$1/base/credentials.env"
    chmod 0600 "$1/base/credentials.env"

}

cleanup() {

    case "$1" in
        "${TEST_PARENT}"/wazuh-resolver-tests.*) rm -rf "$1" ;;
    esac

}

# --------------------------------------------------------------------------------------------
# The two moments
# --------------------------------------------------------------------------------------------

# A clean host resolves everything it owns and nothing it merely consumes, and says nothing about
# the difference: the installer has no opinion about whether the manager can run.
root="$(make_tree)"
run_resolver "${root}" --install
check "a clean install exits 0" "0" "${RC}"
check "the two API passwords are seeded" "yes" \
    "$([ -n "$(seeded_password "${root}" wazuh)" ] && [ -n "$(seeded_password "${root}" wazuh-wui)" ] && echo yes)"
check "both are published to the credentials file" "yes" \
    "$([ "$(published "${root}" WAZUH_MANAGER_API_PASSWORD)" = "$(seeded_password "${root}" wazuh)" ] && \
       [ "$(published "${root}" WAZUH_MANAGER_WUI_PASSWORD)" = "$(seeded_password "${root}" wazuh-wui)" ] && echo yes)"
check "the consumed indexer key is never published" "" \
    "$(published "${root}" WAZUH_INDEXER_MANAGER_PASSWORD)"

# Start on that same host: the one credential the manager cannot invent is missing, and it is named.
run_resolver "${root}" --prestart
check "a start with no indexer credential fails" "1" "${RC}"
check "and names the missing key" "yes" \
    "$(grep -q 'MISSING WAZUH_INDEXER_MANAGER_PASSWORD' <<< "$(resolver_output)" && echo yes)"

# The indexer publishes its key; the manager picks it up at start with no reinstall or repair.
printf "WAZUH_INDEXER_MANAGER_PASSWORD='Indexer.Wr0te1'\n" >> "${root}/base/credentials.env"
run_resolver "${root}" --prestart
check "the next start succeeds once the key is there" "0" "${RC}"
check "and the credential is in the manager's own store" "Indexer.Wr0te1" \
    "$(cat "${root}/store/indexer.password")"

# Re-running changes nothing: an upgrade takes step 0 for everything.
before="$(md5sum "${root}/base/credentials.env" "${root}/store/indexer.password" \
    "${root}/home/etc/certs/remoted.pem" | md5sum)"
run_resolver "${root}" --prestart
check "re-running is a no-op" "${before}" \
    "$(md5sum "${root}/base/credentials.env" "${root}/store/indexer.password" \
        "${root}/home/etc/certs/remoted.pem" | md5sum)"
cleanup "${root}"

# Two independent installations must never share a credential.
root="$(make_tree)";  run_resolver "${root}" --install
root2="$(make_tree)"; run_resolver "${root2}" --install
check "two clean installs generate different passwords" "differ" \
    "$([ "$(seeded_password "${root}" wazuh)" != "$(seeded_password "${root2}" wazuh)" ] && echo differ)"
check "generated passwords are 32 characters" "32" \
    "$(printf '%s' "$(seeded_password "${root}" wazuh)" | wc -c)"
cleanup "${root}"; cleanup "${root2}"

# --------------------------------------------------------------------------------------------
# Where a value comes from
# --------------------------------------------------------------------------------------------

root="$(make_tree)"
write_credentials "${root}" "WAZUH_MANAGER_API_PASSWORD='Supplied.Api1'"
run_resolver "${root}" --install
check "a supplied value is what gets seeded" "Supplied.Api1" "$(seeded_password "${root}" wazuh)"
check "and the user with no supplied value still gets one" "yes" \
    "$([ -n "$(seeded_password "${root}" wazuh-wui)" ] && echo yes)"
cleanup "${root}"

root="$(make_tree)"
write_credentials "${root}" "WAZUH_MANAGER_API_PASSWORD='FromFile.Aa1'"
WAZUH_BASE_DIR="${root}/base" WAZUH_MANAGER_USER=root WAZUH_MANAGER_GROUP=root \
    WAZUH_MANAGER_API_PASSWORD='FromEnvir.Aa1' \
    "${root}/home/bin/resolve-credentials" --install -H "${root}/home" > /dev/null 2>&1
check "the environment overrides the file" "FromEnvir.Aa1" "$(seeded_password "${root}" wazuh)"
cleanup "${root}"

# Step 0 wins over both channels: a value edited into the file after seeding changes nothing.
root="$(make_tree)"
run_resolver "${root}" --install
seeded="$(seeded_password "${root}" wazuh)"
write_credentials "${root}" "WAZUH_MANAGER_API_PASSWORD='Edited.Later1'
WAZUH_INDEXER_MANAGER_PASSWORD='Indexer.Wr0te1'"
run_resolver "${root}" --prestart
check "editing the file does not reseed an existing database" "${seeded}" "$(seeded_password "${root}" wazuh)"
check "and the run still succeeds" "0" "${RC}"
cleanup "${root}"

# --------------------------------------------------------------------------------------------
# An invalid value is a failure, not an absence
# --------------------------------------------------------------------------------------------

root="$(make_tree)"
write_credentials "${root}" "WAZUH_MANAGER_API_PASSWORD='short'"
run_resolver "${root}" --install
install_output="$(resolver_output)"
check "an invalid value still lets the install exit 0" "0" "${RC}"
check "but nothing is seeded" "" "$(seeded_password "${root}" wazuh)"
check "it never falls through to generating a replacement" "" \
    "$(published "${root}" WAZUH_MANAGER_API_PASSWORD)"

run_resolver "${root}" --prestart
start_output="$(resolver_output)"
check "and the service refuses to start" "1" "${RC}"
check "naming the key and the rule" "yes" \
    "$(grep -q 'INVALID WAZUH_MANAGER_API_PASSWORD' <<< "${start_output}" && echo yes)"
check "the value is never printed" "" \
    "$(grep -o 'short' <<< "${install_output}${start_output}" | head -1)"
cleanup "${root}"

# The seeding policy is PCI DSS 8.3.6 -- a letter and a digit -- not the Server API's stricter
# create/update rule. wazuh_password_generate() guarantees no symbol, so requiring one here would
# refuse to seed on roughly one installation in a hundred and fifty.
root="$(make_tree)"
write_credentials "${root}" "WAZUH_MANAGER_API_PASSWORD='NoSymbolsHere123'"
run_resolver "${root}" --install
check "a supplied value with no symbol is accepted at seeding" "NoSymbolsHere123" \
    "$(seeded_password "${root}" wazuh)"
cleanup "${root}"

# A seeding failure must block the start rather than pass silently. The resolver's caller ignores
# the per-credential return values, so a failure that marks nothing would let the service come up
# against a database that was never created.
root="$(make_tree)"
cat > "${root}/home/bin/rbac_control" <<'STUB'
#!/bin/sh
exit 1
STUB
chmod +x "${root}/home/bin/rbac_control"
run_resolver "${root}" --prestart
check "a failure to seed rbac.db blocks the start" "1" "${RC}"
check "and is named" "yes" "$(grep -q 'MISSING rbac.db' <<< "$(resolver_output)" && echo yes)"
run_resolver "${root}" --install
check "but still lets the install exit 0" "0" "${RC}"
cleanup "${root}"

# --------------------------------------------------------------------------------------------
# What the resolver asks the certificate helper for
#
# The helper's own states are covered by test-wazuh-helpers.sh. What matters here is that the
# manager gets both pairs it needs, chained to one anchor, and that an unusable result blocks the
# start instead of being reported as success.
# --------------------------------------------------------------------------------------------

root="$(make_tree)"
run_resolver "${root}" --install
for pair in remoted indexer-connector; do
    check "${pair} is issued and verifies against the CA" "yes" \
        "$(openssl verify -CAfile "${root}/base/ca/root-ca.pem" \
            "${root}/home/etc/certs/${pair}.pem" > /dev/null 2>&1 && echo yes)"
done
check "the anchor is installed for the manager to read" "yes" \
    "$([ -f "${root}/home/etc/certs/root-ca.pem" ] && echo yes)"
check "the connector leaf is a client certificate" "yes" \
    "$(openssl x509 -in "${root}/home/etc/certs/indexer-connector.pem" -noout -ext extendedKeyUsage \
        2>/dev/null | grep -q 'Client Authentication' && echo yes)"
check "the remoted leaf is a server certificate" "yes" \
    "$(openssl x509 -in "${root}/home/etc/certs/remoted.pem" -noout -ext extendedKeyUsage \
        2>/dev/null | grep -q 'Server Authentication' && echo yes)"
check "the CA private key is never copied into the service directory" "" \
    "$(ls "${root}/home/etc/certs" | grep 'root-ca.key')"
cleanup "${root}"

# An anchor with no private key: this host cannot sign and must not pretend to.
root="$(make_tree)"
mkdir -p "${root}/base/ca"
chmod 0700 "${root}/base/ca"
openssl req -x509 -nodes -newkey rsa:2048 -sha256 -days 1 \
    -keyout "${root}/other-ca.key" -out "${root}/base/ca/root-ca.pem" \
    -subj "/CN=Somebody elses CA" > /dev/null 2>&1
chmod 0644 "${root}/base/ca/root-ca.pem"
run_resolver "${root}" --prestart
check "an anchor-only CA leaves the certificates unresolved" "1" "${RC}"
check "and the resolver says so" "yes" \
    "$(grep -q 'MISSING usable TLS certificates' <<< "$(resolver_output)" && echo yes)"
check "no leaf is issued" "" "$(ls "${root}/home/etc/certs" | grep '^remoted')"
check "and no CA private key appears on this host" "" "$(ls "${root}/base/ca" | grep 'root-ca.key')"
cleanup "${root}"

# Explicit SANs replace discovery, for each of the two leaves independently.
root="$(make_tree)"
write_credentials "${root}" "WAZUH_MANAGER_CERT_SANS='DNS:connector.corp.local'
WAZUH_MANAGER_REMOTED_CERT_SANS='DNS:agents.corp.local,IP:10.0.1.11'"
run_resolver "${root}" --install
check "the connector SAN setting is honoured" "yes" \
    "$(openssl x509 -in "${root}/home/etc/certs/indexer-connector.pem" -noout -ext subjectAltName \
        2>/dev/null | grep -q 'connector.corp.local' && echo yes)"
check "the remoted SAN setting is honoured separately" "yes" \
    "$(openssl x509 -in "${root}/home/etc/certs/remoted.pem" -noout -ext subjectAltName \
        2>/dev/null | grep -q 'agents.corp.local' && echo yes)"
cleanup "${root}"

# --------------------------------------------------------------------------------------------

echo ""
echo "${checks} checks, ${failures} failure(s)"
[ "${failures}" -eq 0 ] || exit 1
exit 0
