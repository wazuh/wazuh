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
# The shared helpers it stands on (wazuh-credentials.sh, downloaded; wazuh-manager-certificates.sh,
# in src/init/credentials/) have their
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
# wazuh-credentials.sh is not in this repository: it is shared with the indexer and the dashboard,
# owned by wazuh-installation-assistant, and downloaded by `make deps` into
# src/external/wazuh-credentials/. Everything else the resolver needs is in CRED_SRC.
SHARED_SRC="${WAZUH_SHARED_HELPER_DIR:-${SCRIPT_DIR}/../../external/wazuh-credentials}"
TEST_PARENT="${WAZUH_TEST_PARENT:-/root}"

if [ ! -f "${SHARED_SRC}/wazuh-credentials.sh" ]; then
    echo "cannot find ${SHARED_SRC}/wazuh-credentials.sh" >&2
    echo "run 'make -C src deps TARGET=manager' to download it, or set WAZUH_SHARED_HELPER_DIR" >&2
    exit 1
fi

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
             "${root}/home/api/configuration/security" "${root}/home/queue/keystore"
    chmod 0700 "${root}/base"

    # 1770 root:<group> is what InstallServer() creates and what the certificate helper insists on.
    install -d -m 1770 -o root -g root "${root}/home/etc/certs"

    cp "${SHARED_SRC}/wazuh-credentials.sh" "${root}/home/lib/"
    cp "${CRED_SRC}/wazuh-manager-certificates.sh" "${root}/home/lib/"
    cp "${CRED_SRC}/resolve-credentials.sh" "${root}/home/bin/resolve-credentials"
    chmod +x "${root}/home/bin/resolve-credentials"

    cat > "${root}/home/bin/wazuh-manager-keystore" <<'STUB'
#!/bin/sh
S="$(dirname "$0")/../queue/keystore"
mkdir -p "${S}"
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
    "$(cat "${root}/home/queue/keystore/indexer.password")"

# Re-running changes nothing: every ladder takes step 0 for everything already resolved.
state() {
    md5sum "$1/base/credentials.env" "$1/home/queue/keystore/indexer.password" \
        "$1/home/etc/certs/remoted.pem" "$1/home/etc/certs/remoted-key.pem" \
        "$1/home/etc/certs/root-ca.pem" | md5sum
}
before="$(state "${root}")"
run_resolver "${root}" --prestart
check "re-running a start is a no-op" "${before}" "$(state "${root}")"
run_resolver "${root}" --upgrade
check "an upgrade exits 0" "0" "${RC}"
check "and changes nothing either" "${before}" "$(state "${root}")"
cleanup "${root}"

# --------------------------------------------------------------------------------------------
# Certificates belong to the install and to no other moment
#
# Issuing one is a signature, not a lookup: re-deriving the chain at every start would make the
# shared CA directory a standing dependency of the manager, which a deployment running on its own
# PKI has no reason to satisfy. So neither a start nor an upgrade may reissue, re-anchor or even
# re-examine what is in etc/certs -- an operator's replacement pair has to survive both untouched,
# and the absence of a CA has to be survivable too.
# --------------------------------------------------------------------------------------------

root="$(make_tree)"
write_credentials "${root}" "WAZUH_INDEXER_MANAGER_PASSWORD='Indexer.Wr0te1'"
run_resolver "${root}" --install

# Stand in for an operator who replaced the issued pair with one from their own PKI and kept no
# copy of its root: a foreign leaf, and the CA directory gone entirely.
openssl req -x509 -nodes -newkey rsa:2048 -sha256 -days 1 \
    -keyout "${root}/home/etc/certs/remoted-key.pem" -out "${root}/home/etc/certs/remoted.pem" \
    -subj "/CN=issued-elsewhere" > /dev/null 2>&1
chown root:root "${root}/home/etc/certs/remoted.pem" "${root}/home/etc/certs/remoted-key.pem"
rm -rf "${root}/base/ca"
foreign="$(md5sum "${root}/home/etc/certs/remoted.pem" | cut -d' ' -f1)"

run_resolver "${root}" --prestart
check "a start with no CA directory at all still succeeds" "0" "${RC}"
check "and leaves the operator's own certificate alone" "${foreign}" \
    "$(md5sum "${root}/home/etc/certs/remoted.pem" | cut -d' ' -f1)"
check "and does not recreate the CA directory" "" "$([ -d "${root}/base/ca" ] && echo exists)"

run_resolver "${root}" --upgrade
check "an upgrade with no CA directory succeeds too" "0" "${RC}"
check "and leaves it alone as well" "${foreign}" \
    "$(md5sum "${root}/home/etc/certs/remoted.pem" | cut -d' ' -f1)"
check "and still does not recreate the CA directory" "" "$([ -d "${root}/base/ca" ] && echo exists)"

# A certificate that is simply gone is not reissued either: that verdict belongs to the
# configuration validator and to remoted's own preflight, which read the files as they are.
rm -f "${root}/home/etc/certs/remoted.pem" "${root}/home/etc/certs/remoted-key.pem"
run_resolver "${root}" --prestart
check "a start does not reissue a missing certificate" "0" "${RC}"
check "and the file stays missing" "" \
    "$([ -f "${root}/home/etc/certs/remoted.pem" ] && echo exists)"
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

# A file the helper can read but not write (here, no final newline) must not end up with a seeded
# rbac.db whose passwords were never published: nothing would read them again, and nobody would
# know them. The start is blocked instead, and fixing the file is enough.
root="$(make_tree)"
printf "WAZUH_INDEXER_MANAGER_PASSWORD='Indexer.Wr0te1'" > "${root}/base/credentials.env"
chmod 0600 "${root}/base/credentials.env"
run_resolver "${root}" --install
check "an install that cannot publish still exits 0" "0" "${RC}"
check "and seeds nothing it could not publish" "" "$(seeded_password "${root}" wazuh)"
run_resolver "${root}" --prestart
check "the start is refused" "1" "${RC}"
echo >> "${root}/base/credentials.env"
run_resolver "${root}" --prestart
check "once the file is fixed the start succeeds" "0" "${RC}"
check "and what was seeded is what was published" "yes" \
    "$([ -n "$(seeded_password "${root}" wazuh)" ] && \
       [ "$(published "${root}" WAZUH_MANAGER_API_PASSWORD)" = "$(seeded_password "${root}" wazuh)" ] && echo yes)"
cleanup "${root}"

# Only the generator's alphabet is accepted. A character outside it is reported as the invalid key
# it is, and never reaches the file or rbac.db: a non-ASCII value would be seeded and then refused
# at every login, and a control character cannot go through the seeding JSON.
for value in "$(printf 'Tab\tInside123')" 'Contraseña1234' 'Seven7ñññññ' 'With Space123' 'Dollar$Sign123'; do
    root="$(make_tree)"
    write_credentials "${root}" "WAZUH_MANAGER_API_PASSWORD='${value}'"
    run_resolver "${root}" --install
    check "a value outside the alphabet is not published" "" \
        "$(published "${root}" WAZUH_MANAGER_API_PASSWORD)"
    run_resolver "${root}" --prestart
    check "a value outside the alphabet is invalid" "yes" \
        "$(grep -q 'INVALID WAZUH_MANAGER_API_PASSWORD' <<< "$(resolver_output)" && echo yes)"
    check "and nothing is seeded" "" "$(seeded_password "${root}" wazuh)"
    cleanup "${root}"
done

root="$(make_tree)"
write_credentials "${root}" "WAZUH_MANAGER_API_PASSWORD='Aa1.,_+:@%^=~-'"
run_resolver "${root}" --install
check "every character of the alphabet is accepted" "Aa1.,_+:@%^=~-" \
    "$(seeded_password "${root}" wazuh)"
cleanup "${root}"

# An empty environment variable must fall through to the file rather than shadow it: an
# orchestrator that passes a key through without a value (compose's bare `- KEY`, a unit's
# EnvironmentFile with a blank assignment) would otherwise turn a credential the file holds into a
# MISSING key, and an owned one into a regenerated password.
root="$(make_tree)"
write_credentials "${root}" "WAZUH_MANAGER_API_PASSWORD='FromFile.Aa1'
WAZUH_INDEXER_MANAGER_PASSWORD='Indexer.Wr0te1'"
WAZUH_BASE_DIR="${root}/base" WAZUH_MANAGER_USER=root WAZUH_MANAGER_GROUP=root \
    WAZUH_MANAGER_API_PASSWORD='' WAZUH_INDEXER_MANAGER_PASSWORD='' \
    "${root}/home/bin/resolve-credentials" --prestart -H "${root}/home" > "${RESOLVER_OUT}" 2>&1
RC=$?
check "an empty environment variable does not shadow the file" "0" "${RC}"
check "the owned key is read from the file, not regenerated" "FromFile.Aa1" "$(seeded_password "${root}" wazuh)"
check "and the consumed key is not reported missing" "" \
    "$(grep -o 'MISSING WAZUH_INDEXER_MANAGER_PASSWORD' <<< "$(resolver_output)" | head -1)"
cleanup "${root}"

# --------------------------------------------------------------------------------------------
# The indexer username
# --------------------------------------------------------------------------------------------

# An operator who stored another account keeps it: only the password comes from the file.
root="$(make_tree)"
printf 'admin' > "${root}/home/queue/keystore/indexer.username"
write_credentials "${root}" "WAZUH_INDEXER_MANAGER_PASSWORD='Indexer.Wr0te1'"
run_resolver "${root}" --install
check "a username already in the keystore is kept" "admin" \
    "$(cat "${root}/home/queue/keystore/indexer.username")"
cleanup "${root}"

# A password stored with no username would leave the indexer connector unable to start.
root="$(make_tree)"
printf 'Indexer.Wr0te1' > "${root}/home/queue/keystore/indexer.password"
run_resolver "${root}" --prestart
check "a stored password with no username gets the manager's account" "wazuh-manager" \
    "$(cat "${root}/home/queue/keystore/indexer.username" 2>/dev/null)"
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
for pair in remoted indexer-connector; do
    check "the ${pair} DN and SANs are logged" "yes" \
        "$(grep -qE "${pair}\.pem: DN .*CN ?= ?[^;]+; SANs .*DNS:" <<< "$(resolver_output)" && echo yes)"
done
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
run_resolver "${root}" --install
check "an anchor-only CA still lets the install exit 0" "0" "${RC}"
check "but the resolver says the certificates are missing" "yes" \
    "$(grep -q "has no TLS certificates and this install could not issue them" \
        <<< "$(resolver_output)" && echo yes)"
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

# The installed tree has <manager-home>/etc at 0770 root:wazuh-manager -- a contract
# manager_base.csv pins and CI enforces, because the service rewrites etc/client.keys and
# etc/shared/ after dropping privileges. An ancestor rule that refuses any group-writable directory
# therefore refuses every standard installation.
root="$(make_tree)"
chmod 0770 "${root}/home/etc"
run_resolver "${root}" --install
check "a parent group-writable by the service's own group is accepted" "0" "${RC}"
check "and the certificates are issued" "yes" \
    "$([ -f "${root}/home/etc/certs/remoted.pem" ] && echo yes)"
cleanup "${root}"

# World-writable is still refused: that is a third party, not the service.
root="$(make_tree)"
chmod 0777 "${root}/home/etc"
run_resolver "${root}" --install
check "a world-writable parent is still refused" "yes" \
    "$(grep -q 'must not be world writable' <<< "$(resolver_output)" && echo yes)"
check "and no certificate is issued into it" "" "$(ls "${root}/home/etc/certs" | grep '^remoted')"
cleanup "${root}"

# Externally-issued certificates: wazuh-certs-tool -- the documented way to provision a distributed
# deployment, and owned by the installation assistant rather than this repo -- emits no
# extendedKeyUsage on its node certificates. RFC 5280 4.2.1.12 makes an absent extension
# unrestricted, so refusing those certificates stopped the manager starting on every node
# provisioned the documented way, and on both CI integration environments.
if command -v openssl > /dev/null 2>&1; then
    root="$(make_tree)"
    write_credentials "${root}" "WAZUH_INDEXER_MANAGER_PASSWORD='Indexer.Wr0te1'"
    run_resolver "${root}" --install
    ca="${root}/base/ca"

    issue_leaf() {
        # $1 destination name, $2 extendedKeyUsage line ('' for no extension at all)
        cat > "${root}/leaf.cnf" <<EOF
[req]
distinguished_name = dn
prompt = no
[dn]
CN = wazuh-manager
[ext]
basicConstraints = CA:FALSE
${2}
subjectAltName = DNS:wazuh-manager
EOF
        openssl req -new -nodes -newkey rsa:2048 -keyout "${root}/leaf.key" \
            -out "${root}/leaf.csr" -config "${root}/leaf.cnf" > /dev/null 2>&1
        openssl x509 -req -in "${root}/leaf.csr" -CA "${ca}/root-ca.pem" -CAkey "${ca}/root-ca.key" \
            -CAcreateserial -out "${root}/leaf.pem" -days 2 -sha256 \
            -extensions ext -extfile "${root}/leaf.cnf" > /dev/null 2>&1
        install -m 0640 "${root}/leaf.pem" "${root}/home/etc/certs/$1.pem"
        install -m 0640 "${root}/leaf.key" "${root}/home/etc/certs/$1-key.pem"
    }

    issue_leaf indexer-connector ""
    check "the fixture really carries no extendedKeyUsage" "" \
        "$(openssl x509 -in "${root}/home/etc/certs/indexer-connector.pem" -noout \
            -ext extendedKeyUsage 2>/dev/null | grep -c 'Authentication' | grep -v '^0$')"
    # A reinstall over a tree whose pairs were staged beforehand: install is the one moment that
    # examines them, so it is the one moment this rule can fire.
    run_resolver "${root}" --install
    check "a connector leaf with no extendedKeyUsage is accepted" "" \
        "$(grep -q 'extended key usage' <<< "$(resolver_output)" && echo complained)"

    issue_leaf indexer-connector "extendedKeyUsage = serverAuth"
    run_resolver "${root}" --install
    check "but one declaring serverAuth only is refused" "yes" \
        "$(grep -q 'is not usable for clientAuth' <<< "$(resolver_output)" && echo yes)"
    check "and the diagnostic blames the purpose, not the chain" "" \
        "$(grep -q 'not signed by' <<< "$(resolver_output)" && echo chain)"
    cleanup "${root}"
fi

# The listener pair belongs to the service user, because remoted and authd open it after dropping
# privileges. The install checks that; nothing after it does, so a key that becomes unreadable
# later is caught by remoted's own access(R_OK) preflight instead -- which is what
# tests/integration/.../test_https_cert_unreadable asserts, on remoted's line in the manager log.
root="$(make_tree)"
write_credentials "${root}" "WAZUH_INDEXER_MANAGER_PASSWORD='Indexer.Wr0te1'"
run_resolver "${root}" --install
check "a healthy tree resolves" "0" "${RC}"

# root:root 0600 is the mutation the integration fixture applies. The suite's service identity is
# root, so drop the group instead: what matters is that the pair no longer matches the expected
# ownership the helper enforces.
chown root:0 "${root}/home/etc/certs/remoted-key.pem" 2>/dev/null
chmod 0600 "${root}/home/etc/certs/remoted-key.pem"
run_resolver "${root}" --install
check "a reinstall names a listener key the service cannot read" "yes" \
    "$(grep -qE 'remoted-key\.pem (must have mode|.*unexpected owner)|unexpected owner for .*remoted-key\.pem' \
        <<< "$(resolver_output)" && echo yes)"
run_resolver "${root}" --prestart
check "but a start does not re-examine it" "0" "${RC}"
cleanup "${root}"

# Certificates staged without their anchor. At install the helper refuses to mint a CA when manager
# material already exists -- minting a second root beside certificates issued from a first is how a
# host ends up with two trust roots and nothing detecting it. Starting, though, is unaffected: this
# is exactly the shape of a node provisioned from someone else's PKI, and it must come up.
root="$(make_tree)"
write_credentials "${root}" "WAZUH_INDEXER_MANAGER_PASSWORD='Indexer.Wr0te1'"
run_resolver "${root}" --install          # mints a CA and both pairs
check "a first install resolves" "0" "${RC}"

# Keep the pairs, take the CA away -- pairs present, anchor absent.
rm -rf "${root}/base/ca"
run_resolver "${root}" --install
check "a reinstall will not mint a second CA beside them" "yes" \
    "$(grep -q 'refusing to mint another CA' <<< "$(resolver_output)" && echo yes)"
check "and mints nothing" "" "$([ -d "${root}/base/ca" ] && echo exists)"
run_resolver "${root}" --prestart
check "while the start is unaffected" "0" "${RC}"
cleanup "${root}"

# --------------------------------------------------------------------------------------------
# --clear
#
# For an image built by installing the package: its postinst resolved, so the image layer carries
# one rbac.db, one CA private key and one certificate set that every container would share.
# --------------------------------------------------------------------------------------------

root="$(make_tree)"
write_credentials "${root}" "WAZUH_INDEXER_MANAGER_PASSWORD='Indexer.Wr0te1'"
run_resolver "${root}" --install
baked="$(seeded_password "${root}" wazuh)"
baked_ca="$(openssl x509 -in "${root}/base/ca/root-ca.pem" -noout -fingerprint 2>/dev/null)"

run_resolver "${root}" --clear
check "--clear exits 0" "0" "${RC}"
check "it removes rbac.db" "" "$(ls "${root}/home/api/configuration/security" | grep '^rbac.db$')"
check "it clears the keystore" "0" "$(ls "${root}/home/queue/keystore" 2>/dev/null | wc -l)"
check "it removes every certificate" "0" "$(ls "${root}/home/etc/certs" | wc -l)"
check "it removes the bootstrap CA, private key included" "0" "$(ls "${root}/base/ca" 2>/dev/null | wc -l)"
check "it removes the manager's published keys" "" "$(published "${root}" WAZUH_MANAGER_API_PASSWORD)"
check "but leaves a key it does not own" "1" \
    "$(grep -c "^WAZUH_INDEXER_MANAGER_PASSWORD=" "${root}/base/credentials.env")"

# The point of clearing: what comes next must not reproduce what the image carried. --clear wipes
# and --install resolves; they are a pair, because certificates are only ever issued at install.
run_resolver "${root}" --install
check "a following install resolves again" "0" "${RC}"
check "and the password differs from the baked one" "differ" \
    "$([ "$(seeded_password "${root}" wazuh)" != "${baked}" ] && echo differ)"
check "and so does the CA" "differ" \
    "$([ "$(openssl x509 -in "${root}/base/ca/root-ca.pem" -noout -fingerprint 2>/dev/null)" != "${baked_ca}" ] && echo differ)"
check "the reissued pair verifies against the new CA" "yes" \
    "$(openssl verify -CAfile "${root}/base/ca/root-ca.pem" \
        "${root}/home/etc/certs/remoted.pem" > /dev/null 2>&1 && echo yes)"
cleanup "${root}"

# It is the one destructive path in the tool, so it refuses on a live manager rather than leaving
# a running deployment without the credentials it is using.
root="$(make_tree)"
run_resolver "${root}" --install
mkdir -p "${root}/home/var/run"
sleep 120 &
live_pid=$!
echo "${live_pid}" > "${root}/home/var/run/wazuh-manager-analysisd-${live_pid}.pid"
run_resolver "${root}" --clear
check "--clear refuses while the manager is running" "1" "${RC}"
check "and says so" "yes" \
    "$(grep -q 'refusing to clear credentials while the manager is running' <<< "$(resolver_output)" && echo yes)"
check "leaving rbac.db in place" "yes" \
    "$([ -f "${root}/home/api/configuration/security/rbac.db" ] && echo yes)"
kill "${live_pid}" 2>/dev/null
wait "${live_pid}" 2>/dev/null

# A stale pidfile from an unclean stop is not a running manager.
rm -f "${root}/home/var/run/"*.pid
echo "999999" > "${root}/home/var/run/wazuh-manager-analysisd-999999.pid"
run_resolver "${root}" --clear
check "a stale pidfile does not block it" "0" "${RC}"
cleanup "${root}"

# A CA this host did not mint is kept, private key or not. An operator who stages a signing CA --
# their own anchor AND key, so the manager issues leaves from their PKI -- leaves exactly the shape
# a minted one has, so "root-ca.key is present" cannot be the evidence; only the marker the install
# wrote may authorise deleting a private key.
root="$(make_tree)"
mkdir -p "${root}/base/ca"
chmod 0700 "${root}/base/ca"
openssl req -x509 -nodes -newkey rsa:2048 -sha256 -days 1 \
    -keyout "${root}/base/ca/root-ca.key" -out "${root}/base/ca/root-ca.pem" \
    -subj "/CN=Operator signing CA" > /dev/null 2>&1
chmod 0644 "${root}/base/ca/root-ca.pem"; chmod 0400 "${root}/base/ca/root-ca.key"
staged_ca="$(md5sum < "${root}/base/ca/root-ca.key")"
run_resolver "${root}" --install
run_resolver "${root}" --clear
check "--clear keeps a signing CA this host did not mint" "${staged_ca}" \
    "$(md5sum < "${root}/base/ca/root-ca.key" 2>/dev/null)"
check "and says why" "yes" \
    "$(grep -q 'this host did not mint it' <<< "$(resolver_output)" && echo yes)"
cleanup "${root}"

# A credentials file that cannot be written must not be reported as cleared: the published
# passwords are still in it, and an image cleared on that promise would ship them.
root="$(make_tree)"
run_resolver "${root}" --install
chmod 0644 "${root}/base/credentials.env"
run_resolver "${root}" --clear
check "--clear fails when it cannot unpublish" "1" "${RC}"
check "and says the keys are still published" "yes" \
    "$(grep -q 'they are still published' <<< "$(resolver_output)" && echo yes)"
cleanup "${root}"

# A CA directory holding only an anchor was issued elsewhere and handed to this host: destroying it
# would take a corporate or cert-manager trust root with it.
root="$(make_tree)"
mkdir -p "${root}/base/ca"
chmod 0700 "${root}/base/ca"
openssl req -x509 -nodes -newkey rsa:2048 -sha256 -days 1 \
    -keyout "${root}/external.key" -out "${root}/base/ca/root-ca.pem" \
    -subj "/CN=Corporate PKI" > /dev/null 2>&1
chmod 0644 "${root}/base/ca/root-ca.pem"
external_ca="$(md5sum < "${root}/base/ca/root-ca.pem")"
run_resolver "${root}" --clear
check "--clear keeps an externally-issued trust anchor" "${external_ca}" \
    "$(md5sum < "${root}/base/ca/root-ca.pem")"
check "and says why" "yes" \
    "$(grep -q 'it carries no private key, so it was issued elsewhere' <<< "$(resolver_output)" && echo yes)"
cleanup "${root}"

# --------------------------------------------------------------------------------------------

echo ""
echo "${checks} checks, ${failures} failure(s)"
[ "${failures}" -eq 0 ] || exit 1
exit 0
