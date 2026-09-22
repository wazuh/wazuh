#!/bin/bash

# Copyright (C) 2015, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Drives src/init/credentials/ against a throwaway tree: the resolution ladder, the credentials
# file format and its locking, the password policy, and the four certificate cases.
#
# Black-box where it can be. The keystore and rbac_control are stub binaries, so every case runs
# without a build; openssl is real, so the certificates the cases produce are actually verified
# against the CA that signed them.
#
# CRED_DIR and CRED_TRUST_ROOT point the library at the throwaway tree. Nothing that ships sets
# either -- a real run resolves /etc/wazuh/credentials.env and validates its ancestry from / down --
# but without them every case here would be refused for /tmp's own 1777.
#
#   ./test_resolve_credentials.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRED_SRC="${SCRIPT_DIR}/../credentials"

failures=0
checks=0

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
# JSON it was given on stdin and creates rbac.db), real mint-certs.sh. Echoes the root.
make_tree() {

    local root
    root="$(mktemp -d)"

    mkdir -p "${root}/etc/wazuh" "${root}/home/bin" "${root}/home/lib" \
             "${root}/home/api/configuration/security" "${root}/home/etc/certs" "${root}/store"

    cp "${CRED_SRC}/credentials-lib.sh" "${root}/home/lib/"
    cp "${CRED_SRC}/resolve-credentials" "${root}/home/bin/"
    cp "${CRED_SRC}/mint-certs.sh" "${root}/home/bin/wazuh-manager-mint-certs"
    chmod +x "${root}/home/bin/resolve-credentials" "${root}/home/bin/wazuh-manager-mint-certs"

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
RESOLVER_OUT="$(mktemp)"
trap 'rm -f "${RESOLVER_OUT}"' EXIT

run_resolver() {

    local root="$1"; shift

    CRED_DIR="${root}/etc/wazuh" CRED_TRUST_ROOT="${root}" \
        "${root}/home/bin/resolve-credentials" "$@" -H "${root}/home" > "${RESOLVER_OUT}" 2>&1
    RC=$?

}

resolver_output() {

    cat "${RESOLVER_OUT}"

}

seeded_password() {

    sed -n "s/.*\"$2\": \"\([^\"]*\)\".*/\1/p" "$1/home/api/configuration/security/seeded.json" 2>/dev/null

}

# A value the manager published, with the file's one escape ('\'') undone.
#
# Scoped to the managed block on purpose: a key the operator wrote outside it may carry the same
# name, and reading that back would make "the manager published nothing" indistinguishable from
# "the manager published what the operator already had there".
published() {

    awk -v key="$2" '
        /^# >>> wazuh generated/ { inblock = 1; next }
        /^# >>> end wazuh generated/ { inblock = 0; next }
        inblock && index($0, key "=") == 1 { print substr($0, length(key) + 2) }
    ' "$1/etc/wazuh/credentials.env" 2>/dev/null | sed -e "s/^'//" -e "s/'$//" -e "s/'\\\\''/'/g"

}

write_credentials() {

    printf '%s\n' "$2" > "$1/etc/wazuh/credentials.env"
    chmod 0600 "$1/etc/wazuh/credentials.env"

}

# --------------------------------------------------------------------------------------------
# The ladder
# --------------------------------------------------------------------------------------------

# A clean host resolves everything it owns and nothing it merely consumes, and says nothing about
# the difference: the installer has no opinion about whether the manager can run.
root="$(make_tree)"
run_resolver "${root}" --install > /dev/null
check "a clean install exits 0" "0" "${RC}"
check "the two API passwords are seeded" "yes" \
    "$([ -n "$(seeded_password "${root}" wazuh)" ] && [ -n "$(seeded_password "${root}" wazuh-wui)" ] && echo yes)"
check "both are published to the credentials file" "yes" \
    "$([ "$(published "${root}" WAZUH_MANAGER_API_PASSWORD)" = "$(seeded_password "${root}" wazuh)" ] && \
       [ "$(published "${root}" WAZUH_MANAGER_WUI_PASSWORD)" = "$(seeded_password "${root}" wazuh-wui)" ] && echo yes)"
check "the consumed indexer key is never published" "" \
    "$(published "${root}" WAZUH_INDEXER_MANAGER_PASSWORD)"
check "the credentials file is 0600" "600" "$(stat -c '%a' "${root}/etc/wazuh/credentials.env")"

# Start on that same host: the one credential the manager cannot invent is missing, and it is named.
run_resolver "${root}" --prestart
check "a start with no indexer credential fails" "1" "${RC}"
check "and names the missing key" "yes" \
    "$(grep -q 'MISSING WAZUH_INDEXER_MANAGER_PASSWORD' <<< "$(resolver_output)" && echo yes)"

# The indexer publishes its key; the manager picks it up at start with no reinstall or repair.
printf "WAZUH_INDEXER_MANAGER_PASSWORD='Indexer.Wr0te1'\n" >> "${root}/etc/wazuh/credentials.env"
run_resolver "${root}" --prestart > /dev/null
check "the next start succeeds once the key is there" "0" "${RC}"
check "and the credential is in the manager's own store" "Indexer.Wr0te1" \
    "$(cat "${root}/store/indexer.password")"

# Re-running changes nothing: an upgrade takes step 0 for everything.
before="$(md5sum "${root}/etc/wazuh/credentials.env" "${root}/store/indexer.password")"
run_resolver "${root}" --prestart > /dev/null
check "re-running is a no-op" "${before}" \
    "$(md5sum "${root}/etc/wazuh/credentials.env" "${root}/store/indexer.password")"
rm -rf "${root}"

# Two independent installations must never share a credential.
root="$(make_tree)";  run_resolver "${root}" --install > /dev/null
root2="$(make_tree)"; run_resolver "${root2}" --install > /dev/null
check "two clean installs generate different passwords" "differ" \
    "$([ "$(seeded_password "${root}" wazuh)" != "$(seeded_password "${root2}" wazuh)" ] && echo differ)"
check "generated passwords are 32 characters" "32" "$(printf '%s' "$(seeded_password "${root}" wazuh)" | wc -c)"
rm -rf "${root}" "${root2}"

# --------------------------------------------------------------------------------------------
# Where a value comes from
# --------------------------------------------------------------------------------------------

root="$(make_tree)"
write_credentials "${root}" "WAZUH_MANAGER_API_PASSWORD='Supplied.Api1'"
run_resolver "${root}" --install > /dev/null
check "a supplied value is what gets seeded" "Supplied.Api1" "$(seeded_password "${root}" wazuh)"
check "and the user with no supplied value still gets one" "yes" \
    "$([ -n "$(seeded_password "${root}" wazuh-wui)" ] && echo yes)"
rm -rf "${root}"

root="$(make_tree)"
write_credentials "${root}" "WAZUH_MANAGER_API_PASSWORD='FromFile.Aa1'"
CRED_DIR="${root}/etc/wazuh" CRED_TRUST_ROOT="${root}" WAZUH_MANAGER_API_PASSWORD='FromEnvir.Aa1' \
    "${root}/home/bin/resolve-credentials" --install -H "${root}/home" > /dev/null 2>&1
check "the environment overrides the file" "FromEnvir.Aa1" "$(seeded_password "${root}" wazuh)"
rm -rf "${root}"

# Step 0 wins over both channels: a value edited into the file after seeding changes nothing.
root="$(make_tree)"
run_resolver "${root}" --install > /dev/null
seeded="$(seeded_password "${root}" wazuh)"
write_credentials "${root}" "WAZUH_MANAGER_API_PASSWORD='Edited.Later1'
WAZUH_INDEXER_MANAGER_PASSWORD='Indexer.Wr0te1'"
run_resolver "${root}" --prestart > /dev/null
check "editing the file does not reseed an existing database" "${seeded}" "$(seeded_password "${root}" wazuh)"
rm -rf "${root}"

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
rm -rf "${root}"

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
rm -rf "${root}"

# Each class of the policy, independently.
root="$(make_tree)"
export CRED_DIR="${root}/etc/wazuh"
. "${CRED_SRC}/credentials-lib.sh"
for case in "shortA1." "alllowercase1." "ALLUPPERCASE1." "NoDigitsAtAll." "NoSymbolsHere123"; do
    cred_validate_password KEY "${case}" 2> /dev/null
    check "the policy rejects '${case}'" "1" "$?"
done
cred_validate_password KEY "Perfectly.Fine1" 2> /dev/null
check "and accepts a compliant value" "0" "$?"

# What is generated must pass what is enforced, every time rather than most times.
generated_ok="yes"
for _ in $(seq 1 50); do
    pw="$(cred_generate_password)"
    cred_validate_password GEN "${pw}" 2> /dev/null || generated_ok="no"
    [ "${#pw}" -eq 32 ] || generated_ok="no"
done
check "every generated password satisfies the policy" "yes" "${generated_ok}"
rm -rf "${root}"

# --------------------------------------------------------------------------------------------
# The credentials file
# --------------------------------------------------------------------------------------------

root="$(make_tree)"
write_credentials "${root}" "# an operator comment
WAZUH_MANAGER_API_PASSWORD='OperatorOwns.1'
WAZUH_INDEXER_ADMIN_PASSWORD='Sibling.Key1a'"
run_resolver "${root}" --install > /dev/null
check "lines outside the managed block are left untouched" "yes" \
    "$(grep -qx "WAZUH_MANAGER_API_PASSWORD='OperatorOwns.1'" "${root}/etc/wazuh/credentials.env" && \
       grep -qx '# an operator comment' "${root}/etc/wazuh/credentials.env" && echo yes)"
check "even when they carry a key the manager owns" "1" \
    "$(awk '/^# >>> wazuh generated/{b=1;next} /^# >>> end/{b=0} b&&/^WAZUH_MANAGER_API_PASSWORD=/{n++} END{print n+0}' \
        "${root}/etc/wazuh/credentials.env")"

# Purge takes this component's keys and nothing else.
( export CRED_DIR="${root}/etc/wazuh"
  . "${root}/home/lib/credentials-lib.sh"
  cred_purge_prefix WAZUH_MANAGER_ )
check "a purge leaves the sibling's key" "yes" \
    "$(grep -q "WAZUH_INDEXER_ADMIN_PASSWORD='Sibling.Key1a'" "${root}/etc/wazuh/credentials.env" && echo yes)"
check "a purge leaves the operator's line" "yes" \
    "$(grep -qx "WAZUH_MANAGER_API_PASSWORD='OperatorOwns.1'" "${root}/etc/wazuh/credentials.env" && echo yes)"
check "a purge removes the generated keys" "0" \
    "$(awk '/^# >>> wazuh generated/{b=1;next} /^# >>> end/{b=0} b&&/^WAZUH_MANAGER_/{n++} END{print n+0}' \
        "${root}/etc/wazuh/credentials.env")"
rm -rf "${root}"

# A file anyone else can read is refused outright rather than repaired: it is either a mistake or
# an attack, and fixing it silently hides both.
root="$(make_tree)"
printf "WAZUH_MANAGER_API_PASSWORD='Supplied.Api1'\n" > "${root}/etc/wazuh/credentials.env"
chmod 0644 "${root}/etc/wazuh/credentials.env"
run_resolver "${root}" --prestart
check "a group-readable credentials file is refused" "1" "${RC}"
check "and the reason is logged" "yes" \
    "$(grep -q 'group- or world-accessible' <<< "$(resolver_output)" && echo yes)"
rm -rf "${root}"

root="$(make_tree)"
mkdir -p "${root}/elsewhere"
printf "WAZUH_MANAGER_API_PASSWORD='Supplied.Api1'\n" > "${root}/elsewhere/real.env"
chmod 0600 "${root}/elsewhere/real.env"
ln -s "${root}/elsewhere/real.env" "${root}/etc/wazuh/credentials.env"
run_resolver "${root}" --prestart
check "a symlinked credentials file is refused" "1" "${RC}"
check "and says it is a symlink" "yes" \
    "$(grep -q 'symlink' <<< "$(resolver_output)" && echo yes)"
rm -rf "${root}"

# systemd starts units in parallel, so three pre-start steps can reach one file at once. Without
# the lock, generated values are lost silently at boot.
root="$(make_tree)"
mkdir -p "${root}/etc/wazuh"
(
    # Exported before sourcing on purpose: the library derives CRED_FILE and CRED_LOCK from
    # CRED_DIR when it is sourced, so setting it afterwards -- or as a command prefix -- would
    # leave both pointing at the real /etc/wazuh.
    export CRED_DIR="${root}/etc/wazuh"
    . "${root}/home/lib/credentials-lib.sh"
    for i in $(seq 1 16); do
        ( cred_publish "WAZUH_CONCURRENT_${i}" "Value.Number${i}a" > /dev/null ) &
    done
    wait
)
check "concurrent writers lose no key" "16" \
    "$(grep -c '^WAZUH_CONCURRENT_' "${root}/etc/wazuh/credentials.env")"
check "and produce exactly one managed block" "1" \
    "$(grep -c '>>> wazuh generated' "${root}/etc/wazuh/credentials.env")"
rm -rf "${root}"

# The file is parsed, never sourced: a command in it is a value, not something that runs.
root="$(make_tree)"
write_credentials "${root}" "WAZUH_MANAGER_API_PASSWORD='Valid.Value1a'
touch ${root}/PWNED"
run_resolver "${root}" --install > /dev/null
check "the credentials file is never sourced" "no" \
    "$([ -e "${root}/PWNED" ] && echo yes || echo no)"
rm -rf "${root}"

# --------------------------------------------------------------------------------------------
# Certificates
# --------------------------------------------------------------------------------------------

if command -v openssl > /dev/null 2>&1; then

    # Case A: nothing staged. A bootstrap CA is minted and both pairs are issued from it.
    root="$(make_tree)"
    run_resolver "${root}" --install > /dev/null
    check "case A mints a CA" "yes" "$([ -f "${root}/etc/wazuh/ca/root-ca.pem" ] && echo yes)"
    for pair in remoted indexer-connector; do
        check "case A issues ${pair}, verified against that CA" "yes" \
            "$(openssl verify -CAfile "${root}/etc/wazuh/ca/root-ca.pem" \
                "${root}/home/etc/certs/${pair}.pem" > /dev/null 2>&1 && echo yes)"
    done
    check "and installs the anchor for the manager to read" "yes" \
        "$([ -f "${root}/home/etc/certs/root-ca.pem" ] && echo yes)"
    check "the CA private key is 0400" "400" "$(stat -c '%a' "${root}/etc/wazuh/ca/root-ca.key")"

    # Case B: a second component on the same host finds the CA and issues from it.
    ca_before="$(md5sum < "${root}/etc/wazuh/ca/root-ca.pem")"
    rm -f "${root}/home/etc/certs/"*.pem
    run_resolver "${root}" --install > /dev/null
    check "case B reuses the CA rather than minting another" "${ca_before}" \
        "$(md5sum < "${root}/etc/wazuh/ca/root-ca.pem")"
    check "case B issues from the CA it found" "yes" \
        "$(openssl verify -CAfile "${root}/etc/wazuh/ca/root-ca.pem" \
            "${root}/home/etc/certs/remoted.pem" > /dev/null 2>&1 && echo yes)"

    # Case C: a pre-issued pair is left alone. Placing one is how an operator supplies it, which is
    # why there is no key for it.
    mkdir -p "${root}/home/etc/certs"
    for f in remoted remoted-key indexer-connector indexer-connector-key; do
        printf 'pre-issued %s\n' "${f}" > "${root}/home/etc/certs/${f}.pem"
    done
    run_resolver "${root}" --prestart > /dev/null
    check "case C leaves a pre-issued pair untouched" "pre-issued remoted" \
        "$(cat "${root}/home/etc/certs/remoted.pem")"
    rm -rf "${root}"

    # Case D: an anchor with no private key. This host cannot sign and must not pretend to.
    root="$(make_tree)"
    mkdir -p "${root}/etc/wazuh/ca"
    openssl req -x509 -nodes -newkey rsa:2048 -sha256 -days 1 \
        -keyout "${root}/other-ca.key" -out "${root}/etc/wazuh/ca/root-ca.pem" \
        -subj "/CN=Somebody else's CA" > /dev/null 2>&1
    run_resolver "${root}" --prestart
    check "case D leaves the certificates unresolved" "1" "${RC}"
    check "and says why" "yes" \
        "$(grep -q 'MISSING the manager' <<< "$(resolver_output)" && echo yes)"
    check "case D still installs the anchor" "yes" \
        "$([ -f "${root}/home/etc/certs/root-ca.pem" ] && echo yes)"
    check "case D leaves no CA private key on the host" "" \
        "$(ls "${root}/etc/wazuh/ca/" | grep 'root-ca.key')"
    check "and issues nothing" "" "$(ls "${root}/home/etc/certs/" | grep '^remoted')"
    rm -rf "${root}"

    # The SAN key replaces the derived set, and loopback is always appended.
    root="$(make_tree)"
    write_credentials "${root}" "WAZUH_MANAGER_CERT_SANS='DNS:wazuh.corp.local,IP:10.0.1.11'"
    run_resolver "${root}" --install > /dev/null
    sans="$(openssl x509 -in "${root}/home/etc/certs/remoted.pem" -noout -text | grep -A1 'Alternative Name' | tail -1)"
    check "the SAN key replaces the derived names" "yes" \
        "$(grep -q 'wazuh.corp.local' <<< "${sans}" && ! grep -q "$(hostname)" <<< "${sans}" && echo yes)"
    check "loopback is always appended" "yes" \
        "$(grep -q '127.0.0.1' <<< "${sans}" && echo yes)"
    rm -rf "${root}"

    # A wildcard under a shared CA lets a node present a certificate for any other node.
    root="$(make_tree)"
    write_credentials "${root}" "WAZUH_MANAGER_CERT_SANS='DNS:*.wazuh.indexer'"
    run_resolver "${root}" --prestart > /dev/null
    check "a wildcard SAN is refused" "1" "${RC}"
    check "and no CA is left behind for the next run to adopt" "" \
        "$(ls "${root}/etc/wazuh/ca" 2>/dev/null)"
    rm -rf "${root}"

else
    echo "skip - certificate cases (openssl is not available)"
fi

# --------------------------------------------------------------------------------------------

echo ""
echo "${checks} checks, ${failures} failure(s)"
[ "${failures}" -eq 0 ] || exit 1
exit 0
