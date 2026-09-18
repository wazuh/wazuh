#!/bin/sh
# manager_certs_cli_test.sh — end-to-end checks of bin/wazuh-manager-certs that main.cpp owns and
# runInspect()/runCheck() (manager_certs/commands.hpp) never see, because those two are pure
# functions over an already-parsed bundle: --version/--help with no configuration present at all
# (RF-10, CA-21), the three "environment" exit-2 paths (an unreadable -f, a missing CA bundle, a
# missing leaf), and — the part only the compiled binary can prove — that `inspect`/`check` against
# a REAL, CA-signed bundle on disk actually succeed, that `check` actually rejects a broken one, and
# that neither ever touches the bundle file it read (main.cpp is the only thing in this tool that
# opens a file at all; the GTest suite calls runCheck()/runInspect() directly and so can never see a
# regression in main.cpp itself — review of 4ba63dda7e, objections #7/#8/#9).
#
# Runs from ctest as `manager_certs_cli`, outside the ASAN job (which selects only the
# `manager_certs_utest` GTest label, since it never builds this binary with ASAN).
#
# Usage: manager_certs_cli_test.sh <wazuh-manager-certs> <expected-version>

set -u

CLI="${1:-}"
if [ ! -x "$CLI" ]; then
    echo "usage: $0 <wazuh-manager-certs> <expected-version>" >&2
    exit 2
fi

EXPECTED_VERSION="${2:-}"
if [ -z "$EXPECTED_VERSION" ]; then
    echo "usage: $0 <wazuh-manager-certs> <expected-version>" >&2
    exit 2
fi

TMP=$(mktemp -d) || exit 2
trap 'rm -rf "$TMP"' EXIT INT TERM

TOTAL=0
FAILS=0
pass() { TOTAL=$((TOTAL + 1)); echo "  ok   $1"; }
fail() { TOTAL=$((TOTAL + 1)); FAILS=$((FAILS + 1)); echo "  FAIL $1: $2" >&2; }

# run <cmd...>: captures stdout/stderr in $TMP/out and $TMP/err, prints the exit code.
run() {
    "$@" > "$TMP/out" 2> "$TMP/err"
    echo $?
}

# require <cmd...>: fixture setup only — a failure here means the test environment is broken, not
# that wazuh-manager-certs failed, so it aborts the whole script rather than reporting a false FAIL.
require() {
    if ! "$@" > "$TMP/setup.log" 2>&1; then
        echo "fixture setup failed: $* (see $TMP/setup.log)" >&2
        cat "$TMP/setup.log" >&2
        exit 2
    fi
}

# ---------------------------------------------------------------------------------- real PKI ---
# A genuine, CA-signed leaf (issuer != subject — a self-signed fixture would let `inspect` print
# the subject where the issuer belongs and still pass) and a bundle sealed the exact shape
# ca_bundle::renderBlock() + ca_bundle::serializeCertificates() write
# (src/shared_modules/ca_bundle/src/ca_bundle.cpp): only fixtures this real can tell the CLI
# actually validating something from a no-op that always says yes.
PKI="$TMP/pki"
mkdir -p "$PKI"

require openssl ecparam -name prime256v1 -genkey -noout -out "$PKI/ca-key.pem"
require openssl req -new -x509 -key "$PKI/ca-key.pem" -days 400 -sha256 \
    -subj "/CN=manager-certs-cli-test-ca" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out "$PKI/ca-cert.pem"

require openssl ecparam -name prime256v1 -genkey -noout -out "$PKI/leaf-key.pem"
require openssl req -new -key "$PKI/leaf-key.pem" -subj "/CN=manager-certs-cli-test-leaf" -out "$PKI/leaf.csr"
require openssl x509 -req -in "$PKI/leaf.csr" -CA "$PKI/ca-cert.pem" -CAkey "$PKI/ca-key.pem" \
    -CAcreateserial -days 90 -sha256 -out "$PKI/leaf-cert.pem"

CONTENT_SHA256=$(openssl x509 -in "$PKI/ca-cert.pem" -outform DER | sha256sum | awk '{print $1}')
if [ -z "$CONTENT_SHA256" ]; then
    echo "could not hash the test CA's DER encoding" >&2
    exit 2
fi
WRONG_SHA256=$(printf '0%.0s' $(seq 1 64))

# $1 = output path, $2 = publication timestamp, $3 = Content-SHA256, $4 = certificate PEM file.
write_sealed_bundle() {
    cat > "$1" << SEALED
##
## Wazuh CA bundle
##
## Publication: $2
## Content-SHA256: $3
## Updated: $(date -u +%Y-%m-%dT%H:%M:%SZ)
## Written by: manager_certs_cli_test
##
$(cat "$4")
SEALED
}

VALID_BUNDLE="$PKI/valid-bundle.pem"
write_sealed_bundle "$VALID_BUNDLE" "$(date +%s)" "$CONTENT_SHA256" "$PKI/ca-cert.pem"

# Sealed with a hash that does not describe the certificate next to it: vouch()'s hash_mismatch
# guard, the one guard every other fixture below never exercises.
REJECTED_BUNDLE="$PKI/rejected-bundle.pem"
write_sealed_bundle "$REJECTED_BUNDLE" "$(date +%s)" "$WRONG_SHA256" "$PKI/ca-cert.pem"

# $1 = config path, $2 = certificate, $3 = ca_certificate. <key> is never opened by this tool
# (checkFiles=false), so it does not need to exist.
write_config() {
    cat > "$1" << CONF
<wazuh_config>
  <remote>
    <https>
      <certificate>$2</certificate>
      <key>$PKI/leaf-key.pem</key>
      <ca_certificate>$3</ca_certificate>
    </https>
  </remote>
  <cluster>
    <key>0123456789abcdef0123456789abcdef</key>
  </cluster>
  <indexer>
    <hosts>
      <host>https://127.0.0.1:9200</host>
    </hosts>
  </indexer>
</wazuh_config>
CONF
}

CONFIG_VALID="$PKI/config-valid.conf"
write_config "$CONFIG_VALID" "$PKI/leaf-cert.pem" "$VALID_BUNDLE"

CONFIG_REJECTED="$PKI/config-rejected.conf"
write_config "$CONFIG_REJECTED" "$PKI/leaf-cert.pem" "$REJECTED_BUNDLE"

# --------------------------------------------------------------- --version / --help, no config ---
# Unset so the two flags cannot accidentally see a real manager's configuration through the
# environment: they have to short-circuit before resolveHome() is ever called (RF-10), same as
# `wazuh-manager-conf`'s own -h/-V.
unset WAZUH_MANAGER_HOME

rc=$(run "$CLI" --version)
actual_version_line=$(cat "$TMP/out")
# The FULL line, not just the "wazuh-manager-certs " prefix: that prefix alone is satisfied by
# "unknown" (the macro's own fallback when WAZUH_MANAGER_CERTS_VERSION is undefined) or by any
# other wrong version string (objection #12).
if [ "$rc" = 0 ] && [ "$actual_version_line" = "wazuh-manager-certs $EXPECTED_VERSION" ]; then
    pass cli_version_prints_product_version
else
    fail cli_version_prints_product_version \
        "exit $rc; out='$actual_version_line' err='$(cat "$TMP/err")' expected='wazuh-manager-certs $EXPECTED_VERSION'"
fi

rc=$(run "$CLI" --help)
if [ "$rc" = 0 ] && grep -q '^Usage: wazuh-manager-certs' "$TMP/out" \
    && grep -q 'inspect' "$TMP/out" && grep -q 'check' "$TMP/out" \
    && grep -q -- '--version' "$TMP/out" && grep -q -- '--help' "$TMP/out"; then
    pass cli_help_prints_usage
else
    fail cli_help_prints_usage "exit $rc; out='$(cat "$TMP/out")'"
fi

# ------------------------------------------------------------------------- environment (exit 2) ---
rc=$(run "$CLI" -f "$TMP/does-not-exist.conf" inspect)
if [ "$rc" = 2 ] && grep -q "does-not-exist.conf" "$TMP/err"; then
    pass cli_unreadable_config_exits_two
else
    fail cli_unreadable_config_exits_two "exit $rc; err='$(cat "$TMP/err")'"
fi

# A minimal, schema-valid configuration (cluster.key + indexer.hosts are the two fields with no
# usable default -- manager_config/tests/vectors/valid/minimal-valid.conf's own comment) with a
# REAL leaf (so a leaf-reading bug could not accidentally satisfy this test too — objection #9) and
# a CA bundle path that does not exist. main.cpp reads the bundle before the leaf, so this fails on
# the bundle regardless of the leaf's own content, and the diagnostic has to name the bundle's own
# missing path, not just any exit-2 cause.
CONFIG_NO_BUNDLE="$TMP/config-no-bundle.conf"
write_config "$CONFIG_NO_BUNDLE" "$PKI/leaf-cert.pem" "$TMP/no-such-bundle.pem"

rc=$(run "$CLI" -f "$CONFIG_NO_BUNDLE" inspect)
if [ "$rc" = 2 ] && grep -q "no-such-bundle.pem" "$TMP/err"; then
    pass cli_missing_bundle_exits_two
else
    fail cli_missing_bundle_exits_two "exit $rc; err='$(cat "$TMP/err")'"
fi

# Mirror: a REAL, well-formed bundle (so a bundle-reading bug could not accidentally satisfy this
# test too — objection #9) and a leaf that does not exist; the diagnostic has to name the leaf's
# own missing path.
CONFIG_NO_LEAF="$TMP/config-no-leaf.conf"
write_config "$CONFIG_NO_LEAF" "$TMP/no-such-leaf.pem" "$VALID_BUNDLE"

rc=$(run "$CLI" -f "$CONFIG_NO_LEAF" inspect)
if [ "$rc" = 2 ] && grep -q "no-such-leaf.pem" "$TMP/err"; then
    pass cli_missing_leaf_exits_two
else
    fail cli_missing_leaf_exits_two "exit $rc; err='$(cat "$TMP/err")'"
fi

# ---------------------------------------------------------------------------------- inspect -----
rc=$(run "$CLI" -f "$CONFIG_VALID" inspect)
if [ "$rc" = 0 ] && grep -q "^subject: .*manager-certs-cli-test-ca" "$TMP/out" \
    && grep -q "^issuer: .*manager-certs-cli-test-ca" "$TMP/out" \
    && grep -q "^signsLeaf: yes$" "$TMP/out" && grep -q "^vouched: yes$" "$TMP/out"; then
    pass cli_inspect_reports_real_bundle
else
    fail cli_inspect_reports_real_bundle "exit $rc; out='$(cat "$TMP/out")' err='$(cat "$TMP/err")'"
fi

# --------------------------------------------------------------------------------- check ---------
# The part runCheck()'s own in-process GTest cases cannot cover at all: does the COMPILED BINARY
# leave the bundle file exactly as it found it, both when it accepts one and when it refuses one
# (objection #7). `sleep 1` widens mtime's coarse (1s) resolution: a truncate-and-rewrite
# regression must land in a strictly later second than the fixture's own creation.

before_content=$(cat "$VALID_BUNDLE")
before_mtime=$(stat -c %Y "$VALID_BUNDLE" 2>/dev/null || stat -f %m "$VALID_BUNDLE")
sleep 1
rc=$(run "$CLI" -f "$CONFIG_VALID" check)
after_content=$(cat "$VALID_BUNDLE")
after_mtime=$(stat -c %Y "$VALID_BUNDLE" 2>/dev/null || stat -f %m "$VALID_BUNDLE")
if [ "$rc" = 0 ] && [ -z "$(cat "$TMP/err")" ] \
    && [ "$before_content" = "$after_content" ] && [ "$before_mtime" = "$after_mtime" ]; then
    pass cli_check_accepts_real_bundle_and_leaves_it_unchanged
else
    fail cli_check_accepts_real_bundle_and_leaves_it_unchanged \
        "exit $rc; err='$(cat "$TMP/err")'; content_changed=$([ "$before_content" = "$after_content" ] && echo no || echo YES); mtime_before=$before_mtime mtime_after=$after_mtime"
fi

before_content=$(cat "$REJECTED_BUNDLE")
before_mtime=$(stat -c %Y "$REJECTED_BUNDLE" 2>/dev/null || stat -f %m "$REJECTED_BUNDLE")
sleep 1
rc=$(run "$CLI" -f "$CONFIG_REJECTED" check)
after_content=$(cat "$REJECTED_BUNDLE")
after_mtime=$(stat -c %Y "$REJECTED_BUNDLE" 2>/dev/null || stat -f %m "$REJECTED_BUNDLE")
if [ "$rc" = 1 ] && grep -q "content hash does not match" "$TMP/err" \
    && [ "$before_content" = "$after_content" ] && [ "$before_mtime" = "$after_mtime" ]; then
    pass cli_check_rejects_bad_hash_and_leaves_it_unchanged
else
    fail cli_check_rejects_bad_hash_and_leaves_it_unchanged \
        "exit $rc; err='$(cat "$TMP/err")'; content_changed=$([ "$before_content" = "$after_content" ] && echo no || echo YES); mtime_before=$before_mtime mtime_after=$after_mtime"
fi

echo "manager_certs_cli_test: $((TOTAL - FAILS))/$TOTAL passed"
[ "$FAILS" = 0 ]
