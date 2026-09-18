#!/bin/sh
# manager_certs_cli_test.sh — end-to-end checks of bin/wazuh-manager-certs that main.cpp owns and
# runInspect()/runCheck() (manager_certs/commands.hpp) never see, because those two are pure
# functions over an already-parsed bundle: --version/--help with no configuration present at all
# (RF-10, CA-21), and the three "environment" exit-2 paths (an unreadable -f, a missing CA bundle,
# a missing leaf). Runs from ctest as `manager_certs_cli`, outside the ASAN job (which selects only
# the `manager_certs_utest` GTest label, since it never builds this binary with ASAN).
#
# Usage: manager_certs_cli_test.sh <wazuh-manager-certs>

set -u

CLI="${1:-}"
if [ ! -x "$CLI" ]; then
    echo "usage: $0 <wazuh-manager-certs>" >&2
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

# --------------------------------------------------------------- --version / --help, no config ---
# Unset so the two flags cannot accidentally see a real manager's configuration through the
# environment: they have to short-circuit before resolveHome() is ever called (RF-10), same as
# `wazuh-manager-conf`'s own -h/-V.
unset WAZUH_MANAGER_HOME

rc=$(run "$CLI" --version)
if [ "$rc" = 0 ] && grep -q '^wazuh-manager-certs ' "$TMP/out"; then
    pass cli_version_prints_product_version
else
    fail cli_version_prints_product_version "exit $rc; out='$(cat "$TMP/out")' err='$(cat "$TMP/err")'"
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
if [ "$rc" = 2 ]; then
    pass cli_unreadable_config_exits_two
else
    fail cli_unreadable_config_exits_two "exit $rc; err='$(cat "$TMP/err")'"
fi

# A minimal, schema-valid configuration (cluster.key + indexer.hosts are the two fields with no
# usable default -- manager_config/tests/vectors/valid/minimal-valid.conf's own comment) with an
# absolute leaf that exists and an absolute CA bundle that does not: main.cpp reads the bundle
# before the leaf, so this fails on the bundle regardless of the leaf's own content.
: > "$TMP/leaf.pem"
cat > "$TMP/config-no-bundle.conf" << CONF
<wazuh_config>
  <remote>
    <https>
      <certificate>$TMP/leaf.pem</certificate>
      <key>$TMP/leaf-key.pem</key>
      <ca_certificate>$TMP/no-such-bundle.pem</ca_certificate>
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

rc=$(run "$CLI" -f "$TMP/config-no-bundle.conf" inspect)
if [ "$rc" = 2 ]; then
    pass cli_missing_bundle_exits_two
else
    fail cli_missing_bundle_exits_two "exit $rc; err='$(cat "$TMP/err")'"
fi

# Mirror: an existing (empty) bundle and a leaf that does not exist.
: > "$TMP/bundle.pem"
cat > "$TMP/config-no-leaf.conf" << CONF
<wazuh_config>
  <remote>
    <https>
      <certificate>$TMP/no-such-leaf.pem</certificate>
      <key>$TMP/leaf-key.pem</key>
      <ca_certificate>$TMP/bundle.pem</ca_certificate>
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

rc=$(run "$CLI" -f "$TMP/config-no-leaf.conf" inspect)
if [ "$rc" = 2 ]; then
    pass cli_missing_leaf_exits_two
else
    fail cli_missing_leaf_exits_two "exit $rc; err='$(cat "$TMP/err")'"
fi

echo "manager_certs_cli_test: $((TOTAL - FAILS))/$TOTAL passed"
[ "$FAILS" = 0 ]
