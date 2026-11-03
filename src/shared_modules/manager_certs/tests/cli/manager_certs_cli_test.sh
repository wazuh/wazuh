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
# From E7a it also covers the two things only REAL PROCESSES can show about `add`: two of them
# publishing at once must not lose either certificate (the exclusive lock, C34f), and a refused
# `add` must leave the bundle untouched — which the GTest cases over finishWrite() cannot prove for
# main.cpp itself. Those cases need root (G0) and are skipped, not failed, without it.
#
# E7b adds the other three writing commands, at the one level where main.cpp's own dispatch, arity
# and exit-code mapping are exercised: `stamp` turning a plain PEM into a bundle `check` vouches for,
# `remove` dropping a certificate by the identity `inspect` prints, `prune-expired` writing NOTHING
# when nothing has expired (C35) while still warning about an unpublished bundle (C36i), and all
# three refusing on a worker without leaving a lock file behind.
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
# Not a pass and not a failure: a case whose precondition this environment cannot meet.
skip() { echo "  skip $1: $2"; }

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

# The four writing commands are listed, and none of them is still announced as unavailable: a usage
# text that promises `stamp` "in a later version" is what an operator reads before deciding the tool
# cannot fix their unpublished bundle.
rc=$(run "$CLI" --help)
if [ "$rc" = 0 ] && grep -q 'add <file>' "$TMP/out" && grep -q 'remove <identity>' "$TMP/out" \
    && grep -q 'prune-expired' "$TMP/out" && grep -q '^  stamp ' "$TMP/out" \
    && ! grep -qE 'arrives? in (a )?later version' "$TMP/out"; then
    pass cli_help_lists_the_writing_commands
else
    fail cli_help_lists_the_writing_commands "exit $rc; out='$(cat "$TMP/out")'"
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

# ----------------------------------------------------------------------------------- add --------
# `add` writes, so every case below needs root (G0) and a bundle of its own, never the fixtures the
# read-only cases above assert are unchanged.

if [ "$(id -u)" != 0 ]; then
    skip cli_add_cases "add must run as root (euid 0); nothing here can exercise it"
else
    require openssl ecparam -name prime256v1 -genkey -noout -out "$PKI/ca2-key.pem"
    require openssl req -new -x509 -key "$PKI/ca2-key.pem" -days 400 -sha256 \
        -subj "/CN=manager-certs-cli-test-ca2" \
        -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -out "$PKI/ca2-cert.pem"
    require openssl ecparam -name prime256v1 -genkey -noout -out "$PKI/ca3-key.pem"
    require openssl req -new -x509 -key "$PKI/ca3-key.pem" -days 400 -sha256 \
        -subj "/CN=manager-certs-cli-test-ca3" \
        -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -out "$PKI/ca3-cert.pem"

    CA2_ID=$(openssl x509 -in "$PKI/ca2-cert.pem" -outform DER | sha256sum | awk '{print $1}')
    CA3_ID=$(openssl x509 -in "$PKI/ca3-cert.pem" -outform DER | sha256sum | awk '{print $1}')

    # --- a worker refuses before it takes the lock -----------------------------------------------
    WORKER_BUNDLE="$PKI/worker-bundle.pem"
    write_sealed_bundle "$WORKER_BUNDLE" "$(date +%s)" "$CONTENT_SHA256" "$PKI/ca-cert.pem"
    CONFIG_WORKER="$PKI/config-worker.conf"
    cat > "$CONFIG_WORKER" << CONF
<wazuh_config>
  <remote>
    <https>
      <certificate>$PKI/leaf-cert.pem</certificate>
      <key>$PKI/leaf-key.pem</key>
      <ca_certificate>$WORKER_BUNDLE</ca_certificate>
    </https>
  </remote>
  <cluster>
    <node_type>worker</node_type>
    <key>0123456789abcdef0123456789abcdef</key>
  </cluster>
  <indexer>
    <hosts>
      <host>https://127.0.0.1:9200</host>
    </hosts>
  </indexer>
</wazuh_config>
CONF
    before_content=$(cat "$WORKER_BUNDLE")
    rc=$(run "$CLI" -f "$CONFIG_WORKER" add "$PKI/ca2-cert.pem")
    # No lock file either: G7 is evaluated before anything opens or locks the bundle (C34c), so a
    # worker never leaves a trace beside it.
    if [ "$rc" = 2 ] && grep -q -- "--from-master" "$TMP/err" \
        && [ "$before_content" = "$(cat "$WORKER_BUNDLE")" ] && [ ! -e "$WORKER_BUNDLE.lock" ]; then
        pass cli_add_on_worker_refuses_without_touching_the_bundle
    else
        fail cli_add_on_worker_refuses_without_touching_the_bundle \
            "exit $rc; err='$(cat "$TMP/err")'; lock_exists=$([ -e "$WORKER_BUNDLE.lock" ] && echo YES || echo no)"
    fi

    # --- a refused add leaves the bundle byte for byte ------------------------------------------
    # The bundle holds a CA that does NOT sign the served leaf, so adding another unrelated CA is
    # refused by G6 — the guard that runs last, after the whole candidate has been built.
    ORPHAN_BUNDLE="$PKI/orphan-bundle.pem"
    ORPHAN_SHA256=$(openssl x509 -in "$PKI/ca2-cert.pem" -outform DER | sha256sum | awk '{print $1}')
    write_sealed_bundle "$ORPHAN_BUNDLE" "$(date +%s)" "$ORPHAN_SHA256" "$PKI/ca2-cert.pem"
    CONFIG_ORPHAN="$PKI/config-orphan.conf"
    write_config "$CONFIG_ORPHAN" "$PKI/leaf-cert.pem" "$ORPHAN_BUNDLE"

    before_content=$(cat "$ORPHAN_BUNDLE")
    before_mtime=$(stat -c %Y "$ORPHAN_BUNDLE" 2>/dev/null || stat -f %m "$ORPHAN_BUNDLE")
    sleep 1
    rc=$(run "$CLI" -f "$CONFIG_ORPHAN" add "$PKI/ca3-cert.pem")
    after_mtime=$(stat -c %Y "$ORPHAN_BUNDLE" 2>/dev/null || stat -f %m "$ORPHAN_BUNDLE")
    temporaries=$(find "$PKI" -name "orphan-bundle.pem.tmp.*" | wc -l)
    if [ "$rc" = 1 ] && grep -q "no CA signs the served leaf" "$TMP/err" \
        && [ "$before_content" = "$(cat "$ORPHAN_BUNDLE")" ] && [ "$before_mtime" = "$after_mtime" ] \
        && [ "$temporaries" = 0 ]; then
        pass cli_add_rejected_leaves_the_bundle_unchanged
    else
        fail cli_add_rejected_leaves_the_bundle_unchanged \
            "exit $rc; err='$(cat "$TMP/err")'; mtime_before=$before_mtime mtime_after=$after_mtime temporaries=$temporaries"
    fi

    # --- two real processes publishing at once ---------------------------------------------------
    # Without the exclusive lock both read the same bundle and the second rename wins, so one
    # operator's CA disappears from the file the whole fleet trusts (C34f). With it, both land.
    SHARED_BUNDLE="$PKI/shared-bundle.pem"
    write_sealed_bundle "$SHARED_BUNDLE" "$(date +%s)" "$CONTENT_SHA256" "$PKI/ca-cert.pem"
    CONFIG_SHARED="$PKI/config-shared.conf"
    write_config "$CONFIG_SHARED" "$PKI/leaf-cert.pem" "$SHARED_BUNDLE"

    "$CLI" -f "$CONFIG_SHARED" add "$PKI/ca2-cert.pem" > "$TMP/add2.out" 2> "$TMP/add2.err" &
    pid2=$!
    "$CLI" -f "$CONFIG_SHARED" add "$PKI/ca3-cert.pem" > "$TMP/add3.out" 2> "$TMP/add3.err" &
    pid3=$!
    wait $pid2; rc2=$?
    wait $pid3; rc3=$?

    certificates=$(grep -c "BEGIN CERTIFICATE" "$SHARED_BUNDLE")
    rc_inspect=$(run "$CLI" -f "$CONFIG_SHARED" inspect)
    identities=$(grep -c "^identity: x509-sha256:\($CA2_ID\|$CA3_ID\)$" "$TMP/out")
    rc_check=$(run "$CLI" -f "$CONFIG_SHARED" check)
    temporaries=$(find "$PKI" -name "shared-bundle.pem.tmp.*" | wc -l)
    if [ "$rc2" = 0 ] && [ "$rc3" = 0 ] && [ "$certificates" = 3 ] && [ "$identities" = 2 ] \
        && [ "$rc_inspect" = 0 ] && [ "$rc_check" = 0 ] && [ "$temporaries" = 0 ]; then
        pass cli_two_concurrent_adds_keep_both_certificates
    else
        fail cli_two_concurrent_adds_keep_both_certificates \
            "exits $rc2/$rc3; certificates=$certificates identities=$identities check=$rc_check temporaries=$temporaries; err2='$(cat "$TMP/add2.err")' err3='$(cat "$TMP/add3.err")'"
    fi

    # Strictly increasing publications, from two processes that started in the same second (CA-24).
    first_publication=$(sed -n 's/^## Publication: //p' "$SHARED_BUNDLE")
    if [ -n "$first_publication" ] && [ "$first_publication" -gt 0 ]; then
        pass cli_concurrent_adds_leave_a_published_bundle
    else
        fail cli_concurrent_adds_leave_a_published_bundle "publication='$first_publication'"
    fi

    # --- stamp: a plain PEM becomes a bundle `check` vouches for --------------------------------
    # The end-to-end shape of CA-29, and the one case that needs no fixture at all beyond a CA file
    # an operator could have provisioned by hand: before `stamp` the bundle carries no publication
    # block, so `check` refuses it; afterwards the SAME certificates are published and it passes.
    STAMP_BUNDLE="$PKI/stamp-bundle.pem"
    cp "$PKI/ca-cert.pem" "$STAMP_BUNDLE"
    CONFIG_STAMP="$PKI/config-stamp.conf"
    write_config "$CONFIG_STAMP" "$PKI/leaf-cert.pem" "$STAMP_BUNDLE"

    rc_before=$(run "$CLI" -f "$CONFIG_STAMP" check)
    rc=$(run "$CLI" -f "$CONFIG_STAMP" stamp)
    stamp_out=$(cat "$TMP/out")
    rc_after=$(run "$CLI" -f "$CONFIG_STAMP" check)
    publication=$(sed -n 's/^## Publication: //p' "$STAMP_BUNDLE")
    certificates=$(grep -c "BEGIN CERTIFICATE" "$STAMP_BUNDLE")
    temporaries=$(find "$PKI" -name "stamp-bundle.pem.tmp.*" | wc -l)
    if [ "$rc_before" = 1 ] && [ "$rc" = 0 ] && [ "$rc_after" = 0 ] \
        && [ -n "$publication" ] && [ "$publication" -gt 0 ] && [ "$certificates" = 1 ] \
        && [ "$temporaries" = 0 ]; then
        pass cli_stamp_publishes_a_plain_pem
    else
        fail cli_stamp_publishes_a_plain_pem \
            "check_before=$rc_before stamp=$rc check_after=$rc_after publication='$publication' certificates=$certificates temporaries=$temporaries out='$stamp_out' err='$(cat "$TMP/err")'"
    fi

    # --- remove: by the identity `inspect` prints ------------------------------------------------
    # `add` then `remove` over the same bundle, so the identity fed to `remove` is exactly the
    # string the tool itself printed, and the generation has to grow at every step (CA-24).
    rc_add=$(run "$CLI" -f "$CONFIG_STAMP" add "$PKI/ca2-cert.pem")
    publication_added=$(sed -n 's/^## Publication: //p' "$STAMP_BUNDLE")
    rc=$(run "$CLI" -f "$CONFIG_STAMP" remove "x509-sha256:$CA2_ID")
    remove_out=$(cat "$TMP/out")
    publication_removed=$(sed -n 's/^## Publication: //p' "$STAMP_BUNDLE")
    certificates=$(grep -c "BEGIN CERTIFICATE" "$STAMP_BUNDLE")
    rc_check=$(run "$CLI" -f "$CONFIG_STAMP" check)
    rc_inspect=$(run "$CLI" -f "$CONFIG_STAMP" inspect)
    still_there=$(grep -c "^identity: x509-sha256:$CA2_ID$" "$TMP/out")
    if [ "$rc_add" = 0 ] && [ "$rc" = 0 ] && [ "$certificates" = 1 ] && [ "$still_there" = 0 ] \
        && [ "$rc_check" = 0 ] && [ "$rc_inspect" = 0 ] \
        && [ "$publication_removed" -gt "$publication_added" ]; then
        pass cli_remove_drops_the_certificate_and_republishes
    else
        fail cli_remove_drops_the_certificate_and_republishes \
            "add=$rc_add remove=$rc certificates=$certificates still_there=$still_there check=$rc_check publications=$publication_added/$publication_removed out='$remove_out' err='$(cat "$TMP/err")'"
    fi

    # An identity the bundle does not carry: exit 1, and the file is not republished either — the
    # generation must not move for a command that changed nothing.
    before_content=$(cat "$STAMP_BUNDLE")
    before_mtime=$(stat -c %Y "$STAMP_BUNDLE" 2>/dev/null || stat -f %m "$STAMP_BUNDLE")
    sleep 1
    rc=$(run "$CLI" -f "$CONFIG_STAMP" remove "x509-sha256:$CA3_ID")
    after_mtime=$(stat -c %Y "$STAMP_BUNDLE" 2>/dev/null || stat -f %m "$STAMP_BUNDLE")
    if [ "$rc" = 1 ] && grep -q "not found in bundle" "$TMP/err" \
        && [ "$before_content" = "$(cat "$STAMP_BUNDLE")" ] && [ "$before_mtime" = "$after_mtime" ]; then
        pass cli_remove_unknown_identity_leaves_the_bundle_unchanged
    else
        fail cli_remove_unknown_identity_leaves_the_bundle_unchanged \
            "exit $rc; err='$(cat "$TMP/err")'; mtime_before=$before_mtime mtime_after=$after_mtime"
    fi

    # --- prune-expired: nothing expired, nothing written (C35) -----------------------------------
    # The bundle is sealed, current and vouched, so the command must not touch the file at all: an
    # unchanged bundle under a new generation sends the whole fleet back to GET /cacerts for bytes
    # it already has, every night this runs from cron.
    before_content=$(cat "$STAMP_BUNDLE")
    before_mtime=$(stat -c %Y "$STAMP_BUNDLE" 2>/dev/null || stat -f %m "$STAMP_BUNDLE")
    sleep 1
    rc=$(run "$CLI" -f "$CONFIG_STAMP" prune-expired)
    after_mtime=$(stat -c %Y "$STAMP_BUNDLE" 2>/dev/null || stat -f %m "$STAMP_BUNDLE")
    if [ "$rc" = 0 ] && grep -q "nothing to prune" "$TMP/out" && [ -z "$(cat "$TMP/err")" ] \
        && [ "$before_content" = "$(cat "$STAMP_BUNDLE")" ] && [ "$before_mtime" = "$after_mtime" ]; then
        pass cli_prune_expired_with_nothing_expired_does_not_write
    else
        fail cli_prune_expired_with_nothing_expired_does_not_write \
            "exit $rc; out='$(cat "$TMP/out")' err='$(cat "$TMP/err")'; mtime_before=$before_mtime mtime_after=$after_mtime"
    fi

    # ... but it does not stay silent about an UNPUBLISHED bundle (C36i): same exit 0, nothing
    # written, and a line telling the operator which command fixes it.
    UNSEALED_BUNDLE="$PKI/unsealed-bundle.pem"
    cp "$PKI/ca-cert.pem" "$UNSEALED_BUNDLE"
    CONFIG_UNSEALED="$PKI/config-unsealed.conf"
    write_config "$CONFIG_UNSEALED" "$PKI/leaf-cert.pem" "$UNSEALED_BUNDLE"
    before_content=$(cat "$UNSEALED_BUNDLE")
    before_mtime=$(stat -c %Y "$UNSEALED_BUNDLE" 2>/dev/null || stat -f %m "$UNSEALED_BUNDLE")
    sleep 1
    rc=$(run "$CLI" -f "$CONFIG_UNSEALED" prune-expired)
    after_mtime=$(stat -c %Y "$UNSEALED_BUNDLE" 2>/dev/null || stat -f %m "$UNSEALED_BUNDLE")
    if [ "$rc" = 0 ] && grep -q "nothing to prune" "$TMP/out" \
        && grep -q "not vouched; run 'stamp' to publish it" "$TMP/err" \
        && [ "$before_content" = "$(cat "$UNSEALED_BUNDLE")" ] && [ "$before_mtime" = "$after_mtime" ]; then
        pass cli_prune_expired_warns_about_an_unpublished_bundle
    else
        fail cli_prune_expired_warns_about_an_unpublished_bundle \
            "exit $rc; out='$(cat "$TMP/out")' err='$(cat "$TMP/err")'; mtime_before=$before_mtime mtime_after=$after_mtime"
    fi

    # --- the other three commands refuse on a worker too (CA-30) --------------------------------
    # Same bundle and same configuration as the `add` case above, so what is being compared is the
    # command alone: each one refuses with exit 2, leaves the bundle alone and creates no lock file.
    worker_failures=""
    before_content=$(cat "$WORKER_BUNDLE")
    for worker_command in remove prune-expired stamp; do
        if [ "$worker_command" = remove ]; then
            rc=$(run "$CLI" -f "$CONFIG_WORKER" "$worker_command" "x509-sha256:$CA2_ID")
        else
            rc=$(run "$CLI" -f "$CONFIG_WORKER" "$worker_command")
        fi
        if [ "$rc" != 2 ] || ! grep -q -- "--from-master" "$TMP/err" \
            || [ "$before_content" != "$(cat "$WORKER_BUNDLE")" ] || [ -e "$WORKER_BUNDLE.lock" ]; then
            worker_failures="$worker_failures $worker_command(exit=$rc)"
        fi
    done
    if [ -z "$worker_failures" ]; then
        pass cli_write_commands_refuse_on_worker_without_touching_the_bundle
    else
        fail cli_write_commands_refuse_on_worker_without_touching_the_bundle "failed:$worker_failures"
    fi
fi

echo "manager_certs_cli_test: $((TOTAL - FAILS))/$TOTAL passed"
[ "$FAILS" = 0 ]
