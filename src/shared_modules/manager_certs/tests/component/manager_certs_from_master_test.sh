#!/bin/sh
# manager_certs_from_master_test.sh — the compiled `wazuh-manager-certs --from-master` against a REAL
# HTTPS master (tests/testHttpsMaster.hpp, cpp-httplib's SSLServer over an openssl-built PKI).
#
# What only this level can show, and what the GTest suite next door deliberately does not try to
# (C39h, objection 13): the handshake. The unit suite drives runFromMaster() through the
# MasterTransport seam and the transport through its CurlPort seam, so it proves which options were
# pinned — it cannot prove what those options DO. A grep for a disabled verification flag proves
# less still: it passes on any bypass not spelled that exact way. So the trust cases here are
# genuine TLS refusals: a master signed by a CA this node does not carry, one carrying the wrong
# identity, one trusted only through the ambient OpenSSL environment, and an empty local bundle
# (the state that makes libcurl fall back to its compiled-in CA file if the CAINFO_BLOB failure is
# ignored — `anexos/e8/tls-transporte.md` §1-2).
#
# It also covers what a seam cannot produce at all: the 1 MiB cap against a real stream (exactly at
# the limit, one byte over, and a body that only crosses it in a later chunk), a body that stops
# halfway, a response that is a 302 or a 500 with a perfectly good payload, an unreachable port, the
# URL the configured prefix produces, and an IPv6 master.
#
# Runs from ctest as `manager_certs_from_master`. Every case writes, so all of them need root (G0)
# and are skipped, not failed, without it.
#
# Usage: manager_certs_from_master_test.sh <wazuh-manager-certs> <manager_certs_test_master>

set -u

CLI="${1:-}"
MASTER_BIN="${2:-}"
if [ ! -x "$CLI" ] || [ ! -x "$MASTER_BIN" ]; then
    echo "usage: $0 <wazuh-manager-certs> <manager_certs_test_master>" >&2
    exit 2
fi

TMP=$(mktemp -d) || exit 2
MASTER_PID=""
cleanup() {
    [ -n "$MASTER_PID" ] && kill "$MASTER_PID" 2>/dev/null
    rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

TOTAL=0
FAILS=0
pass() { TOTAL=$((TOTAL + 1)); echo "  ok   $1"; }
fail() { TOTAL=$((TOTAL + 1)); FAILS=$((FAILS + 1)); echo "  FAIL $1: $2" >&2; }
skip() { echo "  skip $1: $2"; }

run() {
    "$@" > "$TMP/out" 2> "$TMP/err"
    echo $?
}

require() {
    if ! "$@" > "$TMP/setup.log" 2>&1; then
        echo "fixture setup failed: $* (see $TMP/setup.log)" >&2
        cat "$TMP/setup.log" >&2
        exit 2
    fi
}

if [ "$(id -u)" != 0 ]; then
    skip manager_certs_from_master "--from-master writes the bundle and must run as root (euid 0)"
    echo "ran 0, failed 0 (skipped)"
    exit 0
fi

# ---------------------------------------------------------------------------------- real PKI ---
# CA_A signs the worker's leaf AND the master's listener certificate: that is the shape a healthy
# cluster has, and the only one in which the pull may succeed. CA_B signs nothing this node trusts.
PKI="$TMP/pki"
mkdir -p "$PKI"

require openssl ecparam -name prime256v1 -genkey -noout -out "$PKI/ca-key.pem"
require openssl req -new -x509 -key "$PKI/ca-key.pem" -days 400 -sha256 \
    -subj "/CN=from-master-test-ca" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out "$PKI/ca-cert.pem"

require openssl ecparam -name prime256v1 -genkey -noout -out "$PKI/ca2-key.pem"
require openssl req -new -x509 -key "$PKI/ca2-key.pem" -days 400 -sha256 \
    -subj "/CN=from-master-test-ca2" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out "$PKI/ca2-cert.pem"

# The worker's own served leaf: what every candidate is validated against (G6).
require openssl ecparam -name prime256v1 -genkey -noout -out "$PKI/leaf-key.pem"
require openssl req -new -key "$PKI/leaf-key.pem" -subj "/CN=from-master-test-leaf" -out "$PKI/leaf.csr"
require openssl x509 -req -in "$PKI/leaf.csr" -CA "$PKI/ca-cert.pem" -CAkey "$PKI/ca-key.pem" \
    -CAcreateserial -days 90 -sha256 -out "$PKI/leaf-cert.pem"

# $1 = name, $2 = CA cert, $3 = CA key, $4 = subject CN, $5 = SAN list.
make_server_cert() {
    require openssl ecparam -name prime256v1 -genkey -noout -out "$PKI/$1-key.pem"
    require openssl req -new -key "$PKI/$1-key.pem" -subj "/CN=$4" -out "$PKI/$1.csr"
    printf 'subjectAltName=%s\n' "$5" > "$PKI/$1.ext"
    require openssl x509 -req -in "$PKI/$1.csr" -CA "$2" -CAkey "$3" -CAcreateserial -days 90 -sha256 \
        -extfile "$PKI/$1.ext" -out "$PKI/$1-cert.pem"
}

# Trusted by the worker's bundle, and named for the addresses the test connects to.
make_server_cert master "$PKI/ca-cert.pem" "$PKI/ca-key.pem" "127.0.0.1" "IP:127.0.0.1,IP:::1"
# Same CA, wrong identity: only VERIFYHOST can refuse this one.
make_server_cert stranger-name "$PKI/ca-cert.pem" "$PKI/ca-key.pem" "wrong.example.com" "DNS:wrong.example.com"
# Right identity, CA the worker does not carry: only VERIFYPEER against the local bundle refuses it.
make_server_cert untrusted "$PKI/ca2-cert.pem" "$PKI/ca2-key.pem" "127.0.0.1" "IP:127.0.0.1,IP:::1"

CONTENT_SHA256=$(openssl x509 -in "$PKI/ca-cert.pem" -outform DER | sha256sum | awk '{print $1}')
[ -n "$CONTENT_SHA256" ] || { echo "could not hash the test CA" >&2; exit 2; }

# What the master serves: the CA that signs this worker's leaf, plus one more, certificates only —
# exactly what remoted's GET /cacerts hands out (no publication block).
cat "$PKI/ca-cert.pem" "$PKI/ca2-cert.pem" > "$PKI/served.pem"

# OpenSSL's ambient trust: a file and a hashed directory that DO vouch for the untrusted master.
# Pointing these at CA_B is how "trusted only by the system store" is produced without touching
# /etc — and the tool must ignore them all the same (CA-33).
HASHDIR="$TMP/hashdir"
mkdir -p "$HASHDIR"
CA2_HASH=$(openssl x509 -in "$PKI/ca2-cert.pem" -hash -noout)
cp "$PKI/ca2-cert.pem" "$HASHDIR/$CA2_HASH.0"

# $1 = output path, $2 = publication, $3 = Content-SHA256, $4 = certificate PEM.
write_sealed_bundle() {
    cat > "$1" << SEALED
##
## Wazuh CA bundle
##
## Publication: $2
## Content-SHA256: $3
## Updated: $(date -u +%Y-%m-%dT%H:%M:%SZ)
## Written by: manager_certs_from_master_test
##
$(cat "$4")
SEALED
}

BUNDLE="$PKI/worker-bundle.pem"
LOCAL_PUBLICATION=$(( $(date +%s) - 3600 ))
NEW_PUBLICATION=$(date +%s)

reset_bundle() {
    write_sealed_bundle "$BUNDLE" "$LOCAL_PUBLICATION" "$CONTENT_SHA256" "$PKI/ca-cert.pem"
    rm -f "$BUNDLE.lock"
}

# $1 = config path, $2 = node_type, $3 = port, $4 = master address, $5 = global_prefix line (may be
# empty, which leaves the schema default /wazuh-manager/ in force).
write_config() {
    cat > "$1" << CONF
<wazuh_config>
  <remote>
    <https>
      <certificate>$PKI/leaf-cert.pem</certificate>
      <key>$PKI/leaf-key.pem</key>
      <ca_certificate>$BUNDLE</ca_certificate>
      <port>$3</port>
      $5
    </https>
  </remote>
  <cluster>
    <node_type>$2</node_type>
    <nodes>
      <node>$4</node>
    </nodes>
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

# ------------------------------------------------------------------------------- the master ----
# start_master <cert> <key> [extra options...]: binds a free port (the server writes which one to
# the ready file), so cases never fight over one.
start_master() {
    cert="$1"
    key="$2"
    shift 2
    rm -f "$TMP/ready" "$TMP/requests"
    "$MASTER_BIN" --port 0 --cert "$cert" --key "$key" \
        --ready-file "$TMP/ready" --request-log "$TMP/requests" "$@" > "$TMP/master.log" 2>&1 &
    MASTER_PID=$!

    attempt=0
    while [ ! -s "$TMP/ready" ] && [ "$attempt" -lt 400 ]; do
        sleep 0.05
        attempt=$((attempt + 1))
    done
    if [ ! -s "$TMP/ready" ]; then
        echo "the test master never came up (see $TMP/master.log)" >&2
        cat "$TMP/master.log" >&2
        exit 2
    fi
    MASTER_PORT=$(cat "$TMP/ready")
}

stop_master() {
    [ -n "$MASTER_PID" ] && kill "$MASTER_PID" 2>/dev/null
    wait "$MASTER_PID" 2>/dev/null
    MASTER_PID=""
}

hash_of() { sha256sum "$1" | awk '{print $1}'; }

CONFIG="$PKI/config.conf"

# ---------------------------------------------------------------- the pull that has to work ----
# The configured port and the configured prefix, with no override on the command line: the URL is
# built from the effective configuration, and the master records which path it was asked for.
reset_bundle
start_master "$PKI/master-cert.pem" "$PKI/master-key.pem" --body "$PKI/served.pem" --generation "$NEW_PUBLICATION"
write_config "$CONFIG" worker "$MASTER_PORT" 127.0.0.1 ""

rc=$(run "$CLI" -f "$CONFIG" --from-master)
if [ "$rc" = 0 ] && grep -q "$NEW_PUBLICATION" "$TMP/out"; then
    pass from_master_installs_the_masters_generation
else
    fail from_master_installs_the_masters_generation "exit $rc; out='$(cat "$TMP/out")' err='$(cat "$TMP/err")'"
fi

# The default prefix is `/wazuh-manager/`: concatenated with `/cacerts` it would have asked for
# `/wazuh-manager//cacerts`, a different route (C39g, objection 5).
if grep -qx "/wazuh-manager/cacerts" "$TMP/requests"; then
    pass from_master_default_prefix_has_no_double_slash
else
    fail from_master_default_prefix_has_no_double_slash "asked for '$(cat "$TMP/requests")'"
fi

# The file the worker now serves is one `check` vouches for, under the master's own generation.
rc=$(run "$CLI" -f "$CONFIG" check)
if [ "$rc" = 0 ] && grep -q "Publication: $NEW_PUBLICATION" "$BUNDLE" \
    && [ "$(grep -c 'BEGIN CERTIFICATE' "$BUNDLE")" = 2 ]; then
    pass from_master_written_bundle_is_vouched_for
else
    fail from_master_written_bundle_is_vouched_for "check exit $rc; err='$(cat "$TMP/err")'"
fi

# Again, unchanged: the same generation is a no-op, not a republish (the fleet would otherwise come
# back for bytes it already has).
before=$(hash_of "$BUNDLE")
rc=$(run "$CLI" -f "$CONFIG" --from-master)
if [ "$rc" = 0 ] && grep -q "nothing to do" "$TMP/out" && [ "$before" = "$(hash_of "$BUNDLE")" ]; then
    pass from_master_repeat_is_a_noop
else
    fail from_master_repeat_is_a_noop "exit $rc; out='$(cat "$TMP/out")'; changed=$([ "$before" = "$(hash_of "$BUNDLE")" ] && echo no || echo YES)"
fi
stop_master

# A generation behind the one already published walks the whole fleet backwards: refused, exit 1.
before=$(hash_of "$BUNDLE")
start_master "$PKI/master-cert.pem" "$PKI/master-key.pem" --body "$PKI/served.pem" \
    --generation "$(( NEW_PUBLICATION - 600 ))"
rc=$(run "$CLI" -f "$CONFIG" --from-master --port "$MASTER_PORT")
if [ "$rc" = 1 ] && [ "$before" = "$(hash_of "$BUNDLE")" ]; then
    pass from_master_lower_generation_rejected
else
    fail from_master_lower_generation_rejected "exit $rc; err='$(cat "$TMP/err")'"
fi
stop_master

# A master that never stamped its own bundle announces 0: read fine, refused (exit 1).
start_master "$PKI/master-cert.pem" "$PKI/master-key.pem" --body "$PKI/served.pem" --generation 0
rc=$(run "$CLI" -f "$CONFIG" --from-master --port "$MASTER_PORT")
if [ "$rc" = 1 ] && grep -q "not vouched" "$TMP/err" && [ "$before" = "$(hash_of "$BUNDLE")" ]; then
    pass from_master_zero_generation_rejected
else
    fail from_master_zero_generation_rejected "exit $rc; err='$(cat "$TMP/err")'"
fi
stop_master

# No header at all: we could not read it, so exit 2 (C38b).
start_master "$PKI/master-cert.pem" "$PKI/master-key.pem" --body "$PKI/served.pem"
rc=$(run "$CLI" -f "$CONFIG" --from-master --port "$MASTER_PORT")
if [ "$rc" = 2 ] && grep -q "announces no Wazuh-CA-Generation" "$TMP/err" && [ "$before" = "$(hash_of "$BUNDLE")" ]; then
    pass from_master_missing_header_rejected
else
    fail from_master_missing_header_rejected "exit $rc; err='$(cat "$TMP/err")'"
fi
stop_master

# --------------------------------------------------------------------------- TLS, for real -----
# The four cases that make CA-33 a fact rather than a grep. All of them leave the bundle alone.

reset_bundle
before=$(hash_of "$BUNDLE")
start_master "$PKI/untrusted-cert.pem" "$PKI/untrusted-key.pem" --body "$PKI/served.pem" \
    --generation "$NEW_PUBLICATION"
rc=$(run "$CLI" -f "$CONFIG" --from-master --port "$MASTER_PORT")
if [ "$rc" = 2 ] && [ "$before" = "$(hash_of "$BUNDLE")" ]; then
    pass from_master_untrusted_ca_fails
else
    fail from_master_untrusted_ca_fails "exit $rc; err='$(cat "$TMP/err")'"
fi

# Same server, now with OpenSSL's ambient trust pointed straight at the CA that signed it. If the
# blob ever stopped being the only trust source — a failed CAINFO_BLOB, an uncleared CAPATH, a
# fallback to the default verify paths — this is the case that would start passing the handshake.
rc=$(env SSL_CERT_FILE="$PKI/ca2-cert.pem" SSL_CERT_DIR="$HASHDIR" \
    "$CLI" -f "$CONFIG" --from-master --port "$MASTER_PORT" > "$TMP/out" 2> "$TMP/err"; echo $?)
if [ "$rc" = 2 ] && [ "$before" = "$(hash_of "$BUNDLE")" ]; then
    pass from_master_system_store_only_trust_rejected
else
    fail from_master_system_store_only_trust_rejected "exit $rc; err='$(cat "$TMP/err")'"
fi
stop_master

# The CA is trusted, the name is not: this is the case VERIFYHOST decides, and a `VERIFYPEER`-only
# implementation would sail through it.
start_master "$PKI/stranger-name-cert.pem" "$PKI/stranger-name-key.pem" --body "$PKI/served.pem" \
    --generation "$NEW_PUBLICATION"
rc=$(run "$CLI" -f "$CONFIG" --from-master --port "$MASTER_PORT")
if [ "$rc" = 2 ] && [ "$before" = "$(hash_of "$BUNDLE")" ]; then
    pass from_master_wrong_identity_rejected
else
    fail from_master_wrong_identity_rejected "exit $rc; err='$(cat "$TMP/err")'"
fi
stop_master

# An empty local bundle is refused before anything connects, with its own message — and with the
# ambient trust deliberately pointed at the master's real CA, so a fallback to the system store
# would have succeeded here.
start_master "$PKI/master-cert.pem" "$PKI/master-key.pem" --body "$PKI/served.pem" \
    --generation "$NEW_PUBLICATION"
: > "$BUNDLE"
rc=$(env SSL_CERT_FILE="$PKI/ca-cert.pem" SSL_CERT_DIR="$HASHDIR" \
    "$CLI" -f "$CONFIG" --from-master --port "$MASTER_PORT" > "$TMP/out" 2> "$TMP/err"; echo $?)
if [ "$rc" = 2 ] && grep -q "local trust bundle is empty" "$TMP/err" && [ ! -s "$BUNDLE" ]; then
    pass from_master_empty_local_bundle_rejected
else
    fail from_master_empty_local_bundle_rejected "exit $rc; err='$(cat "$TMP/err")'"
fi

# An inherited proxy that points nowhere must not be used at all: the request goes direct, and the
# pull succeeds (C39a, objection 3 — the proxy is off so no CONNECT answer can supply a header).
reset_bundle
rc=$(env https_proxy="http://127.0.0.1:9" HTTPS_PROXY="http://127.0.0.1:9" ALL_PROXY="http://127.0.0.1:9" \
    "$CLI" -f "$CONFIG" --from-master --port "$MASTER_PORT" > "$TMP/out" 2> "$TMP/err"; echo $?)
if [ "$rc" = 0 ] && grep -q "$NEW_PUBLICATION" "$TMP/out"; then
    pass from_master_ambient_proxy_ignored
else
    fail from_master_ambient_proxy_ignored "exit $rc; out='$(cat "$TMP/out")' err='$(cat "$TMP/err")'"
fi
stop_master

# ------------------------------------------------------------------- the 1 MiB cap, streamed ---
# Exactly at the cap: accepted. The padding is comment lines, which every PEM reader skips, so what
# is being measured is the cap and not the parser.
reset_bundle
start_master "$PKI/master-cert.pem" "$PKI/master-key.pem" --body "$PKI/served.pem" \
    --generation "$NEW_PUBLICATION" --pad-to 1048576
rc=$(run "$CLI" -f "$CONFIG" --from-master --port "$MASTER_PORT")
if [ "$rc" = 0 ] && grep -q "Publication: $NEW_PUBLICATION" "$BUNDLE"; then
    pass from_master_exact_limit_accepted
else
    fail from_master_exact_limit_accepted "exit $rc; err='$(cat "$TMP/err")'"
fi
stop_master

reset_bundle
before=$(hash_of "$BUNDLE")
start_master "$PKI/master-cert.pem" "$PKI/master-key.pem" --body "$PKI/served.pem" \
    --generation "$NEW_PUBLICATION" --pad-to 1048577
rc=$(run "$CLI" -f "$CONFIG" --from-master --port "$MASTER_PORT")
if [ "$rc" = 2 ] && [ "$before" = "$(hash_of "$BUNDLE")" ]; then
    pass from_master_limit_plus_one_rejected
else
    fail from_master_limit_plus_one_rejected "exit $rc; err='$(cat "$TMP/err")'"
fi
stop_master

# The same overflow, but only reached in a later chunk: the crossing chunk is dropped whole, and the
# transfer is aborted rather than truncated (C39c, objection 6).
start_master "$PKI/master-cert.pem" "$PKI/master-key.pem" --body "$PKI/served.pem" \
    --generation "$NEW_PUBLICATION" --pad-to 1048577 --chunks 2
rc=$(run "$CLI" -f "$CONFIG" --from-master --port "$MASTER_PORT")
if [ "$rc" = 2 ] && [ "$before" = "$(hash_of "$BUNDLE")" ]; then
    pass from_master_chunk_boundary_crossing_rejected
else
    fail from_master_chunk_boundary_crossing_rejected "exit $rc; err='$(cat "$TMP/err")'"
fi
stop_master

# ----------------------------------------------------------- responses that are not a full 200 --
for status in 302 500 206; do
    start_master "$PKI/master-cert.pem" "$PKI/master-key.pem" --body "$PKI/served.pem" \
        --generation "$NEW_PUBLICATION" --status "$status"
    rc=$(run "$CLI" -f "$CONFIG" --from-master --port "$MASTER_PORT")
    if [ "$rc" = 2 ] && [ "$before" = "$(hash_of "$BUNDLE")" ]; then
        pass "from_master_http_${status}_rejected"
    else
        fail "from_master_http_${status}_rejected" "exit $rc; err='$(cat "$TMP/err")'"
    fi
    stop_master
done

# A body that stops halfway is not a smaller bundle, it is none.
start_master "$PKI/master-cert.pem" "$PKI/master-key.pem" --body "$PKI/served.pem" \
    --generation "$NEW_PUBLICATION" --truncate
rc=$(run "$CLI" -f "$CONFIG" --from-master --port "$MASTER_PORT")
if [ "$rc" = 2 ] && [ "$before" = "$(hash_of "$BUNDLE")" ]; then
    pass from_master_truncated_body_rejected
else
    fail from_master_truncated_body_rejected "exit $rc; err='$(cat "$TMP/err")'"
fi
stop_master

# ------------------------------------------------------------------------- address and node ----
# An IPv6 master given bare on the command line: the authority has to be bracketed or the first
# colon reads as the port separator (C39g).
reset_bundle
start_master "$PKI/master-cert.pem" "$PKI/master-key.pem" --bind "::1" --body "$PKI/served.pem" \
    --generation "$NEW_PUBLICATION"
rc=$(run "$CLI" -f "$CONFIG" --from-master --master "::1" --port "$MASTER_PORT")
if [ "$rc" = 0 ] && grep -q "https://\[::1\]:$MASTER_PORT/" "$TMP/out"; then
    pass from_master_ipv6_master_bracketed
else
    fail from_master_ipv6_master_bracketed "exit $rc; out='$(cat "$TMP/out")' err='$(cat "$TMP/err")'"
fi
stop_master

# Nothing listening: exit 2, and the message has to hand the operator the two overrides and the way
# that does not need the network at all.
reset_bundle
before=$(hash_of "$BUNDLE")
rc=$(run "$CLI" -f "$CONFIG" --from-master --port 1)
if [ "$rc" = 2 ] && grep -q -- "--port" "$TMP/err" && grep -q "scp" "$TMP/err" \
    && [ "$before" = "$(hash_of "$BUNDLE")" ]; then
    pass from_master_unreachable_master_rejected
else
    fail from_master_unreachable_master_rejected "exit $rc; err='$(cat "$TMP/err")'"
fi

# On a master it is the wrong command entirely — and, like G7 for the writing commands, it refuses
# before anything is opened or locked (C34c/C37a).
CONFIG_MASTER="$PKI/config-master.conf"
write_config "$CONFIG_MASTER" master 1517 127.0.0.1 ""
# The lock file earlier cases left behind is removed first, so what this asserts is that THIS run
# did not create one -- the guard ran before anything was opened.
rm -f "$BUNDLE.lock"
rc=$(run "$CLI" -f "$CONFIG_MASTER" --from-master)
if [ "$rc" = 2 ] && grep -q "not a cluster worker" "$TMP/err" \
    && [ ! -e "$BUNDLE.lock" ] && [ "$before" = "$(hash_of "$BUNDLE")" ]; then
    pass from_master_refused_on_master_without_locking
else
    fail from_master_refused_on_master_without_locking \
        "exit $rc; err='$(cat "$TMP/err")'; lock_exists=$([ -e "$BUNDLE.lock" ] && echo YES || echo no)"
fi

echo "ran $TOTAL, failed $FAILS"
[ "$FAILS" = 0 ]
