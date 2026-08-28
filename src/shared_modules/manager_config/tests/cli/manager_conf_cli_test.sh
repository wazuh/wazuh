#!/bin/sh
# manager_conf_cli_test.sh — end-to-end checks of bin/wazuh-manager-conf and of the YAML twin produced by
# src/init/gen_wazuh.sh (WriteManagerYaml). Runs from ctest as `manager_config_cli`.
#
# Usage: manager_conf_cli_test.sh <wazuh-manager-conf> <vectors-dir> <repo-root>
#
# The generator is exercised through a scratch mirror of the repository (symlinks to etc/ and src/init/*.sh),
# so its temporary files never touch the working tree.

set -u

CLI="${1:-}"
VECTORS="${2:-}"
REPO="${3:-}"
if [ ! -x "$CLI" ] || [ ! -d "$VECTORS" ] || [ ! -f "$REPO/src/init/gen_wazuh.sh" ]; then
    echo "usage: $0 <wazuh-manager-conf> <vectors-dir> <repo-root>" >&2
    exit 2
fi

TMP=$(mktemp -d) || exit 2
trap 'rm -rf "$TMP"' EXIT INT TERM

VALID="$VECTORS/valid"
INVALID="$VECTORS/invalid"
GEN="$VALID/generated-manager.yml"
VECTOR_KEY="0123456789abcdef0123456789abcdef"

TOTAL=0
FAILS=0
pass() { TOTAL=$((TOTAL + 1)); echo "  ok   $1"; }
fail() { TOTAL=$((TOTAL + 1)); FAILS=$((FAILS + 1)); echo "  FAIL $1: $2" >&2; }

# run <cmd...>: captures stdout/stderr in $TMP/out and $TMP/err, prints the exit code.
run() {
    "$@" > "$TMP/out" 2> "$TMP/err"
    echo $?
}
# effective <file> <key>: `get` with file checks disabled.
effective() { "$CLI" --skip-file-checks -f "$1" get "$2" 2> /dev/null; }

# ---------------------------------------------------------------- CLI ----------------------------------------
rc=$(run "$CLI" --skip-file-checks validate -f "$GEN")
if [ "$rc" = 0 ] && [ ! -s "$TMP/out" ] && [ ! -s "$TMP/err" ]; then
    pass cli_validate_ok
else
    fail cli_validate_ok "exit $rc; out='$(cat "$TMP/out")' err='$(cat "$TMP/err")'"
fi

rc=$(run "$CLI" validate -f "$INVALID/yes-no-boolean.yml")
if [ "$rc" = 1 ] && grep -q '(1244)' "$TMP/err" && grep -q '/auth/use_password' "$TMP/err"; then
    pass cli_validate_invalid
else
    fail cli_validate_invalid "exit $rc; err='$(cat "$TMP/err")'"
fi

rc=$(run "$CLI" validate -f "$TMP/does-not-exist.yml")
if [ "$rc" = 1 ] && grep -q '(1239)' "$TMP/err"; then
    pass cli_validate_missing_file
else
    fail cli_validate_missing_file "exit $rc; err='$(cat "$TMP/err")'"
fi

mkdir -p "$TMP/emptyhome"
rc=$(run "$CLI" validate -H "$TMP/emptyhome" -f "$GEN")
if [ "$rc" = 1 ] && grep -q '(1244)' "$TMP/err" && grep -q '/remote/https/certificate' "$TMP/err"; then
    pass cli_validate_checks_files
else
    fail cli_validate_checks_files "exit $rc; err='$(cat "$TMP/err")'"
fi

if [ "$(effective "$GEN" cluster.node_type)" = "master" ] \
    && [ "$(effective "$GEN" auth.disabled)" = "false" ] \
    && [ "$(effective "$GEN" remote.https.port)" = "1517" ] \
    && [ "$(effective "$GEN" remote.legacy.protocol)" = '["tcp"]' ]; then
    pass cli_get_scalar_bool_list
else
    fail cli_get_scalar_bool_list "node_type='$(effective "$GEN" cluster.node_type)' disabled='$(effective "$GEN" auth.disabled)' port='$(effective "$GEN" remote.https.port)' protocol='$(effective "$GEN" remote.legacy.protocol)'"
fi

rc=$(run "$CLI" --skip-file-checks -f "$GEN" get wdb.backup.global)
object=$(cat "$TMP/out")
rc_missing=$(run "$CLI" --skip-file-checks -f "$GEN" get remote.https.verification_mode)
case "$object" in
    \{*\"interval\"*\}) object_ok=yes ;;
    *) object_ok=no ;;
esac
if [ "$rc" = 0 ] && [ "$object_ok" = yes ] && [ "$rc_missing" = 2 ] && grep -q 'is not set' "$TMP/err"; then
    pass cli_get_object_and_missing
else
    fail cli_get_object_and_missing "object exit $rc '$object'; missing exit $rc_missing err='$(cat "$TMP/err")'"
fi

rc=$(run "$CLI" --skip-file-checks -f "$VALID/empty.yml" dump)
if [ "$rc" = 0 ] && grep -q '"remote"' "$TMP/out" && grep -q '"cluster"' "$TMP/out" \
    && [ "$(effective "$VALID/empty.yml" wdb.backup.global.interval)" = "1d" ]; then
    pass cli_dump_defaults
else
    fail cli_dump_defaults "exit $rc; interval='$(effective "$VALID/empty.yml" wdb.backup.global.interval)'"
fi

mkdir -p "$TMP/home/etc"
cp "$GEN" "$TMP/home/etc/wazuh-manager.yml"
rc=$( (export WAZUH_MANAGER_HOME="$TMP/home"; "$CLI" --skip-file-checks validate > "$TMP/out" 2> "$TMP/err"; echo $?) )
if [ "$rc" = 0 ]; then
    pass cli_default_home
else
    fail cli_default_home "exit $rc; err='$(cat "$TMP/err")'"
fi

# ---------------------------------------------------------------- generator ----------------------------------
# Scratch mirror of the repository: gen_wazuh.sh resolves ./etc/templates relative to <script>/../..
MIRROR="$TMP/repo"
mkdir -p "$MIRROR/src/init"
ln -s "$REPO/etc" "$MIRROR/etc"
ln -s "$REPO/VERSION.json" "$MIRROR/VERSION.json"
for script in "$REPO"/src/init/*.sh; do
    ln -s "$script" "$MIRROR/src/init/$(basename "$script")"
done

# gen <generator> <yaml-out> <xml-out> [VAR=value ...]
gen() {
    generator="$1"; yaml_out="$2"; xml_out="$3"; shift 3
    (
        for assignment in "$@"; do
            export "$assignment"
        done
        sh "$generator" conf manager ubuntu 24.04 /var/wazuh-manager "$yaml_out" > "$xml_out" 2> "$TMP/gen.err"
    )
}
# The cluster key is the only <key> holding 32 hex characters (the others are certificate paths).
xml_key() { sed -n 's:.*<key>\([0-9a-fA-F]\{32\}\)</key>.*:\1:p' "$1"; }

if gen "$MIRROR/src/init/gen_wazuh.sh" "$TMP/w.yml" "$TMP/w.conf" \
    && [ -s "$TMP/w.yml" ] && [ -s "$TMP/w.conf" ] \
    && "$CLI" --skip-file-checks validate -f "$TMP/w.yml" 2> "$TMP/err" \
    && key=$(xml_key "$TMP/w.conf") && [ -n "$key" ] \
    && [ "$(effective "$TMP/w.yml" cluster.key)" = "$key" ] \
    && sed "s/$VECTOR_KEY/$key/" "$GEN" > "$TMP/expected.yml" \
    && "$CLI" --skip-file-checks -f "$TMP/w.yml" dump > "$TMP/dump.actual" \
    && "$CLI" --skip-file-checks -f "$TMP/expected.yml" dump > "$TMP/dump.expected" \
    && sort "$TMP/dump.actual" > "$TMP/dump.actual.sorted" && sort "$TMP/dump.expected" > "$TMP/dump.expected.sorted" \
    && cmp -s "$TMP/dump.actual.sorted" "$TMP/dump.expected.sorted"; then
    # (sorted: the effective documents are equal as sets of lines; key order differs where a default was filled)
    pass gen_both_files_same_key
else
    fail gen_both_files_same_key "gen.err='$(cat "$TMP/gen.err" 2> /dev/null)' err='$(cat "$TMP/err" 2> /dev/null)' diff: $(diff "$TMP/dump.expected" "$TMP/dump.actual" 2>&1 | head -20)"
fi

if gen "$MIRROR/src/init/gen_wazuh.sh" "$TMP/v.yml" "$TMP/v.conf" \
    WAZUH_REMOTE_LEGACY_PROTOCOL=tcp,udp WAZUH_REMOTE_HTTPS_BIND_ADDR=0.0.0.0 WAZUH_REMOTE_HTTPS_DUAL_STACK=yes \
    WAZUH_REMOTE_LEGACY_IPV6=yes WAZUH_REMOTE_LEGACY_RIDS_CLOSING_TIME=10m WAZUH_REMOTE_HTTPS_MAX_BODY_SIZE=2M \
    && "$CLI" --skip-file-checks validate -f "$TMP/v.yml" 2> "$TMP/err" \
    && [ "$(effective "$TMP/v.yml" remote.legacy.protocol)" = '["tcp","udp"]' ] \
    && [ "$(effective "$TMP/v.yml" remote.https.dual_stack)" = "true" ] \
    && [ "$(effective "$TMP/v.yml" remote.legacy.ipv6)" = "true" ] \
    && [ "$(effective "$TMP/v.yml" remote.https.bind_addr)" = "0.0.0.0" ] \
    && [ "$(effective "$TMP/v.yml" remote.legacy.rids_closing_time)" = "10m" ] \
    && [ "$(effective "$TMP/v.yml" remote.https.max_body_size)" = "2M" ] \
    && ! grep -q 'local_ip' "$TMP/v.yml"; then
    pass gen_remote_vars
else
    fail gen_remote_vars "gen.err='$(cat "$TMP/gen.err" 2> /dev/null)' err='$(cat "$TMP/err" 2> /dev/null)' yml: $(cat "$TMP/v.yml" 2> /dev/null | sed -n '/^remote:/,/^$/p')"
fi

# A backslash passes the XML check (& < > " ') but not the YAML one: only CheckRemoteYamlSafe rejects it.
gen "$MIRROR/src/init/gen_wazuh.sh" "$TMP/u.yml" "$TMP/u.conf" 'WAZUH_REMOTE_HTTPS_CIPHERS=A\B'
rc=$?
if [ "$rc" = 1 ] && grep -q 'WAZUH_REMOTE_HTTPS_CIPHERS' "$TMP/gen.err" \
    && [ ! -e "$MIRROR/wazuh.conf.temp" ] && [ ! -e "$MIRROR/wazuh.yml.temp" ] && [ ! -e "$TMP/u.yml" ]; then
    pass gen_yaml_unsafe_rejected
else
    fail gen_yaml_unsafe_rejected "exit $rc; gen.err='$(cat "$TMP/gen.err" 2> /dev/null)'; leftovers: $(ls "$MIRROR" "$TMP/u.yml" 2> /dev/null | tr '\n' ' ')"
fi

# Same generator with authd disabled (AUTHD="no"): DisableAuthdYaml() instead of the auth template.
rm -f "$MIRROR/src/init/gen_wazuh.sh"
sed 's/^  AUTHD="yes"$/  AUTHD="no"/' "$REPO/src/init/gen_wazuh.sh" > "$MIRROR/src/init/gen_wazuh.sh"
if grep -q 'AUTHD="no"' "$MIRROR/src/init/gen_wazuh.sh" \
    && gen "$MIRROR/src/init/gen_wazuh.sh" "$TMP/a.yml" "$TMP/a.conf" \
    && grep -q '<disabled>yes</disabled>' "$TMP/a.conf" \
    && "$CLI" --skip-file-checks validate -f "$TMP/a.yml" 2> "$TMP/err" \
    && [ "$(effective "$TMP/a.yml" auth.disabled)" = "true" ] \
    && [ "$(effective "$TMP/a.yml" auth.use_password)" = "false" ] \
    && [ "$(effective "$TMP/a.yml" auth.ssl_manager_cert)" = "etc/certs/remoted.pem" ]; then
    pass gen_authd_disabled
else
    fail gen_authd_disabled "gen.err='$(cat "$TMP/gen.err" 2> /dev/null)' err='$(cat "$TMP/err" 2> /dev/null)' yml: $(sed -n '/^auth:/,/^$/p' "$TMP/a.yml" 2> /dev/null)"
fi

echo "manager_conf_cli_test: $((TOTAL - FAILS))/$TOTAL passed"
[ "$FAILS" = 0 ]
