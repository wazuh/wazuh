#!/bin/sh
# manager_conf_cli_test.sh — end-to-end checks of bin/wazuh-manager-conf over the vectors and over the
# XML configuration the installer generates (src/init/gen_wazuh.sh -> WriteManager()). Runs from ctest
# as `manager_config_cli`.
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
GEN="$VALID/generated-manager.conf"

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

rc=$(run "$CLI" validate -f "$INVALID/true-false-boolean.conf")
if [ "$rc" = 1 ] && grep -q '(1244)' "$TMP/err" && grep -q '/auth/use_password' "$TMP/err"; then
    pass cli_validate_invalid
else
    fail cli_validate_invalid "exit $rc; err='$(cat "$TMP/err")'"
fi

rc=$(run "$CLI" validate -f "$INVALID/raw-ampersand.conf")
if [ "$rc" = 1 ] && grep -q "raw '&'" "$TMP/err" && grep -q 'line' "$TMP/err"; then
    pass cli_validate_raw_ampersand
else
    fail cli_validate_raw_ampersand "exit $rc; err='$(cat "$TMP/err")'"
fi

rc=$(run "$CLI" validate -f "$TMP/does-not-exist.conf")
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

rc=$(run "$CLI" --skip-file-checks -f "$VALID/minimal-cluster.conf" dump)
if [ "$rc" = 0 ] && grep -q '"remote"' "$TMP/out" && grep -q '"cluster"' "$TMP/out" \
    && [ "$(effective "$VALID/minimal-cluster.conf" wdb.backup.global.interval)" = "1d" ]; then
    pass cli_dump_defaults
else
    fail cli_dump_defaults "exit $rc; interval='$(effective "$VALID/minimal-cluster.conf" wdb.backup.global.interval)'"
fi

mkdir -p "$TMP/home/etc"
cp "$GEN" "$TMP/home/etc/wazuh-manager.conf"
rc=$( (export WAZUH_MANAGER_HOME="$TMP/home"; "$CLI" --skip-file-checks validate > "$TMP/out" 2> "$TMP/err"; echo $?) )
if [ "$rc" = 0 ]; then
    pass cli_default_home
else
    fail cli_default_home "exit $rc; err='$(cat "$TMP/err")'"
fi

# ------------------------------------------------------- installer output ------------------------------------
# The file the installer generates must pass the strict loader untouched (deviation matrix §1: no
# installer input can produce non-well-formed XML). Scratch mirror: gen_wazuh.sh resolves ./etc relative
# to <script>/../..
MIRROR="$TMP/repo"
mkdir -p "$MIRROR/src/init"
ln -s "$REPO/etc" "$MIRROR/etc"
[ -f "$REPO/VERSION.json" ] && ln -s "$REPO/VERSION.json" "$MIRROR/VERSION.json"
for script in "$REPO"/src/init/*.sh; do
    ln -s "$script" "$MIRROR/src/init/$(basename "$script")"
done

# gen <conf-out> [VAR=value ...]: the manager configuration goes to stdout.
gen() {
    conf_out="$1"; shift
    (
        cd "$MIRROR" || exit 2
        for assignment in "$@"; do
            export "$assignment"
        done
        sh src/init/gen_wazuh.sh conf manager ubuntu 24.04 /var/wazuh-manager > "$conf_out" 2> "$TMP/gen.err"
    )
}

if gen "$TMP/w.conf" \
    && [ -s "$TMP/w.conf" ] \
    && "$CLI" --skip-file-checks validate -f "$TMP/w.conf" 2> "$TMP/err" \
    && key=$(effective "$TMP/w.conf" cluster.key) && [ "$(printf '%s' "$key" | wc -c)" = 32 ] \
    && [ ! -e "$MIRROR/wazuh.conf.temp" ]; then
    pass gen_conf_validates_strict
else
    fail gen_conf_validates_strict "gen.err='$(cat "$TMP/gen.err" 2> /dev/null)' err='$(cat "$TMP/err" 2> /dev/null)' key='${key:-}'"
fi

if gen "$TMP/v.conf" \
    WAZUH_REMOTE_LEGACY_PROTOCOL=tcp,udp WAZUH_REMOTE_HTTPS_BIND_ADDR=0.0.0.0 WAZUH_REMOTE_HTTPS_DUAL_STACK=yes \
    WAZUH_REMOTE_LEGACY_RIDS_CLOSING_TIME=10m WAZUH_REMOTE_HTTPS_MAX_BODY_SIZE=2M \
    && "$CLI" --skip-file-checks validate -f "$TMP/v.conf" 2> "$TMP/err" \
    && [ "$(effective "$TMP/v.conf" remote.legacy.protocol)" = '["tcp","udp"]' ] \
    && [ "$(effective "$TMP/v.conf" remote.https.dual_stack)" = "true" ] \
    && [ "$(effective "$TMP/v.conf" remote.https.bind_addr)" = "0.0.0.0" ] \
    && [ "$(effective "$TMP/v.conf" remote.legacy.rids_closing_time)" = "10m" ] \
    && [ "$(effective "$TMP/v.conf" remote.https.max_body_size)" = "2M" ]; then
    pass gen_remote_vars_roundtrip
else
    fail gen_remote_vars_roundtrip "gen.err='$(cat "$TMP/gen.err" 2> /dev/null)' err='$(cat "$TMP/err" 2> /dev/null)' remote: $(sed -n '/<remote>/,/<\/remote>/p' "$TMP/v.conf" 2> /dev/null | tr '\n' ' ')"
fi

# An XML metacharacter in a free-text installer variable is rejected by CheckRemoteXmlSafe before any
# file is written: the generator can never emit non-well-formed XML.
gen "$TMP/u.conf" 'WAZUH_REMOTE_HTTPS_CIPHERS=a&b'
rc=$?
if [ "$rc" != 0 ] && grep -q 'WAZUH_REMOTE_HTTPS_CIPHERS' "$TMP/gen.err" \
    && [ ! -e "$MIRROR/wazuh.conf.temp" ] && [ ! -s "$TMP/u.conf" ]; then
    pass gen_xml_unsafe_rejected
else
    fail gen_xml_unsafe_rejected "exit $rc; gen.err='$(cat "$TMP/gen.err" 2> /dev/null)'; leftovers: $(ls "$MIRROR" 2> /dev/null | tr '\n' ' ')"
fi

echo "manager_conf_cli_test: $((TOTAL - FAILS))/$TOTAL passed"
[ "$FAILS" = 0 ]