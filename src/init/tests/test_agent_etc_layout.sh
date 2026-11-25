#!/bin/sh

# Copyright (C) Wazuh Inc.
#
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU
# General Public License (version 2) as published by the FSF - Free Software Foundation.

# agent-etc-layout.sh, which every agent package and install.sh run as root to lock etc/ and move the
# credentials into etc/keys/. Runs unprivileged: chown is a stub that records its calls, everything
# else (chmod, mv, rm, find) is real and acts on a throwaway installation directory.
#
# Plain POSIX sh; CI runs it under dash and bash:
#   sh src/init/tests/test_agent_etc_layout.sh
#   bash src/init/tests/test_agent_etc_layout.sh

TARGET="$(cd "$(dirname "$0")/.." && pwd)/agent-etc-layout.sh"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

checks=0
failures=0

pass() { checks=$((checks + 1)); echo "ok   - $1"; }
fail() { checks=$((checks + 1)); failures=$((failures + 1)); echo "FAIL - $1: $2" >&2; }

# check <name> <expected> <actual>
check() {
    if [ "$2" = "$3" ]; then
        pass "$1"
    else
        fail "$1" "expected '$2', got '$3'"
    fi
}

mkdir -p "$TMP/bin"
cat > "$TMP/bin/chown" <<'EOF'
#!/bin/sh
echo "$*" >> "$CHOWN_LOG"
EOF
chmod +x "$TMP/bin/chown"

mode_of() { ls -ld "$1" | cut -c1-10; }

# new_dir: a fresh installation directory laid out like an older package left it.
new_dir() {
    DIR="$TMP/case$checks"
    rm -rf "$DIR"
    mkdir -p "$DIR/etc/shared" "$DIR/etc/certs"
    chmod 0770 "$DIR/etc"
    printf '<ossec_config/>\n' > "$DIR/etc/ossec.conf"
    chmod 0660 "$DIR/etc/ossec.conf"
    CHOWN_LOG="$DIR.chown"
    : > "$CHOWN_LOG"
    export CHOWN_LOG
}

run_layout() {
    PATH="$TMP/bin:$PATH" sh "$TARGET" "$DIR" wazuh wazuh 2> "$DIR.stderr"
    RUN_STATUS=$?
}

# --- the directories -------------------------------------------------------------------------------
new_dir
run_layout
check "exits 0" "0" "$RUN_STATUS"
check "etc/ becomes 0750" "drwxr-x---" "$(mode_of "$DIR/etc")"
check "etc/ is handed to root" "1" "$(grep -cx "root:wazuh $DIR/etc" "$CHOWN_LOG")"
check "etc/keys is created 0770, not sticky" "drwxrwx---" "$(mode_of "$DIR/etc/keys")"
check "etc/keys is handed to root" "1" "$(grep -cx "root:wazuh $DIR/etc/keys" "$CHOWN_LOG")"
check "a group-writable ossec.conf loses group write" "-rw-r-----" "$(mode_of "$DIR/etc/ossec.conf")"
check "etc/certs is left alone" "0" "$(grep -c "etc/certs" "$CHOWN_LOG")"
check "nothing to report" "" "$(cat "$DIR.stderr")"

: > "$CHOWN_LOG"
run_layout
check "a second run changes no mode" "drwxr-x---:drwxrwx---" "$(mode_of "$DIR/etc"):$(mode_of "$DIR/etc/keys")"
check "a second run reports nothing" "" "$(cat "$DIR.stderr")"

new_dir
rm -rf "$DIR/etc"
run_layout
check "no etc/ is a no-op" "0:absent" "$RUN_STATUS:$([ -e "$DIR/etc" ] && echo present || echo absent)"

new_dir
mkdir "$DIR/elsewhere"
rm -rf "$DIR/etc"
ln -s elsewhere "$DIR/etc"
run_layout
check "a linked etc/ is not followed" "0:0" "$RUN_STATUS:$(wc -l < "$CHOWN_LOG" | tr -d ' ')"

new_dir
mkdir "$DIR/target"
ln -s ../target "$DIR/etc/keys"
run_layout
check "a link at etc/keys is replaced by a directory" "dir" "$([ -d "$DIR/etc/keys" ] && [ ! -L "$DIR/etc/keys" ] && echo dir)"
check "the link's target is untouched" "drwxr-xr-x" "$(mode_of "$DIR/target")"

new_dir
echo "not a directory" > "$DIR/etc/keys"
run_layout
check "a file at etc/keys is replaced by a directory" "dir" "$([ -d "$DIR/etc/keys" ] && echo dir)"

# --- client.keys ------------------------------------------------------------------------------------
new_dir
echo "001 agent any aaaa" > "$DIR/etc/client.keys"
run_layout
check "a legacy key is moved" "001 agent any aaaa" "$(cat "$DIR/etc/keys/client.keys")"
check "the legacy path is gone" "absent" "$([ -e "$DIR/etc/client.keys" ] && echo present || echo absent)"
check "the key is handed to root before it moves" "1" "$(grep -cx "root:wazuh $DIR/etc/client.keys" "$CHOWN_LOG")"
check "nothing in etc/keys is changed by name" "0" "$(grep -c "$DIR/etc/keys/" "$CHOWN_LOG")"
check "the moved key is 0640" "-rw-r-----" "$(mode_of "$DIR/etc/keys/client.keys")"

new_dir
mkdir -p "$DIR/etc/keys"
: > "$DIR/etc/keys/client.keys"
echo "001 agent any aaaa" > "$DIR/etc/client.keys"
run_layout
check "a legacy key replaces the package's empty one" "001 agent any aaaa" "$(cat "$DIR/etc/keys/client.keys")"

new_dir
mkdir -p "$DIR/etc/keys"
echo "002 new any bbbb" > "$DIR/etc/keys/client.keys"
: > "$DIR/etc/client.keys"
run_layout
check "an empty legacy key is dropped" "absent:002 new any bbbb" \
      "$([ -e "$DIR/etc/client.keys" ] && echo present || echo absent):$(cat "$DIR/etc/keys/client.keys")"

new_dir
mkdir -p "$DIR/etc/keys"
echo "002 new any bbbb" > "$DIR/etc/keys/client.keys"
echo "001 agent any aaaa" > "$DIR/etc/client.keys"
run_layout
check "two keys: both are kept" "001 agent any aaaa:002 new any bbbb" \
      "$(cat "$DIR/etc/client.keys"):$(cat "$DIR/etc/keys/client.keys")"
check "two keys: it says so" "1" "$(grep -c "Both $DIR/etc/client.keys and $DIR/etc/keys/client.keys exist" "$DIR.stderr")"

new_dir
echo "secret" > "$DIR/outside"
ln -s ../outside "$DIR/etc/client.keys"
run_layout
check "a link at the legacy key is removed, not followed" "absent:absent:secret" \
      "$([ -e "$DIR/etc/client.keys" ] || [ -L "$DIR/etc/client.keys" ] && echo present || echo absent):$([ -s "$DIR/etc/keys/client.keys" ] && echo present || echo absent):$(cat "$DIR/outside")"

new_dir
echo "001 agent any aaaa" > "$DIR/other"
ln "$DIR/other" "$DIR/etc/client.keys"
run_layout
check "a hard-linked legacy key is moved as its own copy" "absent:001 agent any aaaa:1" \
      "$([ -e "$DIR/etc/client.keys" ] && echo present || echo absent):$(cat "$DIR/etc/keys/client.keys"):$(stat -c %h "$DIR/etc/keys/client.keys")"
check "its other name is left alone" "001 agent any aaaa:1" "$(cat "$DIR/other"):$(stat -c %h "$DIR/other")"
check "a hard-linked file is reported" "1" "$(grep -c "had more than one link; replaced it with its own copy" "$DIR.stderr")"

new_dir
mkdir -p "$DIR/etc/keys" "$DIR/elsewhere"
ln -s ../../elsewhere "$DIR/etc/keys/client.keys"
echo "001 agent any aaaa" > "$DIR/etc/client.keys"
run_layout
check "a link at the new key is replaced, not moved into" "file:empty" \
      "$([ -f "$DIR/etc/keys/client.keys" ] && [ ! -L "$DIR/etc/keys/client.keys" ] && echo file):$([ -z "$(ls -A "$DIR/elsewhere")" ] && echo empty)"

# --- reenroll.secret --------------------------------------------------------------------------------
new_dir
echo "001 0123" > "$DIR/etc/reenroll.secret"
run_layout
check "a legacy secret is moved" "001 0123" "$(cat "$DIR/etc/keys/reenroll.secret")"
check "the secret is handed to the agent before it moves" "1" "$(grep -cx "wazuh:wazuh $DIR/etc/reenroll.secret" "$CHOWN_LOG")"
check "the moved secret is 0640" "-rw-r-----" "$(mode_of "$DIR/etc/keys/reenroll.secret")"

new_dir
mkdir -p "$DIR/etc/keys"
echo "001 current" > "$DIR/etc/keys/reenroll.secret"
echo "001 stale" > "$DIR/etc/reenroll.secret"
run_layout
check "a stale legacy secret is dropped" "absent:001 current" \
      "$([ -e "$DIR/etc/reenroll.secret" ] && echo present || echo absent):$(cat "$DIR/etc/keys/reenroll.secret")"
check "a stale legacy secret is not reported" "" "$(cat "$DIR.stderr")"

# Without GNU mv -T (the BSDs), the link is removed and the key moved by name.
mkdir -p "$TMP/bsd"
cat > "$TMP/bsd/mv" <<'EOF2'
#!/bin/sh
case "$1" in -*T*) exit 1 ;; esac
exec /bin/mv "$@"
EOF2
chmod +x "$TMP/bsd/mv"
new_dir
mkdir -p "$DIR/etc/keys" "$DIR/elsewhere"
ln -s ../../elsewhere "$DIR/etc/keys/client.keys"
echo "001 agent any aaaa" > "$DIR/etc/client.keys"
PATH="$TMP/bsd:$TMP/bin:$PATH" sh "$TARGET" "$DIR" wazuh wazuh 2> "$DIR.stderr"
check "without mv -T a link at the new key is still replaced" "file:empty" \
      "$([ -f "$DIR/etc/keys/client.keys" ] && [ ! -L "$DIR/etc/keys/client.keys" ] && echo file):$([ -z "$(ls -A "$DIR/elsewhere")" ] && echo empty)"

# --- other files in etc/ ----------------------------------------------------------------------------
new_dir
echo "<ossec_config/>" > "$DIR/queue-owned"
rm -f "$DIR/etc/ossec.conf"
ln "$DIR/queue-owned" "$DIR/etc/ossec.conf"
run_layout
check "a hard-linked ossec.conf gets its own copy" "1:1" "$(stat -c %h "$DIR/etc/ossec.conf"):$(stat -c %h "$DIR/queue-owned")"

# --- leftovers in etc/ ------------------------------------------------------------------------------
new_dir
echo x > "$DIR/etc/client.keys.Ab12Cd"
echo x > "$DIR/etc/reenroll.secret.Zz99Yy"
echo x > "$DIR/etc/client.keys.save"
run_layout
check "staged copies the agent left are removed" "absent:absent" \
      "$([ -e "$DIR/etc/client.keys.Ab12Cd" ] && echo present || echo absent):$([ -e "$DIR/etc/reenroll.secret.Zz99Yy" ] && echo present || echo absent)"
check "other names are kept" "present" "$([ -e "$DIR/etc/client.keys.save" ] && echo present || echo absent)"
check "files in etc/ are handed to root" "1" "$(grep -c "^root:wazuh .*$DIR/etc/client.keys.save" "$CHOWN_LOG")"

new_dir
mkdir -p "$DIR/etc/keys"
echo x > "$DIR/etc/keys/client.keys.Old111"
touch -d '5 minutes ago' "$DIR/etc/keys/client.keys.Old111"
echo x > "$DIR/etc/keys/reenroll.secret.New222"
run_layout
check "old staged copies in etc/keys are removed, a fresh one is kept" "absent:present" \
      "$([ -e "$DIR/etc/keys/client.keys.Old111" ] && echo present || echo absent):$([ -e "$DIR/etc/keys/reenroll.secret.New222" ] && echo present || echo absent)"

echo
echo "${checks} checks, ${failures} failed"
[ "${failures}" -eq 0 ]
