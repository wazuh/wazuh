#!/bin/sh

# Copyright (C) Wazuh Inc.
#
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU
# General Public License (version 2) as published by the FSF - Free Software Foundation.

# agent-etc-layout.sh, which every agent package and install.sh run as root to lock etc/ and move the
# credentials into etc/keys/. Runs unprivileged: chown is a stub that records its calls, everything
# else (chmod, mv, rm, find, head) is real and acts on a throwaway installation directory.
#
# Plain POSIX sh; CI runs it under dash and bash:
#   sh src/init/tests/test_agent_etc_layout.sh
#   bash src/init/tests/test_agent_etc_layout.sh

TARGET="$(cd "$(dirname "$0")/.." && pwd)/agent-etc-layout.sh"

# As root every file the harness creates belongs to root, and the cases that need one owned by
# another user cannot be set up.
if [ "$(id -u)" = "0" ]; then
    echo "Run this as an unprivileged user." >&2
    exit 1
fi
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
check "the key is handed to root before it moves" "yes" \
      "$([ "$(grep -cx "root:wazuh $DIR/etc/client.keys" "$CHOWN_LOG")" -ge 1 ] && echo yes)"
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
check "a link at the legacy key is reported" "1" "$(grep -c "$DIR/etc/client.keys was a link; removed it" "$DIR.stderr")"

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

# The secret goes with the key it was issued for.
new_dir
mkdir -p "$DIR/etc/keys"
: > "$DIR/etc/keys/client.keys"
echo "002 other" > "$DIR/etc/keys/reenroll.secret"
echo "001 agent any aaaa" > "$DIR/etc/client.keys"
echo "001 mine" > "$DIR/etc/reenroll.secret"
run_layout
check "a moved key brings its secret over the one in etc/keys" "001 agent any aaaa:001 mine:absent" \
      "$(cat "$DIR/etc/keys/client.keys"):$(cat "$DIR/etc/keys/reenroll.secret"):$([ -e "$DIR/etc/reenroll.secret" ] && echo present || echo absent)"

new_dir
mkdir -p "$DIR/etc/keys"
: > "$DIR/etc/keys/client.keys"
echo "002 other" > "$DIR/etc/keys/reenroll.secret"
echo "001 agent any aaaa" > "$DIR/etc/client.keys"
run_layout
check "a moved key without a secret drops the one in etc/keys" "001 agent any aaaa:absent" \
      "$(cat "$DIR/etc/keys/client.keys"):$([ -e "$DIR/etc/keys/reenroll.secret" ] && echo present || echo absent)"
check "and it says so" "1" "$(grep -c "Removed $DIR/etc/keys/reenroll.secret" "$DIR.stderr")"

new_dir
mkdir -p "$DIR/etc/keys"
echo "002 new any bbbb" > "$DIR/etc/keys/client.keys"
echo "001 agent any aaaa" > "$DIR/etc/client.keys"
echo "001 mine" > "$DIR/etc/reenroll.secret"
run_layout
check "a key left in etc/ keeps its secret beside it" "001 mine:absent" \
      "$(cat "$DIR/etc/reenroll.secret"):$([ -e "$DIR/etc/keys/reenroll.secret" ] && echo present || echo absent)"

new_dir
mkdir -p "$DIR/etc/keys/reenroll.secret"
echo "001 mine" > "$DIR/etc/reenroll.secret"
run_layout
check "a directory at the new secret is not moved into" "001 mine:empty" \
      "$(cat "$DIR/etc/reenroll.secret"):$([ -z "$(ls -A "$DIR/etc/keys/reenroll.secret")" ] && echo empty)"

new_dir
mkdir -p "$DIR/etc/keys/client.keys"
echo "001 agent any aaaa" > "$DIR/etc/client.keys"
run_layout
check "a directory at the new key is not moved into" "001 agent any aaaa:empty" \
      "$(cat "$DIR/etc/client.keys"):$([ -z "$(ls -A "$DIR/etc/keys/client.keys")" ] && echo empty)"

# Without mv -T the key is left for wazuh-agentd, which moves it at start; nothing is moved by name.
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
check "without mv -T the key stays and the link's target is untouched" "001 agent any aaaa:empty" \
      "$(cat "$DIR/etc/client.keys"):$([ -z "$(ls -A "$DIR/elsewhere")" ] && echo empty)"
check "without mv -T it says so" "1" "$(grep -c "wazuh-agentd tries again when it starts" "$DIR.stderr")"

new_dir
echo "x" > "$DIR/held"
ln "$DIR/held" "$DIR/etc/linked.conf"
PATH="$TMP/bsd:$TMP/bin:$PATH" sh "$TARGET" "$DIR" wazuh wazuh 2> "$DIR.stderr"
check "without mv -T a hard-linked file still gets its own copy" "1:1" \
      "$(stat -c %h "$DIR/etc/linked.conf"):$(stat -c %h "$DIR/held")"

# --- other files in etc/ ----------------------------------------------------------------------------
new_dir
echo "<ossec_config/>" > "$DIR/queue-owned"
rm -f "$DIR/etc/ossec.conf"
ln "$DIR/queue-owned" "$DIR/etc/ossec.conf"
run_layout
check "a hard-linked ossec.conf gets its own copy" "1:1" "$(stat -c %h "$DIR/etc/ossec.conf"):$(stat -c %h "$DIR/queue-owned")"
check "the stage is removed" "" "$(ls -A "$DIR/etc" | grep '^\.etc-layout')"

new_dir
mkdir -p "$DIR/etc/.etc-layout.Ab12Cd"
echo x > "$DIR/etc/.etc-layout.Ab12Cd/copy"
run_layout
check "a stage an interrupted run left is removed" "absent" \
      "$([ -e "$DIR/etc/.etc-layout.Ab12Cd" ] && echo present || echo absent)"

new_dir
echo "victim" > "$DIR/victim"
ln "$DIR/victim" "$DIR/victim.other"
echo "x" > "$DIR/held"
ln "$DIR/held" "$DIR/etc/a
victim"
# The second half of the name would resolve against the working directory (/ for dpkg).
(cd "$DIR" && run_layout)
check "a name with a newline is copied whole" "1:2" \
      "$(stat -c %h "$DIR/etc/a
victim"):$(stat -c %h "$DIR/victim")"

new_dir
cat > "$TMP/bin/head" <<'EOF2'
#!/bin/sh
exit 1
EOF2
chmod +x "$TMP/bin/head"
echo "x" > "$DIR/held"
ln "$DIR/held" "$DIR/etc/linked.conf"
run_layout
rm -f "$TMP/bin/head"
check "a hard-linked file that cannot be copied is kept" "x:x:2" \
      "$(cat "$DIR/etc/linked.conf"):$(cat "$DIR/held"):$(stat -c %h "$DIR/held")"
check "it is made root's in place, its group kept" "1" "$(grep -cx "root $DIR/etc/linked.conf" "$CHOWN_LOG")"
check "a failed copy is reported" "1" "$(grep -c "could not be copied; made it root's in place" "$DIR.stderr")"

# Both names of one file in etc/: neither is lost when the copy fails.
new_dir
cat > "$TMP/bin/head" <<'EOF2'
#!/bin/sh
exit 1
EOF2
chmod +x "$TMP/bin/head"
ln "$DIR/etc/ossec.conf" "$DIR/etc/ossec.conf.bak"
run_layout
rm -f "$TMP/bin/head"
check "two names of one file both survive a failed copy" "<ossec_config/>:<ossec_config/>" \
      "$(cat "$DIR/etc/ossec.conf"):$(cat "$DIR/etc/ossec.conf.bak")"
check "and lose group write" "-rw-r-----" "$(mode_of "$DIR/etc/ossec.conf")"

new_dir
cat > "$TMP/bin/mktemp" <<'EOF2'
#!/bin/sh
exit 1
EOF2
chmod +x "$TMP/bin/mktemp"
echo "x" > "$DIR/held"
ln "$DIR/held" "$DIR/etc/linked.conf"
run_layout
rm -f "$TMP/bin/mktemp"
check "without a stage it says so" "1" "$(grep -c "Could not create a staging directory" "$DIR.stderr")"
check "without a stage a hard-linked file is made root's in place" "1:x" \
      "$(grep -cx "root $DIR/etc/linked.conf" "$CHOWN_LOG"):$(cat "$DIR/etc/linked.conf")"

# --- files in etc/ others could write ---------------------------------------------------------------
# A descriptor opened for writing before the run must not reach the file root reads afterwards.
new_dir
exec 3>> "$DIR/etc/ossec.conf"
run_layout
echo "<injected/>" >&3
exec 3>&-
check "a descriptor held open on ossec.conf no longer reaches it" "<ossec_config/>" "$(cat "$DIR/etc/ossec.conf")"
check "its copy is handed to root in the stage" "1" "$(grep -c "^root:wazuh $DIR/etc/\.etc-layout\.[^/]*/copy$" "$CHOWN_LOG")"
check "its copy is not reported" "" "$(cat "$DIR.stderr")"

new_dir
printf '#!/bin/sh\nexit 1\n' > "$TMP/bin/head"
chmod +x "$TMP/bin/head"
run_layout
rm -f "$TMP/bin/head"
check "a file that cannot be copied is made root's in place" "1:-rw-r-----" \
      "$(grep -cx "root:wazuh $DIR/etc/ossec.conf" "$CHOWN_LOG"):$(mode_of "$DIR/etc/ossec.conf")"

new_dir
echo "#!/bin/sh" > "$DIR/held"
chmod 6775 "$DIR/held"
ln "$DIR/held" "$DIR/etc/run.sh"
run_layout
check "a copy is never setuid or setgid, nor writable by others" "-rwxr-xr-x" "$(mode_of "$DIR/etc/run.sh")"

# The copy is bounded: what it reads may have been swapped for a FIFO or a device.
new_dir
cat > "$TMP/bin/timeout" <<'EOF2'
#!/bin/sh
echo "$*" >> "$CHOWN_LOG.timeout"
shift
exec "$@"
EOF2
chmod +x "$TMP/bin/timeout"
run_layout
rm -f "$TMP/bin/timeout"
check "the copy runs under a timeout, at most one byte past the limit" "30 head -c 67108865 -- $DIR/etc/ossec.conf" \
      "$(cat "$CHOWN_LOG.timeout")"

new_dir
printf '#!/bin/sh\necho 67108865\n' > "$TMP/bin/wc"
chmod +x "$TMP/bin/wc"
echo "x" > "$DIR/held"
ln "$DIR/held" "$DIR/etc/linked.conf"
run_layout
rm -f "$TMP/bin/wc"
check "a copy past the limit is not used" "2:1" \
      "$(stat -c %h "$DIR/held"):$(grep -cx "root $DIR/etc/linked.conf" "$CHOWN_LOG")"

# --- links in etc/ ----------------------------------------------------------------------------------
new_dir
echo "<ossec_config>agent</ossec_config>" > "$DIR/agent-owned"
chmod 0666 "$DIR/agent-owned"
rm -f "$DIR/etc/ossec.conf"
ln -s ../agent-owned "$DIR/etc/ossec.conf"
run_layout
check "a link to a file others can change is replaced by a copy" "file:<ossec_config>agent</ossec_config>" \
      "$([ -f "$DIR/etc/ossec.conf" ] && [ ! -L "$DIR/etc/ossec.conf" ] && echo file):$(cat "$DIR/etc/ossec.conf")"
check "the copy loses group and other write" "-rw-r--r--" "$(mode_of "$DIR/etc/ossec.conf")"
check "the link's target is untouched" "1:-rw-rw-rw-" "$(stat -c %h "$DIR/agent-owned"):$(mode_of "$DIR/agent-owned")"
check "the replaced link is reported" "1" "$(grep -c "ossec.conf led to a file users other than root can change; replaced it with a copy" "$DIR.stderr")"

new_dir
ln -s /etc/passwd "$DIR/etc/local_internal_options.conf"
ln -s /etc/agent-layout-test-missing "$DIR/etc/missing.conf"
run_layout
check "a link to a file only root can change is kept" "link:link" \
      "$([ -L "$DIR/etc/local_internal_options.conf" ] && echo link):$([ -L "$DIR/etc/missing.conf" ] && echo link)"
check "a kept link is not reported" "" "$(cat "$DIR.stderr")"

new_dir
ln -s ../gone "$DIR/etc/dangling.conf"
mkfifo "$DIR/fifo"
ln -s ../fifo "$DIR/etc/fifo.conf"
mkdir "$DIR/somedir"
ln -s ../somedir "$DIR/etc/linked-dir"
run_layout
check "a link to a missing file others could create is removed" "absent" \
      "$([ -L "$DIR/etc/dangling.conf" ] && echo present || echo absent)"
check "a link to something other than a file is removed" "absent:fifo" \
      "$([ -L "$DIR/etc/fifo.conf" ] && echo present || echo absent):$([ -p "$DIR/fifo" ] && echo fifo)"
check "a link to a directory others can change is left alone" "link" "$([ -L "$DIR/etc/linked-dir" ] && echo link)"
check "but it is reported" "1" "$(grep -c "linked-dir leads to a directory users other than root can change; left it in place" "$DIR.stderr")"

new_dir
mkdir "$DIR/agent-dir"
rm -rf "$DIR/etc/shared" "$DIR/etc/certs"
ln -s ../agent-dir "$DIR/etc/shared"
ln -s /etc "$DIR/etc/certs"
run_layout
check "a link at etc/shared, and one to a directory only root can change, are kept" "link:link" \
      "$([ -L "$DIR/etc/shared" ] && echo link):$([ -L "$DIR/etc/certs" ] && echo link)"
check "neither is reported" "" "$(cat "$DIR.stderr")"

# Every step of the way counts, not only where it ends: a link or directory others own on the way
# could be re-pointed afterwards.
new_dir
ln -s /etc/passwd "$DIR/hop"
rm -f "$DIR/etc/ossec.conf"
ln -s "$DIR/hop" "$DIR/etc/ossec.conf"
ln -s /etc "$DIR/etc-dir"
ln -s "$DIR/etc-dir/passwd" "$DIR/etc/local_internal_options.conf"
run_layout
check "a link to a link others can change is replaced by a copy" "file:link" \
      "$([ -f "$DIR/etc/ossec.conf" ] && [ ! -L "$DIR/etc/ossec.conf" ] && echo file):$([ -L "$DIR/hop" ] && echo link)"
check "so is a link through a directory link others can change" "file" \
      "$([ -f "$DIR/etc/local_internal_options.conf" ] && [ ! -L "$DIR/etc/local_internal_options.conf" ] && echo file)"
check "both copies hold the file at the end" "yes" \
      "$(cmp -s "$DIR/etc/ossec.conf" /etc/passwd && cmp -s "$DIR/etc/local_internal_options.conf" /etc/passwd && echo yes)"

new_dir
cat > "$TMP/bin/head" <<'EOF2'
#!/bin/sh
exit 1
EOF2
chmod +x "$TMP/bin/head"
echo "x" > "$DIR/agent-owned"
ln -s ../agent-owned "$DIR/etc/extra.conf"
run_layout
rm -f "$TMP/bin/head"
check "a link that cannot be copied is removed, its target kept" "absent:x" \
      "$([ -L "$DIR/etc/extra.conf" ] && echo present || echo absent):$(cat "$DIR/agent-owned")"
check "and it says so" "1" "$(grep -c "extra.conf led to a file users other than root can change; removed the link" "$DIR.stderr")"

# --- the result -------------------------------------------------------------------------------------
new_dir
cat > "$TMP/bin/chmod" <<EOF2
#!/bin/sh
[ "\$2" = "$DIR/etc" ] && exit 1
exec /bin/chmod "\$@"
EOF2
chmod +x "$TMP/bin/chmod"
run_layout
rm -f "$TMP/bin/chmod"
check "an etc/ that could not be locked fails the run" "1" "$RUN_STATUS"
check "and it says so" "1" "$(grep -c "WARNING: $DIR/etc could not be locked" "$DIR.stderr")"

new_dir
cat > "$TMP/bin/chmod" <<'EOF2'
#!/bin/sh
[ "$1" = "go-w" ] && exit 1
exec /bin/chmod "$@"
EOF2
printf '#!/bin/sh\nexit 1\n' > "$TMP/bin/head"
chmod +x "$TMP/bin/chmod" "$TMP/bin/head"
run_layout
rm -f "$TMP/bin/chmod" "$TMP/bin/head"
check "a file that stays writable does not fail the run" "0" "$RUN_STATUS"
check "but it is reported" "1" "$(grep -c "WARNING: $DIR/etc/ossec.conf is still writable by users other than root" "$DIR.stderr")"

# --- leftovers in etc/ ------------------------------------------------------------------------------
new_dir
echo x > "$DIR/etc/client.keys.Ab12Cd"
echo x > "$DIR/etc/reenroll.secret.Zz99Yy"
echo x > "$DIR/etc/client.keys.save"
run_layout
check "staged copies the agent left are removed" "absent:absent" \
      "$([ -e "$DIR/etc/client.keys.Ab12Cd" ] && echo present || echo absent):$([ -e "$DIR/etc/reenroll.secret.Zz99Yy" ] && echo present || echo absent)"
check "other names are kept" "present" "$([ -e "$DIR/etc/client.keys.save" ] && echo present || echo absent)"
check "ossec.conf and client.keys.save are handed to root as copies" "2:0" \
      "$(grep -c "^root:wazuh $DIR/etc/\.etc-layout\.[^/]*/copy$" "$CHOWN_LOG"):$(grep -c "client.keys.save" "$CHOWN_LOG")"

new_dir
mkdir -p "$DIR/etc/keys"
echo x > "$DIR/etc/keys/client.keys.Old111"
touch -d '5 minutes ago' "$DIR/etc/keys/client.keys.Old111"
echo x > "$DIR/etc/keys/reenroll.secret.New222"
run_layout
check "old staged copies in etc/keys are removed, a fresh one is kept" "absent:present" \
      "$([ -e "$DIR/etc/keys/client.keys.Old111" ] && echo present || echo absent):$([ -e "$DIR/etc/keys/reenroll.secret.New222" ] && echo present || echo absent)"

new_dir
mkdir -p "$DIR/etc/keys"
echo x > "$DIR/etc/keys/client.keys.rpmnew"
touch -d '5 minutes ago' "$DIR/etc/keys/client.keys.rpmnew"
run_layout
check "rpm's client.keys.rpmnew in etc/keys is kept" "present" \
      "$([ -e "$DIR/etc/keys/client.keys.rpmnew" ] && echo present || echo absent)"

echo
echo "${checks} checks, ${failures} failed"
[ "${failures}" -eq 0 ]
