#!/bin/sh

# Copyright (C) Wazuh Inc.
#
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU
# General Public License (version 2) as published by the FSF - Free Software Foundation.

# WriteLogs (inst-functions.sh) writes the default <localfile> blocks of the agent configuration from
# etc/templates/config/generic/localfile-logs: the journald source when journalctl is available, one
# block per template line whose file exists, and the *.xml blocks whose <location> exists. The
# packages run it through add_localfiles.sh on fresh installs. Each case runs it on the shipped
# templates, with their /var/log paths moved under a scratch directory, and compares the whole output.
#
# Plain POSIX sh; CI runs it under dash and bash:
#   sh src/init/tests/test_write_logs.sh
#   bash src/init/tests/test_write_logs.sh

REPO=$(cd "$(dirname "$0")/../../.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

checks=0
failures=0

pass() { checks=$((checks + 1)); echo "  ok   $1"; }
fail() { checks=$((checks + 1)); failures=$((failures + 1)); echo "  FAIL $1: $2" >&2; }

# same <name> <expected> <actual>
same() {
    if [ "$2" = "$3" ]; then
        pass "$1"
    else
        fail "$1" "expected '$2', got '$3'"
    fi
}

LOG="$TMP/var/log"
INSTALL="$TMP/install"

# The shipped templates, reading the log files of the scratch host.
mkdir -p "$TMP/templates"
for template in "$REPO"/etc/templates/config/generic/localfile-logs/*; do
    sed -e "s|/var/log/|$LOG/|g" "$template" > "$TMP/templates/$(basename "$template")"
done

# Two PATHs with the tools WriteLogs uses, one of them with a journalctl.
for dir in no-journald journald; do
    mkdir -p "$TMP/bin-$dir"
    for tool in cat cut grep sed head; do
        ln -s "$(command -v $tool)" "$TMP/bin-$dir/$tool"
    done
done
printf '#!/bin/sh\n' > "$TMP/bin-journald/journalctl"
chmod +x "$TMP/bin-journald/journalctl"

# host <file>...: the scratch host has only these log files.
host() {
    rm -rf "$TMP/var"
    for file in "$@"; do
        mkdir -p "$(dirname "$LOG/$file")"
        : > "$LOG/$file"
    done
}

# write_logs <journald|no-journald> <add|echo> [blocks pattern]: what WriteLogs writes (add) or prints
# (echo), sourced from the repository root as the packages do.
write_logs() {
    rm -f "$TMP/ossec.conf"
    (
        cd "$REPO" && . ./src/init/inst-functions.sh
        LOCALFILES_TEMPLATE="$TMP/templates/*.template"
        LOCALFILES_BLOCKS="${3:-$TMP/templates/*.xml}"
        NEWCONFIG="$TMP/ossec.conf"
        INSTALLDIR="$INSTALL"
        PATH="$TMP/bin-$1"
        WriteLogs "$2"
    )
    [ "$2" = "add" ] && cat "$TMP/ossec.conf"
}

# blocks <block>...: the expected output, one blank line after each block (the trailing ones are
# dropped, as the command substitution of the actual output drops them).
blocks() {
    _sep=""
    for _block in "$@"; do
        printf '%s%s' "$_sep" "$_block"
        _sep='

'
    done
}

# localfile <format> <location>
localfile() {
    printf '  <localfile>\n    <log_format>%s</log_format>\n    <location>%s</location>\n  </localfile>' "$1" "$2"
}

journald=$(localfile journald journald)
active_responses=$(localfile syslog "$INSTALL/logs/active-responses.log")
apt="  <localfile>
    <log_format>multi-line-regex</log_format>
    <location>$LOG/apt/history.log</location>
    <multiline_regex match=\"end\" replace=\"wspace\" timeout=\"120\">^End-Date:</multiline_regex>
  </localfile>"
dnf="  <localfile>
    <log_format>syslog</log_format>
    <location>$LOG/dnf.log</location>
    <restrict>^\\S+ (DDEBUG Command: |WARNING |ERROR |CRITICAL )</restrict>
    <ignore>^\\S+ DDEBUG Command: dnf makecache</ignore>
    <ignore>^\\S+ WARNING (=+|WARNING:)\\s*\$</ignore>
  </localfile>"
dnf_rpm="  <localfile>
    <log_format>syslog</log_format>
    <location>$LOG/dnf.rpm.log</location>
    <ignore>--- logging initialized ---</ignore>
  </localfile>"

# ------------------------------------------------------------------------------- package managers
host dpkg.log apt/history.log auth.log
same "Debian family with journald" \
    "$(blocks "$journald" "$active_responses" "$(localfile syslog "$LOG/dpkg.log")" "$apt")" \
    "$(write_logs journald add)"

same "Debian family without journald" \
    "$(blocks "$active_responses" "$(localfile syslog "$LOG/auth.log")" "$(localfile syslog "$LOG/dpkg.log")" "$apt")" \
    "$(write_logs no-journald add)"

host dnf.log dnf.rpm.log audit/audit.log secure
same "Red Hat family with journald" \
    "$(blocks "$journald" "$(localfile audit "$LOG/audit/audit.log")" "$active_responses" "$dnf" "$dnf_rpm")" \
    "$(write_logs journald add)"

same "Red Hat family without journald" \
    "$(blocks "$(localfile audit "$LOG/audit/audit.log")" "$active_responses" "$(localfile syslog "$LOG/secure")" \
        "$dnf" "$dnf_rpm")" \
    "$(write_logs no-journald add)"

host
same "No package manager logs" "$(blocks "$journald" "$active_responses")" "$(write_logs journald add)"

# The installer summary leaves the package manager logs out, as it does with dpkg.log.
host dpkg.log apt/history.log dnf.log dnf.rpm.log syslog
same "Installer summary" "    -- $LOG/syslog" "$(write_logs no-journald echo)"

# ------------------------------------------------------------------------------------- *.xml blocks
mkdir -p "$TMP/blocks"
printf '  <localfile>\n    <location>%s</location>\n  </localfile>' "$LOG/no-eol.log" > "$TMP/blocks/no-eol.xml"
printf '  <localfile>\n  </localfile>\n' > "$TMP/blocks/no-location.xml"
host no-eol.log
same "Block without a final newline" \
    "$(blocks "$journald" "$active_responses" "  <localfile>
    <location>$LOG/no-eol.log</location>
  </localfile>")" \
    "$(write_logs journald add "$TMP/blocks/*.xml")"

same "No blocks" "$(blocks "$journald" "$active_responses")" \
    "$(write_logs journald add "$TMP/empty/*.xml" 2>&1)"

# Every shipped block is one <localfile> with one <location>, and multi-line-regex comes with its regex.
for block in "$REPO"/etc/templates/config/generic/localfile-logs/*.xml; do
    name=$(basename "$block")
    same "$name opens <localfile>" "  <localfile>" "$(head -n 1 "$block")"
    same "$name closes <localfile>" "  </localfile>" "$(sed -n '$p' "$block")"
    same "$name has one <location>" 1 "$(grep -c '<location>.*</location>' "$block")"
    if grep -q '<log_format>multi-line-regex</log_format>' "$block"; then
        same "$name has its <multiline_regex>" 1 "$(grep -c '<multiline_regex' "$block")"
    fi
done

# ------------------------------------------------------------------------------- add_localfiles.sh
# The packages run it with the installation directory and append its output to ossec.conf. The blocks
# depend on this host's log files, so only the wrapper and the installation directory are checked.
add_localfiles=$(sh "$REPO/src/init/add_localfiles.sh" "$INSTALL")
same "add_localfiles.sh opens <ossec_config>" "<ossec_config>" "$(printf '%s\n' "$add_localfiles" | sed -n 2p)"
same "add_localfiles.sh closes <ossec_config>" "</ossec_config>" "$(printf '%s\n' "$add_localfiles" | tail -n 1)"
case "$add_localfiles" in
    *"$active_responses"*) pass "add_localfiles.sh uses the installation directory" ;;
    *) fail "add_localfiles.sh uses the installation directory" "no '$INSTALL/logs/active-responses.log' block" ;;
esac
same "add_localfiles.sh removes its temporary file" no "$([ -e "$REPO/localfiles.temp" ] && echo yes || echo no)"

echo "test_write_logs: $((checks - failures))/$checks passed"
[ "$failures" = 0 ]
