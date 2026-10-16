#!/bin/sh

# Copyright (C) Wazuh Inc.
#
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU
# General Public License (version 2) as published by the FSF - Free Software Foundation.

# The manager packages run the configuration generator (gen_wazuh.sh with shared.sh and
# inst-functions.sh), dist-detect.sh and the framework/API wrappers on hosts that may not have sed,
# grep or awk, so those scripts read and substitute text with the shell alone. Each case here runs the
# shell helper beside the sed/grep/awk/cut command it replaced, on the same input, and requires the
# same output: the old command is the oracle, so the equivalence is checked on every run.
#
# Plain POSIX sh; CI runs it under dash and bash:
#   sh src/init/tests/test_installer_text_tools.sh
#   bash src/init/tests/test_installer_text_tools.sh

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

# Each helper file is sourced from the repository root, as gen_wazuh.sh and the packages do, in a
# subshell so that its top-level code (it detects this host) cannot leak between cases.
in_repo() { (cd "$REPO" && "$@"); }

# ------------------------------------------------------------------------ ReplaceAll / SubstituteFile
substitute() { . ./src/init/inst-functions.sh; SubstituteFile "$@"; }

printf 'A x A\nfoo/A|bar\n\nA\n\n\n' > "$TMP/template"
printf 'no trailing newline: A' > "$TMP/template-no-eol"
for case_from_to in 'A|replaced' 'A|' 'x A|-' 'missing|never' 'A|${INSTALLDIR}' 'A|/var/wazuh-manager' \
                    'A|with space'; do
    from=${case_from_to%%|*}
    to=${case_from_to#*|}
    for template in "$TMP/template" "$TMP/template-no-eol"; do
        expected=$(sed -e "s|$from|$to|g" "$template"; echo x)
        actual=$(in_repo substitute "$template" "$from" "$to"; echo x)
        same "substitute '$from' -> '$to' in $(basename "$template")" "$expected" "$actual"
    done
done

# Several pairs apply in turn, like several -e expressions.
expected=$(sed -e 's|A|B|g' -e 's|B|C|g' "$TMP/template"; echo x)
actual=$(in_repo substitute "$TMP/template" A B B C; echo x)
same "substitute pairs in order" "$expected" "$actual"

# The header the generator writes, for the three version forms.
header() { DIST_NAME=$1 DIST_VER=$2 DIST_SUBVER=$3; . ./src/init/inst-functions.sh; SetHeaders Manager; }
for form in 'rhel 0 0|rhel ' 'rhel 9 0|rhel 9' 'rhel 9 4|rhel 9.4' 'ubuntu 24 04|ubuntu 24.04'; do
    # shellcheck disable=SC2086
    actual=$(in_repo header ${form%%|*} | sed -n 2p)
    same "header for '${form%%|*}'" "  Wazuh - Manager - Default configuration for ${form#*|}" "$actual"
done

# ---------------------------------------------------------------------------------- dist-detect.sh
dist() { . ./src/init/dist-detect.sh; "$@"; }

for version_id in 24.04 22.04 12 9.4 9 8.10 2023 2 15.5 3.20.3 rolling "" v1.2 15-SP5.1 1a22.3 10.0.1; do
    expected=$(echo $version_id | sed -rn 's/[^0-9]*([0-9]+).*/\1/p')
    same "DistNumber '$version_id'" "$expected" "$(in_repo dist DistNumber "$version_id")"
    expected=$(echo $version_id | sed -rn 's/[^0-9]*[0-9]+\.([0-9]+).*/\1/p')
    same "DistMinor '$version_id'" "$expected" "$(in_repo dist DistMinor "$version_id")"
done

n=0
while IFS= read -r release; do
    n=$((n + 1))
    printf '%s\n' "$release" > "$TMP/release-$n"
    expected=$(sed -rn 's/.* ([0-9]{1,2})\.*[0-9]{0,2}.*/\1/p' "$TMP/release-$n")
    same "ReleaseNumber major '$release'" "$expected" "$(in_repo dist ReleaseNumber "$TMP/release-$n" major)"
    expected=$(sed -rn 's/.* [0-9]{1,2}\.*([0-9]{0,2}).*/\1/p' "$TMP/release-$n")
    same "ReleaseNumber minor '$release'" "$expected" "$(in_repo dist ReleaseNumber "$TMP/release-$n" minor)"
    expected=$(sed -rn 's/.* ([0-9]{1,2}) .*/\1/p' "$TMP/release-$n")
    same "FedoraNumber '$release'" "$expected" "$(in_repo dist FedoraNumber "$TMP/release-$n")"
done <<'EOF'
CentOS Linux release 7.9.2009 (Core)
CentOS Stream release 9
CentOS release 6.10 (Final)
Red Hat Enterprise Linux release 9.4 (Plow)
Red Hat Enterprise Linux Server release 7.9 (Maipo)
Fedora release 39 (Thirty Nine)
Rocky Linux release 8.10 (Green Obsidian)
AlmaLinux release 9.4 (Seafoam Ocelot)
Oracle Linux Server release 8.9
release 123 build 4
no numbers here
1 2 3 4
EOF

# Several lines: one result per matching line, as sed printed them.
printf 'CentOS release 6.10 (Final)\nno digits\nFedora release 39 (x)\n' > "$TMP/release-multi"
same "ReleaseNumber over several lines" \
    "$(sed -rn 's/.* ([0-9]{1,2})\.*[0-9]{0,2}.*/\1/p' "$TMP/release-multi")" \
    "$(in_repo dist ReleaseNumber "$TMP/release-multi" major)"

# The fallbacks for hosts without /etc/os-release (lsb-release, Gentoo, SuSE, Arch, Debian, Slackware,
# Darwin and the BSDs, reached by the agent's installers too) read files and `uname -r` line by line,
# as `sed -rn 's/.../\1/p'` did. Every filter runs on every input below beside the sed expression it
# replaced: the release files and `uname -r` forms of those systems, odd values, several lines, and a
# last line without its newline.
n=0
while IFS= read -r line; do
    n=$((n + 1))
    printf '%s\n' "$line" > "$TMP/lines-$n"
done <<'EOF'
24.04
22.04
16.04
8.04.1
10.10
12.34.56
a 22.04 b 18.10
2004
rolling

12.5
11.9
8.11
10
bookworm/sid
trixie/sid
Gentoo Base System release 2.14
Gentoo Base System release 2.7
Gentoo Base System release 123.4
release 1.2 and 3.45 and 6.7
x 1.
x 12.345
Slackware 15.0
Slackware 14.2
Slackware 15.0+
Slackware 8.1.1
Slackware current
SUSE Linux Enterprise Server 12 (x86_64)
VERSION = 12
VERSION = 123
VERSION = 42.3
VERSION = 13.2
PATCHLEVEL = 5
XVERSION = 5 VERSION = 7
VERSION = 1.2 VERSION = 34.56
VERSION = x
6.8.9-arch1-1
5.15.0-105-generic
2.6.32-754.el6.x86_64
23.4.0
14.0-RELEASE-p6
7.5
10.0
6.4-RELEASE
v1.2
15-SP5.1
1a22.3
EOF
printf 'SUSE Linux Enterprise Server 11 (x86_64)\nVERSION = 11\nPATCHLEVEL = 4\n' > "$TMP/lines-suse-11"
printf 'openSUSE 13.2 (x86_64)\nVERSION = 13.2\nCODENAME = Harlequin\n' > "$TMP/lines-opensuse-13"
printf 'Gentoo Base System release 2.14\nno digits\nSlackware 15.0\n24.04 and 22.10\n' > "$TMP/lines-several"
printf 'VERSION = 12\nPATCHLEVEL = 3' > "$TMP/lines-no-eol"

dist_stdin() { _input=$1; shift; . ./src/init/dist-detect.sh; "$@" < "$_input"; }

# lines_like <sed expression> <filter and arguments...>: one check per filter, every input compared.
lines_like() {
    _expr=$1
    shift
    _bad=""
    for _input in "$TMP"/lines-*; do
        _expected=$(sed -rn "$_expr" "$_input"; echo x)
        _actual=$(in_repo dist_stdin "$_input" "$@"; echo x)
        if [ "$_expected" != "$_actual" ]; then
            _bad="$_bad $(basename "$_input"): expected '$_expected', got '$_actual';"
        fi
    done
    if [ -z "$_bad" ]; then
        pass "$* on $(ls "$TMP"/lines-* | wc -l | tr -d ' ') inputs"
    else
        fail "$*" "$_bad"
    fi
}

lines_like 's/[^0-9]*([0-9]+).*/\1/p' NumberLines major
lines_like 's/[^0-9]*[0-9]+\.([0-9]+).*/\1/p' NumberLines minor
lines_like 's/.*([0-9][0-9])\.[0-9][0-9].*/\1/p' PairLines major
lines_like 's/.*[0-9][0-9]\.([0-9][0-9]).*/\1/p' PairLines minor
lines_like 's/.* ([0-9]{1,2})\.[0-9]{1,2}.*/\1/p' DottedLines major 2
lines_like 's/.* [0-9]{1,2}\.([0-9]{1,2}).*/\1/p' DottedLines minor 2
lines_like 's/.* ([0-9]{1,2})\.[0-9].*/\1/p' DottedLines major 1
lines_like 's/.* [0-9]{1,2}\.([0-9]).*/\1/p' DottedLines minor 1
lines_like 's/.*VERSION = ([0-9]{1,2}).*/\1/p' MarkerLines "VERSION = "
lines_like 's/.*PATCHLEVEL = ([0-9]{1,2}).*/\1/p' MarkerLines "PATCHLEVEL = "
lines_like 's/.*VERSION = ([0-9]{1,2})\.([0-9]{1,2}).*/\1/p' MarkerLines "VERSION = " dotted

# ------------------------------------------------------------------------------------- shared.sh
values() { . ./src/init/shared.sh; "$@"; }
version_values() { . ./src/init/shared.sh; printf '%s %s' "$VERSION" "$REVISION"; }

same "VERSION and REVISION from VERSION.json" \
    "v$(awk -F'"' '/"version"[ \t]*:/ {print $4}' "$REPO/VERSION.json") $(awk -F'"' '/"stage"[ \t]*:/ {print $4}' "$REPO/VERSION.json")" \
    "$(in_repo version_values)"
printf '{\n\t"version"\t: "1.2.3",\n  "stage":"beta1"\n  "versionx": "no",\n  "version": 7\n}\n' > "$TMP/version.json"
for key in version stage versionx missing; do
    expected=$(awk -F'"' "/\"$key\"[ \\t]*:/ {print \$4}" "$TMP/version.json")
    same "JsonString '$key'" "$expected" "$(in_repo values JsonString "$TMP/version.json" "$key")"
done

printf 'nameserver 192.0.2.1\nnameserver\t192.0.2.2\n# nameserver 192.0.2.3\nnameserver  192.0.2.4 x\nnameservers 192.0.2.5\nsearch example.com\nnameserver 2001:db8::1 # c\n' \
    > "$TMP/resolv.conf"
tab=$(printf '\t')
same "LineFields by space" "$(grep "^nameserver" "$TMP/resolv.conf" | cut -d " " -sf 2)" \
    "$(in_repo values LineFields "$TMP/resolv.conf" nameserver " ")"
same "LineFields by tab" "$(grep "^nameserver" "$TMP/resolv.conf" | cut -sf 2)" \
    "$(in_repo values LineFields "$TMP/resolv.conf" nameserver "$tab")"

printf 'processor\t: 0\nmodel name\t: a processor\nprocessor\t: 1\nflags\t: fpu\n' > "$TMP/cpuinfo"
same "CountLines" "$(grep processor "$TMP/cpuinfo" | wc -l)" "$(in_repo values CountLines "$TMP/cpuinfo" processor)"

# -------------------------------------------------------------------------------------- wrappers
# A wrapper installed as bin/<name> runs <dir>/scripts/<name with - as _>.py with the bundled Python.
for wrapper in framework api; do
    home="$TMP/home-$wrapper"
    mkdir -p "$home/bin" "$home/$wrapper/scripts" "$home/framework/python/bin"
    cp "$REPO/$wrapper/wrappers/generic_wrapper.sh" "$home/bin/cluster-control-x"
    chmod +x "$home/bin/cluster-control-x"
    printf '#!/bin/sh\necho "$@"\n' > "$home/framework/python/bin/python3"
    chmod +x "$home/framework/python/bin/python3"
    : > "$home/$wrapper/scripts/cluster_control_x.py"
    same "$wrapper wrapper maps the name" "$home/$wrapper/scripts/cluster_control_x.py -l a" \
        "$("$home/bin/cluster-control-x" -l a)"
done

echo "test_installer_text_tools: $((checks - failures))/$checks passed"
[ "$failures" = 0 ]
