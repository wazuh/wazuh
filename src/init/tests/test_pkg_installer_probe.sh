#!/bin/bash

# Copyright (C) Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Drives the manager probes of pkg_installer.sh: probe_server() with its TCP fallback,
# probe_server_verified() and probe_server_with_ca(). They are cut out of the real script and
# sourced together with the helpers they call. A stub curl models the two hosts whose curl rejects
# --tlsv1.3 (exit 4):
#
#   Amazon Linux 2        the same handshake without the option fails with 35 (the default model)
#   macOS                 the same handshake without the option succeeds, and with -v reports the
#                         TLS version it negotiated
#
# STUB_TLS13_RC, STUB_RETRY_RC and STUB_K_RC set what the stub answers, so each case picks its
# model; STUB_HANDSHAKE is what follows "* SSL connection using " on stderr when -v is given, and
# STUB_CALLS a file that gets each call's arguments. A local listener stands in for the manager.
#
#   ./test_pkg_installer_probe.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${SCRIPT_DIR}/../pkg_installer.sh"

failures=0
checks=0

WORK="$(mktemp -d)"
LISTENER_PID=""
trap '[ -n "${LISTENER_PID}" ] && kill "${LISTENER_PID}" 2>/dev/null; rm -rf "${WORK}"' EXIT

check() {

    local name="$1" expected="$2" actual="$3"

    checks=$(( checks + 1 ))
    if [ "${expected}" = "${actual}" ]; then
        echo "ok   - ${name}"
    else
        failures=$(( failures + 1 ))
        echo "FAIL - ${name}"
        echo "--- expected ---"
        echo "${expected}"
        echo "--- actual ---"
        echo "${actual}"
        echo "---"
    fi

}

sed -n '/^probe_build_target() {/,/^}/p;/^probe_curl() {/,/^}/p;/^probe_tls_version_ok() {/,/^}/p;/^probe_server() {/,/^}/p;/^probe_server_verified() {/,/^}/p;/^probe_system_store() {/,/^}/p;/^probe_server_with_ca() {/,/^}/p' "${TARGET}" > "${WORK}/probe.sh"

# With --tlsv1.3 the stub exits STUB_TLS13_RC (default 4, option rejected). Without it, STUB_RETRY_RC
# (default 35), or STUB_K_RC when the call also carries -k. A --cacert path that is not a file is
# a 99.
mkdir -p "${WORK}/bin" "${WORK}/logs" "${WORK}/ca dir"
: > "${WORK}/ca dir/ca.pem"
cat > "${WORK}/bin/curl" <<'STUB'
#!/bin/sh
[ -n "${STUB_CALLS}" ] && echo "$*" >> "${STUB_CALLS}"
tls13=0
k=0
v=0
prev=""
for arg in "$@"; do
    [ "${arg}" = "--tlsv1.3" ] && tls13=1
    [ "${arg}" = "-k" ] && k=1
    [ "${arg}" = "-v" ] && v=1
    [ "${prev}" = "--cacert" ] && [ ! -f "${arg}" ] && exit 99
    prev="${arg}"
done
[ ${tls13} -eq 1 ] && exit "${STUB_TLS13_RC:-4}"
if [ ${v} -eq 1 ]; then
    echo "*   Trying 127.0.0.1:1517..." >&2
    [ -n "${STUB_HANDSHAKE}" ] && echo "* SSL connection using ${STUB_HANDSHAKE}" >&2
    echo "* Connection #0 to host 127.0.0.1 left intact" >&2
fi
[ ${k} -eq 1 ] && [ -n "${STUB_K_RC}" ] && exit "${STUB_K_RC}"
exit "${STUB_RETRY_RC:-35}"
STUB
chmod +x "${WORK}/bin/curl"

python3 -c 'import socket, sys
s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(16)
print(s.getsockname()[1], flush=True)
while True:
    c, _ = s.accept(); c.close()' > "${WORK}/port" &
LISTENER_PID=$!
disown "${LISTENER_PID}"
for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ -s "${WORK}/port" ] && break
    sleep 0.2
done
PORT="$(cat "${WORK}/port")"

# A port nothing listens on: bind one, then close it.
CLOSED_PORT="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"

# $1 = function, $2 = host, $3 = port, $4 = shell code run before the probe, in the same shell.
# Prints the function's exit code. The CA path holds a space, and is a positional argument so the
# shell code cannot split it.
run_probe() {
    ( cd "${WORK}" && PATH="${WORK}/bin:${PATH}" bash -c ". ./probe.sh; $4
      $1 \"\$0\" \"\$1\" wazuh-manager \"\$2\"; echo \$?" "$2" "$3" "${WORK}/ca dir/ca.pem" 2>/dev/null )
}

# $1 = host, $2 = port, $3 = shell code run before the probe, in the same shell.
probe() {
    run_probe probe_server "$1" "$2" "$3"
}

# Empty the log, run the function and print "<exit code> <log lines matching the pattern>".
# $1 = function, $2 = shell code run before the probe, $3 = host, $4 = log pattern.
probe_and_log() {
    local rc
    : > "${WORK}/logs/upgrade.log"
    rc="$(run_probe "$1" "$3" "${PORT}" "$2")"
    echo "${rc} $(grep -c "$4" "${WORK}/logs/upgrade.log"; true)"
}

check "the fallback does not redirect onto a fixed fd" "" \
    "$(sed -n '/^probe_server() {/,/^}/p' "${TARGET}" | grep -E '[0-9]+<>[^&]*/dev/tcp')"

check "a reachable manager passes" "0" "$(probe 127.0.0.1 "${PORT}")"
check "the fallback is logged" "1" \
    "$(grep -c 'falling back to a TCP connectivity check' "${WORK}/logs/upgrade.log")"
check "a reachable manager named by host name passes" "0" "$(probe localhost "${PORT}")"
check "a reachable manager passes with fd 3 closed" "0" "$(probe localhost "${PORT}" 'exec 3<&-')"
check "a reachable manager passes with fd 3 already open" "0" \
    "$(probe localhost "${PORT}" 'exec 3</dev/null')"
check "a closed port fails" "1" "$(probe 127.0.0.1 "${CLOSED_PORT}")"
check "a name that does not resolve fails" "1" "$(probe no-such-host.invalid "${PORT}")"

# probe_server() with a curl that does TLS 1.3 once --tlsv1.3 is dropped (macOS).
FALLBACK='falling back to a TCP connectivity check'
TLS13_LINE='TLSv1.3 / AEAD-CHACHA20-POLY1305-SHA256 / [blank] / UNDEF'
TLS12_LINE='TLSv1.2 / ECDHE-RSA-AES256-GCM-SHA384 / [blank] / UNDEF'
MACOS_PASS="export STUB_RETRY_RC=0 STUB_HANDSHAKE='${TLS13_LINE}'"
MACOS_TLS12="export STUB_RETRY_RC=0 STUB_HANDSHAKE='${TLS12_LINE}'"
MACOS_NO_LINE='export STUB_RETRY_RC=0'
UNCONFIRMED='TLS 1.3 could not be confirmed'
check "macOS: the retry succeeds over TLS 1.3, so the manager passes with no fallback" "0 0" \
    "$(probe_and_log probe_server "${MACOS_PASS}" 127.0.0.1 "${FALLBACK}")"
check "macOS: a TLS 1.3 handshake line is not logged as unconfirmed" "0 0" \
    "$(probe_and_log probe_server "${MACOS_PASS}" 127.0.0.1 "${UNCONFIRMED}")"
check "macOS: a wrong prefix (22 on the retry) fails with no fallback" "22 0" \
    "$(probe_and_log probe_server 'export STUB_RETRY_RC=22' 127.0.0.1 "${FALLBACK}")"
# probe_server() with a curl that takes --tlsv1.3 (no retry).
check "a curl with TLS 1.3 passes with no fallback" "0 0" \
    "$(probe_and_log probe_server 'export STUB_TLS13_RC=0' 127.0.0.1 "${FALLBACK}")"
check "a curl with TLS 1.3 needs no version check" "0 0" \
    "$(probe_and_log probe_server 'export STUB_TLS13_RC=0' 127.0.0.1 "${UNCONFIRMED}")"
check "a handshake failure (35) without a retry fails and does not fall back" "35 0" \
    "$(probe_and_log probe_server 'export STUB_TLS13_RC=35' 127.0.0.1 "${FALLBACK}")"
check "a curl that does not know --tlsv1.3 at all (exit 2) retries the same way" "0 0" \
    "$(probe_and_log probe_server 'export STUB_TLS13_RC=2 STUB_RETRY_RC=0' 127.0.0.1 "${FALLBACK}")"

# The retry answers over a version the agent refuses, or reports none.
check "probe_server: TLS 1.2 on the retry fails" "1 1" \
    "$(probe_and_log probe_server "${MACOS_TLS12}" 127.0.0.1 'answered over TLSv1.2; the upgraded agent requires TLS 1.3')"
check "probe_server: TLS 1.2 on the retry does not fall back" "1 0" \
    "$(probe_and_log probe_server "${MACOS_TLS12}" 127.0.0.1 "${FALLBACK}")"
check "probe_server: TLS 1.1 on the retry fails" "1 1" \
    "$(probe_and_log probe_server "export STUB_RETRY_RC=0 STUB_HANDSHAKE='TLSv1.1 / X / Y / Z'" 127.0.0.1 'answered over TLSv1.1')"
check "probe_server: no handshake line passes and says the version could not be confirmed" "0 1" \
    "$(probe_and_log probe_server "${MACOS_NO_LINE}" 127.0.0.1 "${UNCONFIRMED}")"
check "probe_server: a handshake line without a version passes as unconfirmed" "0 1" \
    "$(probe_and_log probe_server "export STUB_RETRY_RC=0 STUB_HANDSHAKE='TLS_AES_256_GCM_SHA384'" 127.0.0.1 "${UNCONFIRMED}")"

# Any other failure of the retry leaves the TCP check to decide, and the log states the exit code.
for code in 35 52 56 28 7; do
    check "retry exit ${code} falls back to TCP and passes" "0 1" \
        "$(probe_and_log probe_server "export STUB_RETRY_RC=${code}" 127.0.0.1 "HTTPS check without --tlsv1.3 failed (curl exit ${code}), ${FALLBACK}")"
    check "retry exit ${code} names no cause in its own log" "0" \
        "$(grep -c "cannot negotiate" "${WORK}/logs/upgrade.log"; true)"
done
check "retry exit 28 with nothing listening still fails through the TCP check" "1" \
    "$(run_probe probe_server 127.0.0.1 "${CLOSED_PORT}" 'export STUB_RETRY_RC=28')"

# probe_server_verified() and probe_server_with_ca(). The log pattern is the line saying the HTTPS
# check without --tlsv1.3 failed.
NO_HTTPS='HTTPS check without --tlsv1.3 failed (curl exit 35), so the manager'"'"'s certificate could not be verified'
check "verified, macOS: the retry succeeds over TLS 1.3" "0 0" \
    "$(probe_and_log probe_server_verified "${MACOS_PASS}" 127.0.0.1 "${NO_HTTPS%%(curl exit*}")"
check "verified, macOS: TLS 1.2 on the retry fails" "1 1" \
    "$(probe_and_log probe_server_verified "${MACOS_TLS12}" 127.0.0.1 'answered over TLSv1.2; the upgraded agent requires TLS 1.3')"
check "verified, macOS: no handshake line passes as unconfirmed" "0 1" \
    "$(probe_and_log probe_server_verified "${MACOS_NO_LINE}" 127.0.0.1 "${UNCONFIRMED}")"
# Any exit code: a certificate verdict must not be reported as a failed HTTPS check.
ANY_FAILED_CHECK='certificate could not be verified'
for rc in 51 60 83; do
    check "verified, macOS: a certificate verdict (${rc} on the retry) is not logged as a failed check" "${rc} 0" \
        "$(probe_and_log probe_server_verified "export STUB_RETRY_RC=${rc}" 127.0.0.1 "${ANY_FAILED_CHECK}")"
done
check "verified, macOS: a refusal (7 on the retry) is logged with its exit code" "7 1" \
    "$(probe_and_log probe_server_verified 'export STUB_RETRY_RC=7' 127.0.0.1 'HTTPS check without --tlsv1.3 failed (curl exit 7), so the manager')"
check "verified, macOS: a timeout (28 on the retry) is logged with its exit code" "28 1" \
    "$(probe_and_log probe_server_verified 'export STUB_RETRY_RC=28' 127.0.0.1 'HTTPS check without --tlsv1.3 failed (curl exit 28), so the manager')"
check "verified, macOS: an HTTP error (22 on the retry) is not logged as a failed check" "22 0" \
    "$(probe_and_log probe_server_verified 'export STUB_RETRY_RC=22' 127.0.0.1 "${NO_HTTPS%%(curl exit*}")"
check "verified, AL2: 35 on the retry is logged with its exit code and stays fail-closed" "35 1" \
    "$(probe_and_log probe_server_verified '' 127.0.0.1 "${NO_HTTPS}")"
check "verified: 35 from a curl that takes --tlsv1.3 is not logged as a failed retry" "35 0" \
    "$(probe_and_log probe_server_verified 'export STUB_TLS13_RC=35' 127.0.0.1 "${NO_HTTPS}")"

NO_CHECK='HTTPS check without'
check "with CA, macOS: the CA verifies (0 on the retry)" "0 0" \
    "$(probe_and_log probe_server_with_ca "${MACOS_PASS}" 127.0.0.1 "${NO_CHECK}")"
check "with CA, macOS: the CA verifies (22 on the retry)" "0 0" \
    "$(probe_and_log probe_server_with_ca "export STUB_RETRY_RC=22 STUB_HANDSHAKE='${TLS13_LINE}'" 127.0.0.1 "${NO_CHECK}")"
check "with CA, macOS: TLS 1.2 on the retry is not the manager" "1 1" \
    "$(probe_and_log probe_server_with_ca "${MACOS_TLS12}" 127.0.0.1 'answered over TLSv1.2')"
check "with CA, macOS: TLS 1.2 behind an HTTP error (22) is not the manager" "1 1" \
    "$(probe_and_log probe_server_with_ca "export STUB_RETRY_RC=22 STUB_HANDSHAKE='${TLS12_LINE}'" 127.0.0.1 'answered over TLSv1.2')"
check "with CA, macOS: no handshake line passes as unconfirmed" "0 1" \
    "$(probe_and_log probe_server_with_ca "${MACOS_NO_LINE}" 127.0.0.1 "${UNCONFIRMED}")"
check "with CA, macOS: the CA does not verify (60 on the retry)" "1 0" \
    "$(probe_and_log probe_server_with_ca 'export STUB_RETRY_RC=60' 127.0.0.1 "${NO_CHECK}")"
check "with CA, macOS: 35 that succeeds with -k is a CA that does not verify" "1 0" \
    "$(probe_and_log probe_server_with_ca 'export STUB_RETRY_RC=35 STUB_K_RC=0' 127.0.0.1 "${NO_CHECK}")"
check "with CA, macOS: no answer (7 on the retry) could not tell" "2 0" \
    "$(probe_and_log probe_server_with_ca 'export STUB_RETRY_RC=7' 127.0.0.1 "${NO_CHECK}")"
check "with CA, AL2: 35 on the retry could not tell" "2 0" \
    "$(probe_and_log probe_server_with_ca '' 127.0.0.1 "${NO_CHECK}")"
check "with CA: a CA path holding a space reaches curl as one argument (else the stub answers 99)" "0" \
    "$(run_probe probe_server_with_ca 127.0.0.1 "${PORT}" "${MACOS_PASS}")"

# Whether the agent's 'system' store can be checked. A stub curl that verifies (0) stands for Apple's.
probe_system_store_case() {
    : > "${WORK}/logs/upgrade.log"
    : > "${WORK}/calls"
    ( cd "${WORK}" && PATH="${WORK}/bin:${PATH}" STUB_CALLS="${WORK}/calls" STUB_TLS13_RC=0 \
        bash -c ". ./probe.sh; OS=$1; SSL_VERIFICATION_MODE_EXPLICIT=$2
                probe_system_store 127.0.0.1 1 wazuh-manager; echo \$?" 2>/dev/null )
}
CANNOT_CHECK="cannot check the trust store the agent uses under 'system' on macOS"
check "macOS with an explicit system is unverified, whatever curl says" "1" "$(probe_system_store_case Darwin 1)"
check "macOS with an explicit system logs that the store cannot be checked" "1" \
    "$(grep -c "${CANNOT_CHECK}" "${WORK}/logs/upgrade.log")"
check "macOS with an explicit system does not ask curl" "0" "$(wc -l < "${WORK}/calls" | tr -d ' ')"
check "macOS with the mode unset keeps curl's verdict" "0" "$(probe_system_store_case Darwin 0)"
check "macOS with the mode unset does not log it" "0" "$(grep -c "${CANNOT_CHECK}" "${WORK}/logs/upgrade.log")"
check "Linux with an explicit system keeps curl's verdict" "0" "$(probe_system_store_case Linux 1)"
check "Linux with an explicit system does not log it" "0" "$(grep -c "${CANNOT_CHECK}" "${WORK}/logs/upgrade.log")"

# The -v output curl is asked for on the retry stays in a variable: stderr is upgrade.log.
probe_stderr() {
    ( cd "${WORK}" && PATH="${WORK}/bin:${PATH}" STUB_RETRY_RC=0 STUB_HANDSHAKE="${TLS13_LINE}" \
        bash -c ". ./probe.sh; $1 127.0.0.1 \"\$0\" wazuh-manager \"\$1\" >/dev/null" "${PORT}" "${WORK}/ca dir/ca.pem" 2>&1 >/dev/null )
}
for function in probe_server probe_server_verified probe_server_with_ca; do
    check "${function}: curl's -v output does not reach stderr" "" "$(probe_stderr "${function}")"
done

# The 'system' arm of the TLS gate, cut out of the script and driven with the real probes and the
# stub curl, which verifies (the system curl's verdict, 0). Stands in for the whole script, which
# cannot run as Darwin: it insists on /Library/Ossec.
{
    echo 'abort_upgrade() { echo "ABORT $1" >> ./logs/upgrade.log; exit 1; }'
    echo 'SERVER_ADDRESS=127.0.0.1; SERVER_PORT=1517; SERVER_ENDPOINT=wazuh-manager'
    echo 'DEFAULT_CA_FILE=./etc/certs/root-ca.pem; SSL_CA=""; CA_TOOL_HINT=""; IS_LEGACY_AGENT=0'
    echo 'SYSTEM_ABORT_ADVICE=advice; LEGACY_ADVICE=advice; CURRENT_AGENT_VERSION=4.14.7'
    echo 'case system in'
    sed -n '/^    system)$/,/^    none)$/p' "${TARGET}" | sed '$d'
    echo 'esac'
} > "${WORK}/gate.sh"
# $1 = OS, $2 = verification_mode explicit (1) or not (0), $3 = anchor available. Fills the log.
gate_case() {
    : > "${WORK}/logs/upgrade.log"
    ( cd "${WORK}" && PATH="${WORK}/bin:${PATH}" STUB_TLS13_RC=0 OS="$1" SSL_VERIFICATION_MODE_EXPLICIT="$2" \
        ANCHOR_AVAILABLE="$3" bash -c ". ./probe.sh; . ./gate.sh" > /dev/null 2>&1 )
}
gate_log() {
    grep -c -e "$1" "${WORK}/logs/upgrade.log"
}
gate_case Darwin 1 0
check "gate, macOS, explicit system: curl's verdict is not taken" "0" "$(gate_log 'already verifies')"
check "gate, macOS, explicit system with no anchor: aborts" "1" "$(gate_log 'ABORT 2')"
check "gate, macOS: the abort says the store was not checked" "1" "$(gate_log "explicitly 'system' but the system trust store was not checked, and no trust anchor")"
check "gate, macOS: the abort does not claim the store does not verify" "0" "$(gate_log 'does not verify')"
check "gate, macOS: the advice does not offer importing into the OS store" "0" "$(gate_log 'Import the manager')"
check "gate, macOS: the advice offers the anchor and certificate mode" "1" \
    "$(gate_log "Place the manager's CA at ./etc/certs/root-ca.pem and retry, or switch to <verification_mode>certificate")"
gate_case Darwin 1 1
check "gate, macOS, explicit system with an anchor: proceeds on the anchor" "1" \
    "$(gate_log "explicitly 'system' and the system trust store was not checked, but a trust anchor is present")"
check "gate, macOS, explicit system with an anchor: does not abort" "0" "$(gate_log 'ABORT')"
gate_case Darwin 0 0
check "gate, macOS, mode unset: curl's verdict is kept" "1" "$(gate_log 'already verifies')"
gate_case Linux 1 0
check "gate, Linux, explicit system: curl's verdict is kept" "1" "$(gate_log 'already verifies')"
: > "${WORK}/logs/upgrade.log"
( cd "${WORK}" && PATH="${WORK}/bin:${PATH}" STUB_TLS13_RC=60 OS=Linux SSL_VERIFICATION_MODE_EXPLICIT=1 ANCHOR_AVAILABLE=0 \
    bash -c ". ./probe.sh; . ./gate.sh" > /dev/null 2>&1 )
check "gate, Linux, explicit system, store does not verify: the abort keeps its wording" "1" \
    "$(gate_log "explicitly 'system' but the system trust store does not verify the manager's certificate at 127.0.0.1:1517, and no trust anchor")"
check "gate, Linux: the advice still offers importing into the OS store" "1" "$(gate_log 'Import the manager')"

# Whether --tlsv1.3 is detected once per run, not once per call.
count_calls() {
    grep -c -e "$1" "${WORK}/calls"
}
run_all_probes() {
    : > "${WORK}/calls"
    ( cd "${WORK}" && PATH="${WORK}/bin:${PATH}" STUB_CALLS="${WORK}/calls" bash -c "
        . ./probe.sh; $1
        probe_server 127.0.0.1 \"\$0\" wazuh-manager >/dev/null
        probe_server 127.0.0.1 \"\$0\" wazuh-manager >/dev/null
        probe_server_verified 127.0.0.1 \"\$0\" wazuh-manager
        probe_server_with_ca 127.0.0.1 \"\$0\" wazuh-manager \"\$1\"
        echo \$?" "${PORT}" "${WORK}/ca dir/ca.pem" 2>/dev/null )
}
# 35 on every retry: probe_server (--tlsv1.3 rejected, then the retry), probe_server again,
# verified, and a CA check that repeats the handshake with -k: six curl calls.
check "a host whose curl rejects --tlsv1.3 gets the verdict of the last probe" "1" \
    "$(run_all_probes 'export STUB_RETRY_RC=35 STUB_K_RC=0 STUB_HANDSHAKE="'"${TLS13_LINE}"'"')"
check "--tlsv1.3 is attempted exactly once per run" "1" "$(count_calls '^--tlsv1.3 ')"
check "every other call goes without it, asking for the handshake line" "5" "$(count_calls '^-v ')"
check "that is six curl calls in all" "6" "$(wc -l < "${WORK}/calls" | tr -d ' ')"
check "with a curl that takes --tlsv1.3 the CA check could not tell" "2" \
    "$(run_all_probes 'export STUB_TLS13_RC=35')"
check "and never asks for the handshake line" "0" "$(count_calls '^-v ')"
check "and every one of its five calls carries --tlsv1.3" "5" "$(count_calls '^--tlsv1.3 ')"

# A target that hangs: a listener that never accepts, its backlog filled so that the next connect is
# dropped. With neither curl nor wget the TCP check must give up after PROBE_TIMEOUT, return 1 and
# keep bash's "Killed" report off stderr (upgrade.log). Linux only: elsewhere a full backlog refuses.
if [ "$(uname -s)" = "Linux" ]; then
    mkdir -p "${WORK}/nobin"
    ln -sf "$(command -v sleep)" "${WORK}/nobin/sleep"
    ln -sf "$(command -v date)" "${WORK}/nobin/date"
    python3 -c 'import socket, time
s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(0)
held = []
while True:
    c = socket.socket(); c.settimeout(0.5)
    try:
        c.connect(s.getsockname())
        held.append(c)
    except OSError:
        c.close()
        break
print(s.getsockname()[1], flush=True)
time.sleep(600)' > "${WORK}/hang_port" &
    HANG_PID=$!
    disown "${HANG_PID}"
    for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
        [ -s "${WORK}/hang_port" ] && break
        sleep 0.2
    done
    HANG_PORT="$(cat "${WORK}/hang_port")"
    : > "${WORK}/logs/upgrade.log"
    ( cd "${WORK}" && PATH="${WORK}/nobin" "${BASH}" -c ". ./probe.sh; SECONDS=0
        probe_server 127.0.0.1 \"\$0\" wazuh-manager; echo \"\$? \${SECONDS}\"" "${HANG_PORT}" \
        > "${WORK}/hang_out" 2> "${WORK}/hang_err" )
    kill "${HANG_PID}" 2>/dev/null
    read -r HANG_RC HANG_SECONDS < "${WORK}/hang_out"
    check "a target that never accepts fails" "1" "${HANG_RC}"
    check "and nothing reaches stderr, no Killed report" "" "$(cat "${WORK}/hang_err")"
    check "and it waited out the whole PROBE_TIMEOUT, so the listener did block" "yes" \
        "$([ "${HANG_SECONDS:-0}" -ge 5 ] && echo yes || echo "no (${HANG_SECONDS:-none}s)")"
    check "and the fallback was logged" "1" \
        "$(grep -c 'Neither curl nor wget found, falling back to a TCP connectivity check' "${WORK}/logs/upgrade.log")"
fi

echo
echo "${checks} checks, ${failures} failed"
[ "${failures}" -eq 0 ]
