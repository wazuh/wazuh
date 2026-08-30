#!/bin/bash
# Switches remote.https.verification_mode on manager node 1 and restarts remoted.
#
# Usage: ./set_manager_verification_mode.sh none|certificate|full|<any other value>
#
#   none         remoted does not ask the client for a certificate (the default)
#   certificate  remoted asks for one and checks it against remote.https.ca
#   full         same, plus the certificate must carry the address the connection came from,
#                as a subjectAltName. Behind a proxy that address is the PROXY's, so the
#                certificate the manager sees must be the proxy's own -- see the README section
#                on TLS termination before using this one.
#
# Those are the three modes remoted supports. Any other value is accepted by this script on
# purpose -- writing one in is how the suite checks that an unsupported value is REJECTED at
# config parse time (remoted refuses to start and -t names it; the parser hardening made a typo
# fatal instead of silently disabling certificate verification).
#
# remote.https.ca is set alongside, because 'certificate' is unusable without a CA to validate
# agent certificates against.
#
# NOTE ON THE RESTART: this lives in a script file on purpose. A 'pkill -f
# wazuh-manager-remoted' typed on a command line also kills the shell running it, because that
# shell's own command line contains the pattern. The pattern is also scoped to node 1's full
# path, since both nodes share the binary name.
set -euo pipefail

MODE="${1:?usage: $0 none|certificate|full|<any other value, to test rejection>}"

HERE="$(cd "$(dirname "$0")" && pwd)"
MANAGER_HOME="${MANAGER_HOME:-/var/wazuh-manager}"
source "$HERE/lib_manager_paths.sh"

# etc/wazuh-manager.yml: remote.https.ca and remote.https.verification_mode, whatever their
# previous values (an invalid mode is written as-is, see above).
set_https_options ca="$LAB_CA_REL" verification_mode="$MODE"

echo "==> configuration now:"
show_https | sed 's/^/    /'

pkill -f "$MANAGER_HOME/bin/[w]azuh-manager-remoted" 2>/dev/null || true
sleep 2
"$MANAGER_HOME/bin/wazuh-manager-remoted"

for _ in $(seq 1 40); do
    if ss -ltn 2>/dev/null | grep -q ':1517'; then
        echo "==> remoted up with verification_mode=$MODE"
        exit 0
    fi
    sleep 0.5
done

echo "==> remoted never started listening. Log:"
tail -12 "$MANAGER_HOME/logs/wazuh-manager.log"
exit 1
