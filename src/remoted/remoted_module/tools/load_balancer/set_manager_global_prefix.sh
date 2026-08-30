#!/bin/bash
# Switches remote.https.global_prefix on manager node 1 and restarts remoted.
#
# Usage: ./set_manager_global_prefix.sh /wazuh-manager/ | / | <any value, to test rejection>
#
#   /wazuh-manager/   every endpoint is served under the prefix; the unprefixed paths 404.
#                       Agents (and this lab's probe) must send AND SIGN the prefixed target.
#   /                   explicit identity: endpoints served unprefixed (today's behavior).
#
# Any other value is passed through on purpose -- writing an invalid one (no leading slash,
# '//', bad characters...) is how the suite checks that remoted refuses to start with it
# ('wazuh-manager-remoted -t' reports the exact grammar error).
#
# NOTE ON THE RESTART: this lives in a script file on purpose. A 'pkill -f
# wazuh-manager-remoted' typed on a command line also kills the shell running it, because that
# shell's own command line contains the pattern. The pattern is also scoped to node 1's full
# path, since both nodes share the binary name.
set -euo pipefail

PREFIX="${1:?usage: $0 /wazuh-manager/ | / | <any value, to test rejection>}"

HERE="$(cd "$(dirname "$0")" && pwd)"
MANAGER_HOME="${MANAGER_HOME:-/var/wazuh-manager}"
source "$HERE/lib_manager_paths.sh"

# etc/wazuh-manager.yml: remote.https.global_prefix (an invalid value is written as-is, see above).
set_https_options global_prefix="$PREFIX"

echo "==> configuration now:"
show_https | sed 's/^/    /'

pkill -f "$MANAGER_HOME/bin/[w]azuh-manager-remoted" 2>/dev/null || true
sleep 2
"$MANAGER_HOME/bin/wazuh-manager-remoted"

for _ in $(seq 1 40); do
    if ss -ltn 2>/dev/null | grep -q ':1517'; then
        echo "==> remoted up with global_prefix=$PREFIX"
        exit 0
    fi
    sleep 0.5
done

echo "==> remoted never started listening. Log:"
tail -12 "$MANAGER_HOME/logs/wazuh-manager.log"
exit 1
