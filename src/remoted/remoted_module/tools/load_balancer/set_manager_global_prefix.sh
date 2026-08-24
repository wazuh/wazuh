#!/bin/bash
# Switches <remote><https><global_prefix> on manager node 1 and restarts remoted.
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

MANAGER_HOME=/var/wazuh-manager
CONFIG="$MANAGER_HOME/etc/wazuh-manager.conf"
PREFIX_LINE="      <global_prefix>${PREFIX}</global_prefix>"

python3 - "$CONFIG" "$PREFIX_LINE" <<'PYTHON'
import re
import sys

config_path, prefix_line = sys.argv[1], sys.argv[2]
with open(config_path) as handle:
    text = handle.read()

# Drop any previous <global_prefix> and re-insert right after <bind_addr> (the shipped
# ordering); fall back to right after <port> for a config without a bind_addr line.
text = re.sub(r'^\s*<global_prefix>.*</global_prefix>\n', '', text, flags=re.M)
if re.search(r'^\s*<bind_addr>.*</bind_addr>\n', text, flags=re.M):
    text = re.sub(r'(^\s*<bind_addr>.*</bind_addr>\n)', r'\1' + prefix_line + '\n',
                  text, count=1, flags=re.M)
else:
    text = re.sub(r'(^\s*<https>\n\s*<port>.*</port>\n)', r'\1' + prefix_line + '\n',
                  text, count=1, flags=re.M)

with open(config_path, 'w') as handle:
    handle.write(text)
PYTHON

echo "==> configuration now:"
sed -n '/<https>/,/<\/https>/p' "$CONFIG" | sed 's/^/    /'

pkill -f '/var/wazuh-manager/bin/[w]azuh-manager-remoted' 2>/dev/null || true
sleep 2
/var/wazuh-manager/bin/wazuh-manager-remoted

for _ in $(seq 1 40); do
    if ss -ltn 2>/dev/null | grep -q ':1517'; then
        echo "==> remoted up with global_prefix=$PREFIX"
        exit 0
    fi
    sleep 0.5
done

echo "==> remoted never started listening. Log:"
tail -12 /var/wazuh-manager/logs/wazuh-manager.log
exit 1
