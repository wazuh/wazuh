#!/bin/bash
# Switches <remote><https><verification_mode> on manager node 1 and restarts remoted.
#
# Usage: ./set_manager_verification_mode.sh none|certificate|full|<any other value>
#
#   none         remoted does not ask the client for a certificate (the default)
#   certificate  remoted asks for one and checks it against <ca>
#   full         same, plus the certificate must carry the address the connection came from,
#                as a subjectAltName. Behind a proxy that address is the PROXY's, so the
#                certificate the manager sees must be the proxy's own -- see the README section
#                on TLS termination before using this one.
#
# Those are the three modes remoted supports. Any other value is accepted by this script on
# purpose -- writing one in is how the suite checks that an unsupported value is ignored with a
# warning instead of taking the listener down.
#
# <ca> is inserted alongside, because 'certificate' is unusable without a CA to validate
# agent certificates against.
#
# NOTE ON THE RESTART: this lives in a script file on purpose. A 'pkill -f
# wazuh-manager-remoted' typed on a command line also kills the shell running it, because that
# shell's own command line contains the pattern. The pattern is also scoped to node 1's full
# path, since both nodes share the binary name.
set -euo pipefail

MODE="${1:?usage: $0 none|certificate|full|<any other value, to test rejection>}"

HERE="$(cd "$(dirname "$0")" && pwd)"
MANAGER_HOME=/var/wazuh-manager
source "$HERE/lib_manager_paths.sh"

CONFIG="$MANAGER_HOME/etc/wazuh-manager.conf"
CA_LINE="      <ca>${LAB_CA_REL}</ca>"
MODE_LINE="      <verification_mode>${MODE}</verification_mode>"

python3 - "$CONFIG" "$CA_LINE" "$MODE_LINE" <<'PYTHON'
import re
import sys

config_path, ca_line, mode_line = sys.argv[1], sys.argv[2], sys.argv[3]
with open(config_path) as handle:
    text = handle.read()

# Drop any previous <ca>/<verification_mode> and re-insert both right after <key>.
text = re.sub(r'^\s*<ca>.*</ca>\n', '', text, flags=re.M)
text = re.sub(r'^\s*<verification_mode>.*</verification_mode>\n', '', text, flags=re.M)
text = re.sub(r'(^\s*<key>.*</key>\n)', r'\1' + ca_line + '\n' + mode_line + '\n',
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
        echo "==> remoted up with verification_mode=$MODE"
        exit 0
    fi
    sleep 0.5
done

echo "==> remoted never started listening. Log:"
tail -12 /var/wazuh-manager/logs/wazuh-manager.log
exit 1
