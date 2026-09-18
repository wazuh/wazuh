#!/usr/bin/env bash
# Simulates an IN-PLACE 4.x -> 5.x upgrade: the 5.x binaries, but the ossec.conf and
# client.keys the 4.x agent had. An upgrade never rewrites ossec.conf, so this is exactly
# what a migrated host looks like on first boot.
set -euo pipefail
OSSEC=/var/ossec
# Supplied at run time by the operator: the client.keys line of the 4.x agent being
# migrated. Never committed -- it is a live credential.
if [[ ! -s /migrate/legacy.keys ]]; then
    echo "[migrate] /migrate/legacy.keys is missing. Copy the 4.x agent's client.keys line into it." >&2
    exit 1
fi
cp /migrate/legacy.keys "$OSSEC/etc/client.keys"
chown root:wazuh "$OSSEC/etc/client.keys" 2>/dev/null || true
chmod 640 "$OSSEC/etc/client.keys"

python3 - "$OSSEC/etc/ossec.conf" <<'PY'
import re, sys
path = sys.argv[1]
s = open(path).read()
# The 4.x shape, verbatim: deprecated <client><server><address>/<port>, no <agent> block.
legacy = """  <client>
    <server>
      <address>wazuh-lb-haproxy</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <notify_time>20</notify_time>
    <time-reconnect>60</time-reconnect>
  </client>"""
s = re.sub(r'[ \t]*<agent>.*?</agent>', legacy, s, count=1, flags=re.S)
open(path, 'w').write(s)
PY
echo "[migrate] effective client block:"
sed -n '/<client>/,/<\/client>/p' "$OSSEC/etc/ossec.conf"
"$OSSEC/bin/wazuh-control" start || true
sleep 5
tail -F "$OSSEC/logs/ossec.log"
