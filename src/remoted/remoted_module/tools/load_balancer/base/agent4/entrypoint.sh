#!/usr/bin/env bash
# $1 agent name   $2 manager address (the balancer)   $3 enrollment password
set -euo pipefail
NAME="$1"; MGR="$2"; PASS="$3"
OSSEC=/var/ossec

echo "[agent4] $NAME -> $MGR (legacy 1514, enrollment 1515)"

# 4.x reads the password from this file when <enrollment> does not carry it inline.
printf '%s\n' "$PASS" > "$OSSEC/etc/authd.pass"
chmod 640 "$OSSEC/etc/authd.pass"; chown root:wazuh "$OSSEC/etc/authd.pass" 2>/dev/null || true

python3 - "$OSSEC/etc/ossec.conf" "$MGR" "$NAME" <<'PY' 2>/dev/null || \
sed -i "s|<address>.*</address>|<address>${MGR}</address>|" "$OSSEC/etc/ossec.conf"
import re, sys
path, mgr, name = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(path).read()
s = re.sub(r'<address>.*?</address>', f'<address>{mgr}</address>', s, count=1)
block = (f"<enrollment><enabled>yes</enabled><manager_address>{mgr}</manager_address>"
         f"<port>1515</port><agent_name>{name}</agent_name></enrollment>")
if '<enrollment>' in s:
    s = re.sub(r'<enrollment>.*?</enrollment>', block, s, count=1, flags=re.S)
else:
    s = s.replace('</client>', block + '\n  </client>', 1)
open(path, 'w').write(s)
PY

"$OSSEC/bin/wazuh-control" start || true
sleep 3
echo "[agent4] ---- status ----"
"$OSSEC/bin/wazuh-control" status || true
tail -F "$OSSEC/logs/ossec.log"
