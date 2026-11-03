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

# A real in-place upgrade does NOT create etc/certs/root-ca.pem: 4.x never had one, and the
# upgrade only replaces binaries. The agent therefore resolves verification_mode to `none` and
# logs "TLS verification is DISABLED". That is the faithful default here, because it is what a
# migrated fleet actually looks like on first boot.
#
# MIGRATE_PLACE_ANCHOR=1 installs the lab CA at that path instead, so the same host comes up as
# `full` -- the other half of the ladder, on one container, without editing any configuration.
if [[ "${MIGRATE_PLACE_ANCHOR:-0}" == "1" ]]; then
    install -d -m 755 "$OSSEC/etc/certs"
    cp /lab-certs/root-ca.pem "$OSSEC/etc/certs/root-ca.pem"
    chmod 644 "$OSSEC/etc/certs/root-ca.pem"
    echo "[migrate] trust anchor placed at etc/certs/root-ca.pem -> expect verification_mode=full"
else
    echo "[migrate] no trust anchor, as an in-place upgrade leaves it -> expect verification_mode=none"
fi

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
