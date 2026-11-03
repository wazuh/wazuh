#!/usr/bin/env bash
# $1 agent name   $2 manager endpoint   $3 verification_mode   $4 enrollment password
#
# The endpoint carries no trailing slash on purpose: that selects the default prefix
# "wazuh-manager", which matches the managers' shipped <global_prefix>/wazuh-manager/.
# A trailing slash would be the explicit opt-out and every route would answer 404.
set -euo pipefail
NAME="$1"; ENDPOINT="$2"; VMODE="$3"; PASS="$4"
OSSEC=/var/ossec
CONF="$OSSEC/etc/ossec.conf"

echo "[agent5] $NAME -> $ENDPOINT (verification_mode=$VMODE)"

# Modes that probe the shipped default instead of configuring one:
#   stock         no <ssl> block, no anchor on disk  -> the ladder's last rung
#   stock-anchor  no <ssl> block, anchor IS on disk  -> the rung above it
# Both exist to test what the agent does when the operator configures NOTHING, which is
# where docs/ref/modules/client/configuration.md and the implementation disagree.
printf '%s\n' "$PASS" > "$OSSEC/etc/authd.pass"
chmod 640 "$OSSEC/etc/authd.pass"
chown root:wazuh "$OSSEC/etc/authd.pass" 2>/dev/null || true

install -d -m 755 "$OSSEC/etc/lab"
cp /lab-certs/root-ca.pem "$OSSEC/etc/lab/root-ca.pem"
chmod 644 "$OSSEC/etc/lab/root-ca.pem"

if [[ "$VMODE" == "stock-anchor" ]]; then
    # AGENT_ANCHOR_CA is etc/certs/root-ca.pem (src/shared/include/defs.h:298).
    install -d -m 755 "$OSSEC/etc/certs"
    cp /lab-certs/root-ca.pem "$OSSEC/etc/certs/root-ca.pem"
    chmod 644 "$OSSEC/etc/certs/root-ca.pem"
    echo "[agent5] trust anchor placed at etc/certs/root-ca.pem, no <ssl> block configured"
fi

if [[ "$VMODE" == stock* ]]; then
    python3 - "$CONF" "$NAME" "$ENDPOINT" <<'PY2'
import re, sys
path, name, endpoint = sys.argv[1:4]
s = open(path).read()
block = f"""  <agent>
    <manager>
      <endpoint>{endpoint}</endpoint>
    </manager>
    <enrollment>
      <enabled>yes</enabled>
      <agent_name>{name}</agent_name>
      <authorization_pass_path>/var/ossec/etc/authd.pass</authorization_pass_path>
    </enrollment>
  </agent>"""
s = re.sub(r'[ \t]*<agent>.*?</agent>', block, s, count=1, flags=re.S)
open(path, 'w').write(s)
PY2
    echo "[agent5] ---- effective <agent> block (no <ssl>) ----"
    sed -n '/<agent>/,/<\/agent>/p' "$CONF"
    "$OSSEC/bin/wazuh-control" start || true
    sleep 4
    tail -F "$OSSEC/logs/ossec.log"
    exit 0
fi

python3 - "$CONF" "$NAME" "$ENDPOINT" "$VMODE" <<'PY'
import re, sys
path, name, endpoint, vmode = sys.argv[1:5]
s = open(path).read()
block = f"""  <agent>
    <manager>
      <endpoint>{endpoint}</endpoint>
    </manager>
    <enrollment>
      <enabled>yes</enabled>
      <agent_name>{name}</agent_name>
      <authorization_pass_path>/var/ossec/etc/authd.pass</authorization_pass_path>
    </enrollment>
    <ssl>
      <certificate_authorities>/var/ossec/etc/lab/root-ca.pem</certificate_authorities>
      <verification_mode>{vmode}</verification_mode>
    </ssl>
  </agent>"""
s = re.sub(r'[ \t]*<agent>.*?</agent>', block, s, count=1, flags=re.S)
open(path, 'w').write(s)
PY

echo "[agent5] ---- effective <agent> block ----"
sed -n '/<agent>/,/<\/agent>/p' "$CONF"

"$OSSEC/bin/wazuh-control" start || true
sleep 4
tail -F "$OSSEC/logs/ossec.log"
