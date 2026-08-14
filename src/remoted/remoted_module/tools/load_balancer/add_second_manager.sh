#!/bin/bash
# Builds a SECOND remoted node under /var/wazuh-manager-2, listening on :1518.
#
# WHY NOT DOCKER: the installed manager tree is several GB (the engine binary alone is ~200 MB),
# so copying it or baking it into an image is disproportionate. Instead:
#   * the remoted binary is HARD LINKED (0 extra bytes, same filesystem). Its RUNPATH points at
#     absolute build paths, so it finds its libraries from any location.
#   * remoted resolves its home directory via /proc/self/exe, so a binary living in
#     /var/wazuh-manager-2/bin/ takes /var/wazuh-manager-2 as its home and chroots there.
#
# THE SECOND NODE HAS NO ENGINE, DELIBERATELY. Authentication happens BEFORE the request is
# forwarded downstream, which makes this node a clean authentication oracle:
#     503 -> the signature was ACCEPTED (only the downstream is missing)
#     401 -> the signature was REJECTED
# It also makes the two nodes tell themselves apart by status code, since node 1 answers 202.
set -euo pipefail

NODE1=/var/wazuh-manager
NODE2=/var/wazuh-manager-2
HERE="$(cd "$(dirname "$0")" && pwd)"
# Node 2 writes its own configuration, so it could name its certificates anything; it mirrors
# node 1's layout on purpose, so that every troubleshooting command in the README works verbatim
# against either node.
MANAGER_HOME="$NODE1"
source "$HERE/lib_manager_paths.sh"
PORT=1518
LEGACY_PORT=1519

[[ -d "$NODE1" ]] || { echo "no manager installed at $NODE1"; exit 1; }
[[ -f "$HERE/certs/manager_node2.crt" ]] || {
    echo "certificates missing; run ./generate_test_certificates.sh first"; exit 1; }

echo "==> creating the $NODE2 tree"
mkdir -p "$NODE2"/{bin,etc,logs,tmp}
mkdir -p "$NODE2"/var/{run,db,download,multigroups,upgrade}
mkdir -p "$NODE2"/queue/{sockets,db,diff,rids,cluster,agents-timestamp,tasks}

echo "==> hard linking the remoted binary (0 extra bytes)"
ln -f "$NODE1/bin/wazuh-manager-remoted" "$NODE2/bin/wazuh-manager-remoted"

echo "==> certificates: manager_node2 (into $MANAGER_CERT_REL, same layout as node 1)"
for rel in "$MANAGER_CERT_REL" "$MANAGER_KEY_REL" "$LAB_CA_REL"; do
    mkdir -p "$(dirname "$NODE2/$rel")"
done
cp "$HERE/certs/manager_node2.crt" "$NODE2/$MANAGER_CERT_REL"
cp "$HERE/certs/manager_node2.key" "$NODE2/$MANAGER_KEY_REL"
cp "$HERE/certs/ca.crt"            "$NODE2/$LAB_CA_REL"

echo "==> client.keys IDENTICAL to node 1 (this is what a cluster synchronises)"
cp "$NODE1/etc/client.keys" "$NODE2/etc/client.keys"

cp "$NODE1/etc/wazuh-manager-internal-options.conf" "$NODE2/etc/" 2>/dev/null || true
cp "$NODE1/etc/localtime" "$NODE2/etc/" 2>/dev/null || true

echo "==> own configuration, port $PORT"
cat > "$NODE2/etc/wazuh-manager.conf" <<CONFIG
<wazuh_config>
  <logging>
    <log_format>plain</log_format>
  </logging>

  <remote>
    <https>
      <port>${PORT}</port>
      <bind_addr>0.0.0.0</bind_addr>
      <certificate>${MANAGER_CERT_REL}</certificate>
      <key>${MANAGER_KEY_REL}</key>
      <ca>${LAB_CA_REL}</ca>
      <verification_mode>none</verification_mode>
    </https>

    <legacy>
      <port>${LEGACY_PORT}</port>
      <protocol>tcp</protocol>
      <local_ip>127.0.0.1</local_ip>
      <queue_size>131072</queue_size>
    </legacy>
  </remote>
</wazuh_config>
CONFIG

echo "==> rids files: remoted needs one per agent (legacy 1514 channel) or it dies with"
echo "    CRITICAL (1103) shortly after the listener comes up"
while read -r agent_id _; do
    [[ -n "$agent_id" ]] && : > "$NODE2/queue/rids/$agent_id"
done < "$NODE2/etc/client.keys"
: > "$NODE2/queue/rids/sender_counter"

echo "==> ownership and permissions"
chown -R wazuh-manager:wazuh-manager "$NODE2"
chmod 750 "$NODE2"
chmod 640 "$NODE2/$MANAGER_CERT_REL" "$NODE2/$MANAGER_KEY_REL" \
          "$NODE2/$LAB_CA_REL" "$NODE2"/etc/client.keys
chmod 770 "$NODE2"/queue/sockets "$NODE2"/logs "$NODE2"/var/run "$NODE2"/queue/rids

echo "==> starting node 2 (takes ~15 s: it retries wazuh-db before opening the listener)"
"$NODE2/bin/wazuh-manager-remoted" || true

for _ in $(seq 1 60); do
    if ss -ltn 2>/dev/null | grep -q ":${PORT}"; then
        echo "==> node 2 listening:"
        ss -ltn 2>/dev/null | grep ":${PORT}" | sed 's/^/    /'
        echo
        echo "    Remember: it has no engine, so 503 means the signature was ACCEPTED."
        exit 0
    fi
    sleep 0.5
done

echo "==> node 2 never started listening. Log:"
tail -20 "$NODE2/logs/wazuh-manager.log" 2>/dev/null || echo "(no log)"
exit 1
