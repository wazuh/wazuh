#!/usr/bin/env bash
# Manager node entrypoint.
#   $1 node name      (wazuh-master | wazuh-worker1 | wazuh-worker2)
#   $2 node type      (master | worker)
#   $3 master address (the address every node points its cluster link at)
#
# Everything this writes is per node ON PURPOSE. The whole point of the lab is that
# some state is NOT cluster-synchronised, so each node gets its own certificate, its
# own tree, and its own configuration, exactly like three real machines would.
set -euo pipefail

NODE_NAME="$1"
NODE_TYPE="$2"
MASTER_ADDR="$3"

DIR=/var/wazuh-manager
CONF="$DIR/etc/wazuh-manager.conf"

echo "[entrypoint] $NODE_NAME ($NODE_TYPE), master at $MASTER_ADDR"

# ---------------------------------------------------------------- certificates
# Mounted read-only at /lab-certs by the compose file. Each node has its OWN leaf,
# which is what a real deployment has: cluster.json does not replicate etc/certs/.
CERTSRC="/lab-certs/$NODE_NAME"
if [[ -d "$CERTSRC" ]]; then
    install -d -m 1770 -o root -g wazuh-manager "$DIR/etc/certs"
    install -o wazuh-manager -g wazuh-manager -m 640 "$CERTSRC/node.pem"     "$DIR/etc/certs/remoted.pem"
    install -o wazuh-manager -g wazuh-manager -m 640 "$CERTSRC/node-key.pem" "$DIR/etc/certs/remoted-key.pem"
    install -o root -g wazuh-manager -m 640 "/lab-certs/root-ca.pem"         "$DIR/etc/certs/root-ca.pem"
    echo "[entrypoint] listener certificate: $(openssl x509 -in "$DIR/etc/certs/remoted.pem" -noout -subject | sed 's/.*CN *= *//')"
    echo "[entrypoint] SANs: $(openssl x509 -in "$DIR/etc/certs/remoted.pem" -noout -ext subjectAltName | tail -1 | tr -s ' ')"
else
    echo "[entrypoint] !! no certificates at $CERTSRC" >&2
fi

# ---------------------------------------------------------------- cluster
sed -i "s|<node_name>node01</node_name>|<node_name>$NODE_NAME</node_name>|" "$CONF"
sed -i "/<cluster>/,/<\/cluster>/s|<bind_addr>127.0.0.1</bind_addr>|<bind_addr>0.0.0.0</bind_addr>|" "$CONF"
sed -i "/<cluster>/,/<\/cluster>/s|<node>127.0.0.1</node>|<node>$MASTER_ADDR</node>|" "$CONF"
sed -i "/<cluster>/,/<\/cluster>/s|<key>.*</key>|<key>9d273b53510fef702b54a92e9cffc82e</key>|" "$CONF"
if [[ "$NODE_TYPE" != "master" ]]; then
    sed -i "s|<node_type>master</node_type>|<node_type>worker</node_type>|" "$CONF"
fi

# ---------------------------------------------------------------- remoted HTTPS
# ca_certificate is NOT in the shipped configuration, so it falls back to the schema
# default (etc/certs/root-ca.pem). Written explicitly here so GET /cacerts is testable
# and so the file the listener is validated against is unambiguous in the logs.
#
# GUARDED BY THE SCHEMA ON PURPOSE: the option exists on the 5.0.0 branch but not in
# every 5.0.0 package. Writing it blindly makes a slightly older build refuse to start
# with error 1244 ("unknown option ... additionalProperties"). See FINDINGS.md L-02.
if grep -q '"ca_certificate"' "$DIR/etc/wazuh-manager.schema.json" 2>/dev/null; then
    if ! grep -q '<ca_certificate>' "$CONF"; then
        sed -i "s|<key>etc/certs/remoted-key.pem</key>|<key>etc/certs/remoted-key.pem</key>\n      <ca_certificate>etc/certs/root-ca.pem</ca_certificate>|" "$CONF"
        echo "[entrypoint] remote.https.ca_certificate set explicitly"
    fi
else
    echo "[entrypoint] this build has no remote.https.ca_certificate; leaving it unset"
fi

# ---------------------------------------------------------------- indexer
# Pointed at the lab's own single-node indexer. It is needed for exactly one measurement:
# vd_feed_offset divergence between nodes while their vulnerability feeds load. Set
# LAB_INDEXER=none to go back to an unreachable indexer (a supported state) if a scenario
# wants the manager running without one.
INDEXER_HOST="${LAB_INDEXER:-https://wazuh-indexer:9200}"
if [[ "$INDEXER_HOST" == "none" ]]; then
    INDEXER_HOST="https://wazuh-indexer.invalid:9200"
fi
sed -i "s|<host>https://127.0.0.1:9200</host>|<host>${INDEXER_HOST}</host>|" "$CONF"

# The indexer authenticates the manager by client certificate, with admin.pem -- its DN is
# the one opensearch.yml pins as plugins.security.authcz.admin_dn. A single-host install
# points <indexer><ssl> straight at /etc/wazuh-indexer/certs/{root-ca,admin,admin-key}.pem
# because both services share the filesystem. Here they are separate containers, so the same
# three files are copied into the manager's own etc/certs and referenced from there.
if [[ -d /lab-certs-indexer ]]; then
    install -o wazuh-manager -g wazuh-manager -m 640 /lab-certs-indexer/admin.pem \
        "$DIR/etc/certs/indexer-connector.pem"
    install -o wazuh-manager -g wazuh-manager -m 640 /lab-certs-indexer/admin-key.pem \
        "$DIR/etc/certs/indexer-connector-key.pem"
fi

# The engine REFUSES TO START if the indexer's TLS material is missing, even when the
# indexer itself is unreachable and every request to it is going to fail anyway:
#   ERROR: Could not initialize Indexer Connector: The CA root certificate file:
#          '/etc/wazuh-indexer/certs/root-ca.pem' does not exist.
# and without the engine, wazuh-manager-control aborts the startup before remoted.
# So the connector is pointed at this lab's own material, which exists. See FINDINGS.md L-03.
sed -i "/<indexer>/,/<\/indexer>/{
    s|<ca>.*</ca>|<ca>etc/certs/root-ca.pem</ca>|
    s|<certificate>.*</certificate>|<certificate>etc/certs/indexer-connector.pem</certificate>|
    s|<key>.*</key>|<key>etc/certs/indexer-connector-key.pem</key>|
}" "$CONF"

# ---------------------------------------------------------------- enrollment password
# use_password is yes in the shipped configuration. authd.pass IS cluster-synchronised,
# so seeding it only on the master is deliberate: the propagation of this file to the
# workers is one of the things under test.
if [[ "$NODE_TYPE" == "master" && -n "${AUTHD_PASS:-}" ]]; then
    printf '%s\n' "$AUTHD_PASS" > "$DIR/etc/authd.pass"
    chown root:wazuh-manager "$DIR/etc/authd.pass"
    chmod 640 "$DIR/etc/authd.pass"
    echo "[entrypoint] authd.pass seeded on the master only"
fi

# Extra per-node overrides, applied last so a scenario can change anything above.
if [[ -d /lab-overrides ]]; then
    for f in /lab-overrides/*.sh; do
        [[ -e "$f" ]] || continue
        echo "[entrypoint] override: $f"
        # shellcheck disable=SC1090
        . "$f"
    done
fi

"$DIR/bin/wazuh-manager-control" start || true

echo "[entrypoint] ---- listening ----"
ss -ltnp 2>/dev/null | grep -E ':(1514|1515|1516|1517|55000)' || true

tail -F "$DIR/logs/wazuh-manager.log" 2>/dev/null
