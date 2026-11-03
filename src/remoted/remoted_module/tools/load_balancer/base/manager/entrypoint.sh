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
# The manager configuration directory is fixed, outside the installation home.
CONF_DIR=/etc/wazuh-manager
CONF="$CONF_DIR/wazuh-manager.conf"

echo "[entrypoint] $NODE_NAME ($NODE_TYPE), master at $MASTER_ADDR"

# ---------------------------------------------------------------- certificates
# Mounted read-only at /lab-certs by the compose file. Each node has its OWN leaf,
# which is what a real deployment has: cluster.json does not replicate certs/.
#
# The package's credential resolver already ran at `dpkg -i` (image build): it minted a CA
# of its own in ca/ and issued remoted/apid pairs from it. Every start then checks that
# certs/root-ca.pem contains ca/root-ca.pem and that every pair chains to that CA, so the lab
# PKI cannot just be copied over certs/ -- the start would be refused ("Invalid credentials").
# Instead this follows the documented path for certificates issued elsewhere, when the install
# minted a CA first (docs/ref/getting-started/installation.md#using-certificates-issued-elsewhere):
#   - the minted CA's key and mint marker go, and the lab CA takes ca/root-ca.pem (root:root
#     0644 in a root:root 0700 directory). Its key is not staged: nothing is issued on a node;
#   - certs/root-ca.pem (the agents' bundle) is the lab CA;
#   - remoted AND apid serve the node's lab leaf: the minted pairs no longer chain, and the
#     resolver never reissues a pair outside an install.
# Installed layout: certs/ root:wazuh-manager exactly 0750, every PEM root:wazuh-manager 0640
# (the daemons read them through the group after dropping privileges). Re-run on every boot:
# each step converges.
CERTSRC="/lab-certs/$NODE_NAME"
if [[ -d "$CERTSRC" ]]; then
    install -d -m 700 -o root -g root "$CONF_DIR/ca"
    rm -f "$CONF_DIR/ca/root-ca.key" "$CONF_DIR/ca/.wazuh-manager-bootstrap-ca"
    install -o root -g root -m 644 "/lab-certs/root-ca.pem" "$CONF_DIR/ca/root-ca.pem"

    install -d -m 750 -o root -g wazuh-manager "$CONF_DIR/certs"
    install -o root -g wazuh-manager -m 640 "/lab-certs/root-ca.pem"         "$CONF_DIR/certs/root-ca.pem"
    for pair in remoted apid; do
        install -o root -g wazuh-manager -m 640 "$CERTSRC/node.pem"     "$CONF_DIR/certs/$pair.pem"
        install -o root -g wazuh-manager -m 640 "$CERTSRC/node-key.pem" "$CONF_DIR/certs/$pair-key.pem"
    done
    echo "[entrypoint] lab CA staged in ca/ and certs/root-ca.pem; remoted and apid serve the node's leaf"
    echo "[entrypoint] listener certificate: $(openssl x509 -in "$CONF_DIR/certs/remoted.pem" -noout -subject | sed 's/.*CN *= *//')"
    echo "[entrypoint] SANs: $(openssl x509 -in "$CONF_DIR/certs/remoted.pem" -noout -ext subjectAltName | tail -1 | tr -s ' ')"
else
    echo "[entrypoint] !! no certificates at $CERTSRC: the start will be refused (the image's minted pairs" \
         "are kept, but nothing the lab front ends trust)" >&2
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
# default (/etc/wazuh-manager/certs/root-ca.pem). Written explicitly here so GET /cacerts is testable
# and so the file the listener is validated against is unambiguous in the logs.
#
# GUARDED BY THE SCHEMA ON PURPOSE: the option exists on the 5.0.0 branch but not in
# every 5.0.0 package. Writing it blindly makes a slightly older build refuse to start
# with error 1244 ("unknown option ... additionalProperties"). See FINDINGS.md L-02.
if grep -q '"ca_certificate"' "$CONF_DIR/wazuh-manager.schema.json" 2>/dev/null; then
    if ! grep -q '<ca_certificate>' "$CONF"; then
        sed -i "s|\(<key>[^<]*remoted-key\.pem</key>\)|\1\n      <ca_certificate>$CONF_DIR/certs/root-ca.pem</ca_certificate>|" "$CONF"
        echo "[entrypoint] remote.https.ca_certificate set explicitly"
    fi
else
    echo "[entrypoint] this build has no remote.https.ca_certificate; leaving it unset"
fi

# ---------------------------------------------------------------- membership cache
# How long remoted trusts a cached agent membership before reading wazuh-db again
# (remoted.control_groups_refresh_interval, 60 s by default). The lab lengthens it to an hour so
# that no check can be passed by the cache simply expiring: when the revocation check sees the
# old selector refused within its window, only the cluster daemon's publication can have caused
# it. LAB_GROUPS_REFRESH_INTERVAL=default keeps the product default. Written idempotently
# (the entrypoint runs on every boot); the probes read the effective value back from this file.
INTERNAL="$DIR/etc/wazuh-manager-internal-options.conf"
REFRESH="${LAB_GROUPS_REFRESH_INTERVAL:-3600}"
sed -i '/^remoted\.control_groups_refresh_interval=/d' "$INTERNAL"
if [[ "$REFRESH" != "default" ]]; then
    printf 'remoted.control_groups_refresh_interval=%s\n' "$REFRESH" >> "$INTERNAL"
    echo "[entrypoint] remoted.control_groups_refresh_interval=$REFRESH"
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

# The indexer trust is CONSUMED, never generated: every start is refused until
# certs/indexer-ca.pem, the indexer-connector pair and WAZUH_INDEXER_MANAGER_PASSWORD resolve
# ("Unresolved credentials"). A single-host install imports all three from
# /etc/wazuh-indexer/export/; the lab's indexer is another container, so they are staged here
# under the names the generated <indexer><ssl> block already uses -- the operator-staged path
# of docs/ref/getting-started/installation.md (no import marker: validated, never replaced).
#
# The indexer authenticates the manager by client certificate, with admin.pem -- its DN is
# the one opensearch.yml pins as plugins.security.authcz.admin_dn -- and the CA is the lab's.
if [[ -d /lab-certs-indexer ]]; then
    install -o root -g wazuh-manager -m 640 /lab-certs-indexer/root-ca.pem \
        "$CONF_DIR/certs/indexer-ca.pem"
    install -o root -g wazuh-manager -m 640 /lab-certs-indexer/admin.pem \
        "$CONF_DIR/certs/indexer-connector.pem"
    install -o root -g wazuh-manager -m 640 /lab-certs-indexer/admin-key.pem \
        "$CONF_DIR/certs/indexer-connector-key.pem"
else
    echo "[entrypoint] !! no /lab-certs-indexer: certs/indexer-ca.pem and the indexer-connector pair" \
         "are missing, so the start will be refused" >&2
fi

# The password of the indexer's wazuh-manager user, through local.env (root, 0600, one link):
# the resolver stores it in the keystore at the first start that finds none there, and never
# replaces it afterwards. The lab indexer authenticates the manager by its client certificate,
# so the default only has to satisfy the password rule (12-64 characters, upper and lower case,
# a digit and a symbol); set LAB_INDEXER_MANAGER_PASSWORD to the indexer's real one when it has
# a wazuh-manager user. A local.env already present (staged by a scenario) is left alone.
if [[ ! -e "$CONF_DIR/local.env" ]]; then
    install -m 600 -o root -g root /dev/null "$CONF_DIR/local.env"
    printf "WAZUH_INDEXER_MANAGER_PASSWORD='%s'\n" "${LAB_INDEXER_MANAGER_PASSWORD:-Lab.Indexer.Passw0rd}" \
        > "$CONF_DIR/local.env"
    echo "[entrypoint] local.env written with the indexer password"
fi

# ---------------------------------------------------------------- enrollment password
# use_password is yes in the shipped configuration. authd.pass IS cluster-synchronised,
# so seeding it only on the master is deliberate: the propagation of this file to the
# workers is one of the things under test.
if [[ "$NODE_TYPE" == "master" && -n "${AUTHD_PASS:-}" ]]; then
    printf '%s\n' "$AUTHD_PASS" > "$CONF_DIR/authd.pass"
    chown root:wazuh-manager "$CONF_DIR/authd.pass"
    chmod 640 "$CONF_DIR/authd.pass"
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

# A refused start (exit 1) leaves no daemon running; the reason is in the log tailed below
# ("wazuh-manager-control: ERROR: ..." plus the resolver's MISSING/INVALID/UNSAFE lines).
if ! "$DIR/bin/wazuh-manager-control" start; then
    echo "[entrypoint] !! the manager did not start; see the resolver lines in the log below" >&2
fi

echo "[entrypoint] ---- listening ----"
ss -ltnp 2>/dev/null | grep -E ':(1514|1515|1516|1517|55000)' || true

tail -F "$DIR/logs/wazuh-manager.log" 2>/dev/null
