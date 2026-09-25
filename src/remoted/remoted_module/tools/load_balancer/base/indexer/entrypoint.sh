#!/usr/bin/env bash
# Single-node Wazuh indexer for the lab.
#
# The certificate DNs are NOT free. opensearch.yml ships with CN=admin pinned as the admin DN
# and a PLACEHOLDER CN=node-1 as the node DN, and wazuh-certs-tool names the node certificate
# after the node instead, so the two do not agree out of the box. A supported install closes
# that gap by hand -- the step-by-step guides tell you to list your real node names under
# plugins.security.nodes_dn -- and this entrypoint does the same below.
#
# Everything is issued by the same tool and the same CA as the managers, so one root-ca.pem is
# the anchor for the whole lab.
set -euo pipefail

# Two JVM options the indexer needs in a container. Without them it starts and then fails on
# the cgroup file it reads for memory accounting; they are the same pair a supported install
# appends to jvm.options.
if ! grep -q 'java.security.policy' /etc/wazuh-indexer/jvm.options; then
    cat >> /etc/wazuh-indexer/jvm.options <<'JVM'

-Djava.security.policy=all.policy
-Dpermission.java.io.FilePermission=/sys/fs/cgroup/-,read
JVM
fi

# Heap. The shipped default is 1g, which is not enough once the Wazuh data streams and their
# templates are created; 4g is what a working single-node install uses.
HEAP="${INDEXER_HEAP:-4g}"
sed -i "s/^-Xms.*/-Xms${HEAP}/; s/^-Xmx.*/-Xmx${HEAP}/" /etc/wazuh-indexer/jvm.options
echo "[indexer] heap ${HEAP}"

CERTS=/etc/wazuh-indexer/certs
install -d -o wazuh-indexer -g wazuh-indexer -m 500 "$CERTS"
for f in indexer.pem indexer-key.pem admin.pem admin-key.pem root-ca.pem; do
    install -o wazuh-indexer -g wazuh-indexer -m 640 "/lab-certs-indexer/$f" "$CERTS/$f"
done
echo "[indexer] node cert: $(openssl x509 -in "$CERTS/indexer.pem" -noout -subject)"

# Align plugins.security.nodes_dn with the DN the node actually presents. Left at the packaged
# CN=node-1 the node rejects its own transport certificate at bootstrap ("Node presenting
# certificate with SSL Principal ... could not securely connect to the cluster"). A single node
# survives it because nothing else joins, which is exactly what makes it easy to ship broken.
NODE_DN="$(openssl x509 -in "$CERTS/indexer.pem" -noout -subject -nameopt RFC2253 |
           sed 's/^subject= *//')"
awk -v dn="$NODE_DN" '
    /^plugins\.security\.nodes_dn:/ { print; print "- \"" dn "\""; skip = 1; next }
    skip && /^[[:space:]]*#?-/        { next }
    { skip = 0; print }
' /etc/wazuh-indexer/opensearch.yml > /tmp/os.yml && mv /tmp/os.yml /etc/wazuh-indexer/opensearch.yml
chown wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/opensearch.yml
echo "[indexer] nodes_dn: $NODE_DN"

install -d -o wazuh-indexer -g wazuh-indexer /var/lib/wazuh-indexer /var/log/wazuh-indexer /run/wazuh-indexer

# memory_lock needs the ulimit the compose file grants; without it the node refuses to start.
echo "[indexer] starting"
# The configuration directory is selected by OPENSEARCH_PATH_CONF, not by -Epath.conf:
# that setting was removed and the node refuses to start with it ("unknown setting [path.conf]").
su -s /bin/bash wazuh-indexer -c "OPENSEARCH_PATH_CONF=/etc/wazuh-indexer \
    /usr/share/wazuh-indexer/bin/opensearch" &
OS_PID=$!

# The security index has to be initialised once, after the node answers.
for _ in $(seq 1 120); do
    if curl -s -k --cert "$CERTS/admin.pem" --key "$CERTS/admin-key.pem" \
            https://127.0.0.1:9200 >/dev/null 2>&1; then
        break
    fi
    sleep 2
done
echo "[indexer] running security init"
export JAVA_HOME=/usr/share/wazuh-indexer/jdk
bash /usr/share/wazuh-indexer/bin/indexer-security-init.sh 2>&1 | tail -5 || \
    echo "[indexer] security init reported a problem (may already be initialised)"

wait $OS_PID
