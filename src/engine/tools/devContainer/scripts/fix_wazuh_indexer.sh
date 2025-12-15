#!/bin/bash
CERT_ORG_DIR="/workspaces/wazuh-5.x/scripts_public/certs"

# Check if wazuh-indexer user exists
if ! id -u wazuh-indexer >/dev/null 2>&1; then
    echo "User 'wazuh-indexer' does not exist. Please install wazuh-indexer before running this script."
    exit 1
fi

cp ${CERT_ORG_DIR}/node-1-key.pem /etc/wazuh-indexer/certs/indexer-key.pem
cp ${CERT_ORG_DIR}/node-1.pem /etc/wazuh-indexer/certs/indexer.pem
cp ${CERT_ORG_DIR}/root-ca.pem /etc/wazuh-indexer/certs
cp ${CERT_ORG_DIR}/admin.pem /etc/wazuh-indexer/certs
cp ${CERT_ORG_DIR}/admin-key.pem /etc/wazuh-indexer/certs
chown wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs/*
chmod 640 /etc/wazuh-indexer/certs/*

# Create or modify the opensearch configuration to set an explicit memory value instead of percentage
echo "knn.memory.circuit_breaker.limit: 4096mb" >> /etc/wazuh-indexer/opensearch.yml
# Add Java security policy permissions for cgroup access
cat >> /etc/wazuh-indexer/jvm.options << 'EOF'

-Djava.security.policy=all.policy

-Dpermission.java.io.FilePermission=/sys/fs/cgroup/-,read

EOF
# Restart the wazuh-indexer service
service wazuh-indexer restart
sleep 10
/usr/share/wazuh-indexer/bin/indexer-security-init.sh

exit 0


# <indexer>
#   <hosts>
#     <host>https://127.0.0.1:9200</host>
#   </hosts>
#   <ssl>
#     <certificate_authorities>
#       <ca>/etc/wazuh-indexer/certs/root-ca.pem</ca>
#     </certificate_authorities>
#     <certificate>/etc/wazuh-indexer/certs/admin.pem</certificate>
#     <key>/etc/wazuh-indexer/certs/admin-key.pem</key>
#   </ssl>
# </indexer>
