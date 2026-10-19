FROM ubuntu:24.04

# Update and install dependencies. curl is for entrypoint.sh (cluster readiness and the auth
# probe): the per-package wazuh-indexer no longer depends on it.
RUN apt-get update && apt-get install -y locales curl && rm -rf /var/lib/apt/lists/* \
    && localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8
ENV LANG=en_US.utf8

# Copy all files to a temporary location for installation
WORKDIR /tmp/wazuh-install
COPY . .

# Install wazuh-indexer
RUN apt-get update && apt install -y /tmp/wazuh-install/wazuh-indexer_5.0.0-latest.deb && rm -rf /var/lib/apt/lists/*


# Add Java security policy permissions for cgroup access
RUN cat <<'EOF' >> /etc/wazuh-indexer/jvm.options
-Djava.security.policy=all.policy
-Dpermission.java.io.FilePermission=/sys/fs/cgroup/-,read
EOF

# Change jvm options to use more memory for testing from the default 1g to 4g for Xms and 4g for Xmx
RUN sed -i 's/-Xms1g/-Xms4g/g' /etc/wazuh-indexer/jvm.options
RUN sed -i 's/-Xmx1g/-Xmx4g/g' /etc/wazuh-indexer/jvm.options

# Unbake what the postinst resolved into this layer, so every new container resolves from the env
# it is given (entrypoint.sh). --clear takes back the bcrypt digests in internal_users.yml (it puts
# the ${KEY} placeholders back), the CA it minted in /etc/wazuh-indexer/ca, the pairs in certs/, the
# DNs in opensearch.yml and everything published in /etc/wazuh-indexer/export. The grep proves the
# placeholders are back: without them the next resolution would have nothing to write into.
RUN set -e; \
    /usr/share/wazuh-indexer/bin/resolve-credentials.sh --clear; \
    grep -qF '${WAZUH_INDEXER_ADMIN_PASSWORD}' /etc/wazuh-indexer/opensearch-security/internal_users.yml; \
    test ! -e /etc/wazuh-indexer/export/credentials.env

# Clean up installation files
RUN rm -rf /tmp/wazuh-install

# Set working directory
WORKDIR /root

# Wait for interactive debugging
#CMD [ "sleep", "infinity" ]
