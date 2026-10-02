FROM ubuntu:24.04

# Update and install dependencies
RUN apt-get update && apt-get install -y locales && rm -rf /var/lib/apt/lists/* \
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

# Create certs directory (will be populated by volume mount at runtime)
RUN mkdir -p /etc/wazuh-indexer/certs/

# Unbake the credentials the postinst resolved into this layer (the .deb is still in
# /tmp/wazuh-install here). --clear alone is not enough: the resolver only substitutes ${KEY}
# placeholders in internal_users.yml, so the build's bcrypt hashes would stay orphaned there --
# restore the pristine file from the .deb (same owner/mode) and drop the emptied credentials.env,
# so every new container resolves from the env it is given (entrypoint.sh).
RUN set -e; \
    IU=/etc/wazuh-indexer/opensearch-security/internal_users.yml; \
    /usr/share/wazuh-indexer/bin/resolve-credentials.sh --clear; \
    IU_OWNER="$(stat -c '%u:%g' "$IU")"; IU_MODE="$(stat -c '%a' "$IU")"; \
    dpkg-deb --fsys-tarfile /tmp/wazuh-install/wazuh-indexer_5.0.0-latest.deb \
        | tar -xOf - ./etc/wazuh-indexer/opensearch-security/internal_users.yml > "$IU"; \
    chown "$IU_OWNER" "$IU"; chmod "$IU_MODE" "$IU"; \
    grep -qF '${WAZUH_INDEXER_ADMIN_PASSWORD}' "$IU"; \
    rm -f /etc/wazuh/credentials.env

# Clean up installation files
RUN rm -rf /tmp/wazuh-install

# Set working directory
WORKDIR /root

# Wait for interactive debugging
#CMD [ "sleep", "infinity" ]
