#!/usr/bin/env bash

# RBAC configuration
sqlite3 /var/wazuh-manager/api/configuration/security/rbac.db < /tmp_volume/configuration_files/schema_security_test.sql
sqlite3 /var/wazuh-manager/api/configuration/security/rbac.db < /tmp_volume/configuration_files/base_security_test.sql
chown wazuh-manager:wazuh-manager /var/wazuh-manager/api/configuration/security/rbac.db
chmod 640 /var/wazuh-manager/api/configuration/security/rbac.db