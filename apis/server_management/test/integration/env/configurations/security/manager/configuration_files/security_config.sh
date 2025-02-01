#!/usr/bin/env bash

# RBAC configuration
sqlite3 /var/ossec/api/configuration/security/rbac.db < /tmp_volume/configuration_files/schema_security_test.sql
sqlite3 /var/ossec/api/configuration/security/rbac.db < /tmp_volume/configuration_files/base_security_test.sql
chown wazuh:wazuh /var/ossec/api/configuration/security/rbac.db
chmod 640 /var/ossec/api/configuration/security/rbac.db
