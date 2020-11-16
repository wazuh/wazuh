#!/usr/bin/env bash

# RBAC configuration
sqlite3 /var/ossec/api/configuration/security/rbac.db < /configuration_files/schema_security_test.sql
chown ossec:ossec /var/ossec/api/configuration/security/rbac.db
