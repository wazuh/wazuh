#!/usr/bin/env bash

# Syscheck configuration
sqlite3 /var/ossec/queue/db/000.db < /configuration_files/schema_syscheck_test.sql
chown ossec:ossec /var/ossec/queue/db/000.db
