/*
 * SQL Schema for upgrading databases
 * Copyright (C) 2015-2024, Wazuh Inc.
 *
 * April 30, 2025.
 *
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
*/

BEGIN;

CREATE TABLE IF NOT EXISTS _agent (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    ip TEXT,
    register_ip TEXT,
    internal_key TEXT,
    os_name TEXT,
    os_version TEXT,
    os_major TEXT,
    os_minor TEXT,
    os_codename TEXT,
    os_build TEXT,
    os_platform TEXT,
    os_uname TEXT,
    os_arch TEXT,
    version TEXT,
    config_sum TEXT,
    merged_sum TEXT,
    manager_host TEXT,
    node_name TEXT DEFAULT 'unknown',
    date_add INTEGER NOT NULL,
    last_keepalive INTEGER,
    `group` TEXT DEFAULT 'default',
    group_hash TEXT default NULL,
    group_sync_status TEXT NOT NULL CHECK (group_sync_status IN ('synced', 'syncreq')) DEFAULT 'synced',
    sync_status TEXT NOT NULL CHECK (sync_status IN ('synced', 'syncreq', 'syncreq_status', 'syncreq_keepalive')) DEFAULT 'synced',
    connection_status TEXT NOT NULL CHECK (connection_status IN ('pending', 'never_connected', 'active', 'disconnected')) DEFAULT 'never_connected',
    disconnection_time INTEGER DEFAULT 0,
    group_config_status TEXT NOT NULL CHECK (group_config_status IN ('synced', 'not synced')) DEFAULT 'not synced',
    status_code INTEGER DEFAULT 0
);

INSERT INTO _agent (id, name, ip, register_ip, internal_key, os_name, os_version, os_major, os_minor, os_codename, os_build, os_platform, os_uname, os_arch, version, config_sum, merged_sum, manager_host, node_name, date_add, last_keepalive, `group`, group_hash, group_sync_status, sync_status, connection_status, disconnection_time, group_config_status, status_code) SELECT id, name, ip, register_ip, internal_key, os_name, os_version, os_major, os_minor, os_codename, os_build, os_platform, os_uname, os_arch, version, config_sum, merged_sum, manager_host, node_name, date_add, last_keepalive, `group`, group_hash, group_sync_status, sync_status, connection_status, disconnection_time, group_config_status, status_code FROM agent;

DROP TABLE IF EXISTS agent;
ALTER TABLE _agent RENAME TO agent;
CREATE INDEX IF NOT EXISTS agent_name ON agent (name);
CREATE INDEX IF NOT EXISTS agent_ip ON agent (ip);
CREATE INDEX IF NOT EXISTS agent_group_hash ON agent (group_hash);

INSERT OR IGNORE INTO `group` (name) VALUES ('default');

UPDATE agent SET `group` = 'default' WHERE `group` IS NULL AND id != 0;

WITH default_group AS (
    SELECT id AS id_group FROM `group` WHERE name = 'default'
) INSERT INTO belongs (id_agent, id_group, priority)
SELECT agent.id, dg.id_group, 0 FROM agent CROSS JOIN default_group dg WHERE agent.id != 0 AND NOT EXISTS (
    SELECT 1 FROM belongs WHERE belongs.id_agent = agent.id
);

UPDATE metadata SET value = '7' WHERE key = 'db_version';

END;
