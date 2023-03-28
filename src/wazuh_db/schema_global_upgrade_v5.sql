/*
 * SQL Schema for upgrading databases
 * Copyright (C) 2015-2022, Wazuh Inc.
 *
 * December, 2022.
 *
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
*/

CREATE TABLE IF NOT EXISTS _belongs (
    id_agent INTEGER REFERENCES agent (id) ON DELETE CASCADE,
    name_group TEXT REFERENCES `group` (name) ON DELETE CASCADE,
    priority INTEGER NOT NULL DEFAULT 0,
    UNIQUE (id_agent, priority),
    PRIMARY KEY (id_agent, name_group)
);

BEGIN;

INSERT INTO _belongs (id_agent, name_group, priority) SELECT id_agent, name, priority FROM belongs JOIN `group` ON id = id_group WHERE id_agent IN (SELECT id FROM agent);

END;

DROP TABLE IF EXISTS belongs;
ALTER TABLE _belongs RENAME TO belongs;
CREATE INDEX IF NOT EXISTS belongs_id_agent ON belongs (id_agent);
CREATE INDEX IF NOT EXISTS belongs_name_group ON belongs (name_group);

CREATE TABLE IF NOT EXISTS `_group` (
    name TEXT PRIMARY KEY
);

BEGIN;
INSERT INTO `_group` (name) SELECT name FROM `group`;
END;

DROP TABLE IF EXISTS `group`;
ALTER TABLE `_group` RENAME TO `group`;
CREATE INDEX IF NOT EXISTS group_name ON `group` (name);

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
    group_sync_status TEXT NOT NULL CHECK (group_sync_status IN ('synced', 'syncreq')) DEFAULT 'synced',
    sync_status TEXT NOT NULL CHECK (sync_status IN ('synced', 'syncreq')) DEFAULT 'synced',
    connection_status TEXT NOT NULL CHECK (connection_status IN ('pending', 'never_connected', 'active', 'disconnected')) DEFAULT 'never_connected',
    disconnection_time INTEGER DEFAULT 0,
    group_config_status TEXT NOT NULL CHECK (group_config_status IN ('synced', 'not synced')) DEFAULT 'not synced',
    status_code INTEGER DEFAULT 0
);

BEGIN;

INSERT INTO _agent (id, name, ip, register_ip, internal_key, os_name, os_version, os_major, os_minor, os_codename, os_build, os_platform, os_uname, os_arch, version, config_sum, merged_sum, manager_host, node_name, date_add, last_keepalive, sync_status, connection_status) SELECT id, name, ip, register_ip, internal_key, os_name, os_version, os_major, os_minor, os_codename, os_build, os_platform, os_uname, os_arch, version, config_sum, merged_sum, manager_host, node_name, date_add, last_keepalive, sync_status, connection_status FROM agent;

END;

DROP TABLE IF EXISTS agent;
ALTER TABLE _agent RENAME TO agent;
CREATE INDEX IF NOT EXISTS agent_name ON agent (name);
CREATE INDEX IF NOT EXISTS agent_ip ON agent (ip);

UPDATE metadata SET value = '5' where key = 'db_version';
