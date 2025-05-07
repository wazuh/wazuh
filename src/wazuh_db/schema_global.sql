/*
 * SQL Schema for global database
 * Copyright (C) 2015, Wazuh Inc.
 *
 * June 30, 2016.
 *
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
*/

PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS agent (
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

CREATE INDEX IF NOT EXISTS agent_name ON agent (name);
CREATE INDEX IF NOT EXISTS agent_ip ON agent (ip);
CREATE INDEX IF NOT EXISTS agent_group_hash ON agent (group_hash);

INSERT INTO agent (id, ip, register_ip, name, date_add, last_keepalive, `group`, connection_status) VALUES (0, '127.0.0.1', '127.0.0.1', 'localhost', strftime('%s','now'), 253402300799, NULL, 'active');

CREATE TABLE IF NOT EXISTS labels (
    id INTEGER REFERENCES agent (id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (id,key)
);

CREATE TABLE IF NOT EXISTS info (
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS `group` (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    UNIQUE (name)
);

CREATE INDEX IF NOT EXISTS group_name ON `group` (name);

CREATE TABLE IF NOT EXISTS belongs (
    id_agent INTEGER REFERENCES agent (id) ON DELETE CASCADE,
    id_group INTEGER REFERENCES `group` (id) ON DELETE CASCADE,
    priority INTEGER NOT NULL DEFAULT 0,
    UNIQUE (id_agent, priority),
    PRIMARY KEY (id_agent, id_group)
);

CREATE INDEX IF NOT EXISTS belongs_id_agent ON belongs (id_agent);
CREATE INDEX IF NOT EXISTS belongs_id_group ON belongs (id_group);

CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT
);

INSERT INTO `group` (name) VALUES ('default');

INSERT INTO metadata (key, value) VALUES ('db_version', '7');
