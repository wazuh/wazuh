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
PRAGMA user_version = 1;

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
    os_platform TEXT,
    os_arch TEXT,
    version TEXT,
    merged_sum TEXT,
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

CREATE TABLE IF NOT EXISTS `group` (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    UNIQUE (name)
);

CREATE TABLE IF NOT EXISTS belongs (
    id_agent INTEGER REFERENCES agent (id) ON DELETE CASCADE,
    id_group INTEGER REFERENCES `group` (id) ON DELETE CASCADE,
    priority INTEGER NOT NULL DEFAULT 0,
    UNIQUE (id_agent, priority),
    PRIMARY KEY (id_agent, id_group)
);

CREATE INDEX IF NOT EXISTS belongs_id_group ON belongs (id_group);

CREATE TABLE IF NOT EXISTS metadata (
    key   TEXT PRIMARY KEY,
    value TEXT
);

