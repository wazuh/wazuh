/*
 * SQL Schema for global database
 * Copyright 2016 Wazuh, Inc. <info@wazuh.com>
 * June 30, 2016.
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
 */

CREATE TABLE IF NOT EXISTS agent (
    id INTEGER PRIMARY KEY,
    name TEXT,
    ip TEXT,
    key TEXT,
    os TEXT,
    version TEXT,
    date_add TEXT DEFAULT CURRENT_TIMESTAMP,
    last_keepalive TEXT
);

CREATE INDEX IF NOT EXISTS agent_name ON agent (name);
CREATE INDEX IF NOT EXISTS agent_ip ON agent (ip);

INSERT INTO agent (id, name, last_keepalive) VALUES (0, 'localhost', '9999-12-31 23:59:59');

PRAGMA journal_mode=WAL;
