/*
 * SQL Schema for upgrading databases
 * Copyright (C) 2015-2020, Wazuh Inc.
 * 
 * September, 2020.
 * 
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
*/

PRAGMA journal_mode=DELETE;

BEGIN;

CREATE TABLE IF NOT EXISTS labels (
    id INTEGER,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (id,key)
);

ALTER TABLE agent ADD COLUMN sync_status TEXT NOT NULL CHECK (sync_status IN ('synced', 'syncreq')) DEFAULT 'synced';
CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT
);

INSERT INTO metadata (key, value) VALUES ('db_version', '1');

END;
