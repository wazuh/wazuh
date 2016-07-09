-- SQL Schema for per-agent database
-- Copyright 2016 Wazuh, Inc. <info@wazuh.com>
-- June 30, 2016.
-- This program is a free software, you can redistribute it
-- and/or modify it under the terms of GPLv2.

CREATE TABLE IF NOT EXISTS fim_file (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path TEXT NOT NULL,
    type TEXT NOT NULL CHECK (type IN ('file', 'registry'))
);

CREATE UNIQUE INDEX IF NOT EXISTS fim_file_path ON fim_file (type, path);

CREATE TABLE IF NOT EXISTS fim_event (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    id_file INTEGER NOT NULL REFERENCES fim_file (id),
    type TEXT NOT NULL CHECK (type IN ('added', 'modified', 'readded', 'deleted')),
    date NUMERIC,
    size INTEGER,
    perm INTEGER,
    uid INTEGER,
    gid INTEGER,
    md5 TEXT,
    sha1 TEXT,
    uname TEXT,
    gname TEXT,
    mtime NUMERIC,
    inode INTEGER
);

CREATE INDEX IF NOT EXISTS fim_event_type ON fim_event (type);
CREATE INDEX IF NOT EXISTS fim_event_file ON fim_event (id_file);
CREATE INDEX IF NOT EXISTS fim_event_date ON fim_event (date);
CREATE INDEX IF NOT EXISTS fim_event_md5 ON fim_event (md5);
CREATE INDEX IF NOT EXISTS fim_event_sha1 ON fim_event (sha1);

CREATE TABLE IF NOT EXISTS pm_event (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    date_first NUMERIC,
    date_last NUMERIC,
    log TEXT
);

CREATE INDEX IF NOT EXISTS pm_event_log ON pm_event (log);
CREATE INDEX IF NOT EXISTS pm_event_date ON pm_event (date_last);

PRAGMA journal_mode=WAL;
