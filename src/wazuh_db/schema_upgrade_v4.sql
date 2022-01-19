/*
 * SQL Schema for upgrading databases
 * Copyright (C) 2015, Wazuh Inc.
 *
 * October 16, 2019.
 *
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
*/

CREATE TABLE _fim_entry (
    file TEXT PRIMARY KEY,
    type TEXT NOT NULL CHECK (type IN ('file', 'registry')),
    date INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    changes INTEGER NOT NULL DEFAULT 1,
    size INTEGER,
    perm TEXT,
    uid TEXT,
    gid TEXT,
    md5 TEXT,
    sha1 TEXT,
    uname TEXT,
    gname TEXT,
    mtime INTEGER,
    inode INTEGER,
    sha256 TEXT,
    attributes TEXT,
    symbolic_path TEXT,
    checksum TEXT
);

CREATE TABLE IF NOT EXISTS sync_info (
    component TEXT PRIMARY KEY,
    last_attempt INTEGER DEFAULT 0,
    last_completion INTEGER DEFAULT 0,
    n_attempts INTEGER DEFAULT 0,
    n_completions INTEGER DEFAULT 0
);

BEGIN;

INSERT OR REPLACE INTO metadata (key, value) VALUES ('db_version', 4);
INSERT INTO _fim_entry (file, type, date, changes, size, perm, uid, gid, md5, sha1, uname, gname, mtime, inode, sha256, attributes, symbolic_path) SELECT file, type, date, changes, size, perm, uid, gid, md5, sha1, uname, gname, mtime, inode, sha256, attributes, symbolic_path FROM fim_entry;
INSERT INTO sync_info (component) VALUES ('fim');

END;

DROP TABLE IF EXISTS fim_entry;
ALTER TABLE _fim_entry RENAME TO fim_entry;

CREATE INDEX IF NOT EXISTS fim_file_index ON fim_entry (file);
CREATE INDEX IF NOT EXISTS fim_date_index ON fim_entry (date);
