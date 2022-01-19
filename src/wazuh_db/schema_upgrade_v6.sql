/*
 * SQL Schema for upgrading databases
 * Copyright (C) 2015, Wazuh Inc.
 *
 * October 5, 2020.
 *
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
*/

CREATE TABLE IF NOT EXISTS _fim_entry (
    full_path TEXT NOT NULL PRIMARY KEY,
    file TEXT,
    type TEXT NOT NULL CHECK (type IN ('file', 'registry_key', 'registry_value')),
    date INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    changes INTEGER NOT NULL DEFAULT 1,
    arch TEXT CHECK (arch IN (NULL, '[x64]', '[x32]')),
    value_name TEXT,
    value_type TEXT,
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

INSERT INTO _fim_entry (full_path, file, type, date, changes, size, perm, uid, gid, md5, sha1, uname, gname, mtime, inode, sha256, attributes, symbolic_path) SELECT file, file, CASE type WHEN 'registry' THEN 'registry_key' ELSE 'file' END, date, changes, size, perm, uid, gid, md5, sha1, uname, gname, mtime, inode, sha256, attributes, symbolic_path FROM fim_entry;

DROP TABLE IF EXISTS fim_entry;
ALTER TABLE _fim_entry RENAME TO fim_entry;

CREATE INDEX IF NOT EXISTS fim_full_path_index ON fim_entry (full_path);
CREATE INDEX IF NOT EXISTS fim_file_index ON fim_entry (file);
CREATE INDEX IF NOT EXISTS fim_date_index ON fim_entry (date);

ALTER TABLE sys_osinfo ADD COLUMN os_patch TEXT DEFAULT NULL;

INSERT OR REPLACE INTO metadata (key, value) VALUES ('db_version', 6);
