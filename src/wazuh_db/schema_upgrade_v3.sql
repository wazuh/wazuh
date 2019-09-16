/*
 * SQL Schema for upgrading databases
 * Copyright (C) 2015-2019, Wazuh Inc.
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
*/

DROP TABLE IF EXISTS fim_entry;

CREATE TABLE fim_entry (
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

UPDATE metadata SET value = 3 WHERE key = 'db_version';
