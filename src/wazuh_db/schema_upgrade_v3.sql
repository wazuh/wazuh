/*
 * SQL Schema for upgrading databases
 * Copyright (C) 2015-2019, Wazuh Inc.
 *
 * July, 2019.
 *
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

CREATE TABLE IF NOT EXISTS sync_info (
    component TEXT PRIMARY KEY,
    last_attempt INTEGER DEFAULT 0,
    last_completion INTEGER DEFAULT 0,
    n_attempts INTEGER DEFAULT 0,
    n_completions INTEGER DEFAULT 0
);

ALTER TABLE sys_programs ADD COLUMN cpe TEXT DEFAULT NULL;
ALTER TABLE sys_programs ADD COLUMN msu_name TEXT DEFAULT NULL;
ALTER TABLE sys_osinfo ADD COLUMN os_release TEXT DEFAULT NULL;
ALTER TABLE sca_check ADD COLUMN condition TEXT;

INSERT OR REPLACE INTO metadata (key, value) VALUES ('db_version', 3);
INSERT INTO sync_info (component) VALUES ('fim');

CREATE TABLE IF NOT EXISTS sys_hotfixes (
    scan_id INTEGER,
    scan_time TEXT,
    hotfix TEXT,
    PRIMARY KEY (scan_id, scan_time, hotfix)
);
CREATE INDEX IF NOT EXISTS hotfix_id ON sys_hotfixes (scan_id);

CREATE TABLE IF NOT EXISTS vuln_metadata (
    LAST_SCAN INTEGER,
    WAZUH_VERSION TEXT
);
INSERT INTO vuln_metadata (LAST_SCAN, WAZUH_VERSION)
    SELECT '0', '0' WHERE NOT EXISTS (
        SELECT * FROM vuln_metadata
    );

END;
