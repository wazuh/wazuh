/*
 * SQL Schema for upgrading databases
 * Copyright (C) 2015-2020, Wazuh Inc.
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

DELETE FROM sys_osinfo;
DELETE FROM sys_netiface;
DELETE FROM sys_netproto;
DELETE FROM sys_netaddr;
DELETE FROM sys_programs;
DELETE FROM sys_hotfixes;
DELETE FROM sys_processes;

DROP TABLE sys_ports;
CREATE TABLE IF NOT EXISTS sys_ports (
    scan_id INTEGER,
    scan_time TEXT,
    protocol TEXT,
    local_ip TEXT,
    local_port INTEGER CHECK (local_port >= 0),
    remote_ip TEXT,
    remote_port INTEGER CHECK (remote_port >= 0),
    tx_queue INTEGER,
    rx_queue INTEGER,
    inode INTEGER,
    state TEXT,
    PID INTEGER,
    process TEXT,
    checksum TEXT NOT NULL CHECK (checksum <> ''),
    PRIMARY KEY (protocol, local_ip, local_port, inode)
);

ALTER TABLE sys_netiface ADD COLUMN checksum TEXT DEFAULT NOT NULL CHECK (checksum <> '');
ALTER TABLE sys_netproto ADD COLUMN checksum TEXT DEFAULT NOT NULL CHECK (checksum <> '');
ALTER TABLE sys_netaddr ADD COLUMN checksum TEXT DEFAULT NOT NULL CHECK (checksum <> '');
ALTER TABLE sys_programs ADD COLUMN checksum TEXT DEFAULT NOT NULL CHECK (checksum <> '');
ALTER TABLE sys_hotfixes ADD COLUMN checksum TEXT DEFAULT NOT NULL CHECK (checksum <> '');
ALTER TABLE sys_processes ADD COLUMN checksum TEXT DEFAULT NOT NULL CHECK (checksum <> '');

ALTER TABLE sys_netiface ADD COLUMN item_id TEXT DEFAULT NULL;
ALTER TABLE sys_netproto ADD COLUMN item_id TEXT DEFAULT NULL;
ALTER TABLE sys_netaddr ADD COLUMN item_id TEXT DEFAULT NULL;
ALTER TABLE sys_ports ADD COLUMN item_id TEXT DEFAULT NULL;
ALTER TABLE sys_programs ADD COLUMN item_id TEXT DEFAULT NULL;
ALTER TABLE sys_programs ADD COLUMN os_patch TEXT DEFAULT NULL;

INSERT OR REPLACE INTO metadata (key, value) VALUES ('db_version', 6);
