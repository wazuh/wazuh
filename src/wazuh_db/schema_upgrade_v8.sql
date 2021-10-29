/*
 * SQL Schema for upgrading databases
 * Copyright (C) 2015-2021, Wazuh Inc.
 *
 * May 21, 2021
 *
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
*/

CREATE TABLE IF NOT EXISTS _sys_programs (
    scan_id INTEGER,
    scan_time TEXT,
    format TEXT NOT NULL CHECK (format IN ('pacman', 'deb', 'rpm', 'win', 'pkg')),
    name TEXT,
    priority TEXT,
    section TEXT,
    size INTEGER CHECK (size >= 0),
    vendor TEXT,
    install_time TEXT,
    version TEXT,
    architecture TEXT,
    multiarch TEXT,
    source TEXT,
    description TEXT,
    location TEXT,
    triaged INTEGER(1),
    cpe TEXT,
    msu_name TEXT,
    checksum TEXT NOT NULL CHECK (checksum <> ''),
    item_id TEXT,
    PRIMARY KEY (scan_id, name, version, architecture)
);

INSERT INTO _sys_programs SELECT * FROM sys_programs;
DROP TABLE IF EXISTS sys_programs;
ALTER TABLE _sys_programs RENAME TO sys_programs;
CREATE INDEX IF NOT EXISTS programs_id ON sys_programs (scan_id);

ALTER TABLE sys_osinfo ADD COLUMN os_display_version TEXT DEFAULT NULL;
ALTER TABLE sync_info ADD COLUMN last_manager_checksum TEXT NOT NULL DEFAULT '';

INSERT INTO sync_info (component) VALUES ('fim_file');
INSERT INTO sync_info (component) VALUES ('fim_registry');
INSERT INTO sync_info (component) VALUES ('syscollector-processes');
INSERT INTO sync_info (component) VALUES ('syscollector-packages');
INSERT INTO sync_info (component) VALUES ('syscollector-hotfixes');
INSERT INTO sync_info (component) VALUES ('syscollector-ports');
INSERT INTO sync_info (component) VALUES ('syscollector-netproto');
INSERT INTO sync_info (component) VALUES ('syscollector-netaddress');
INSERT INTO sync_info (component) VALUES ('syscollector-netinfo');
INSERT INTO sync_info (component) VALUES ('syscollector-hwinfo');
INSERT INTO sync_info (component) VALUES ('syscollector-osinfo');

INSERT OR REPLACE INTO metadata (key, value) VALUES ('db_version', 8);
