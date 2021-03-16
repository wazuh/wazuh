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

ALTER TABLE sys_osinfo ADD COLUMN reference TEXT DEFAULT '' NOT NULL;
ALTER TABLE sys_osinfo ADD COLUMN triaged INTEGER(1) DEFAULT 0;

DROP TABLE IF EXISTS vuln_cves;

CREATE TABLE IF NOT EXISTS vuln_cves (
    name TEXT,
    version TEXT,
    architecture TEXT,
    cve TEXT,
    reference TEXT DEFAULT '' NOT NULL,
    type TEXT DEFAULT 'UNDEFINED' NOT NULL CHECK (type IN ('OS', 'PACKAGE','UNDEFINED')),
    status TEXT DEFAULT 'PENDING' NOT NULL CHECK (status IN ('VALID', 'PENDING', 'OBSOLETE')),
    PRIMARY KEY (reference, cve)
);
CREATE INDEX IF NOT EXISTS packages_id ON vuln_cves (name);
CREATE INDEX IF NOT EXISTS cves_id ON vuln_cves (cve);
CREATE INDEX IF NOT EXISTS cve_type ON vuln_cves (type);
CREATE INDEX IF NOT EXISTS cve_status ON vuln_cves (status);

UPDATE vuln_metadata SET LAST_SCAN = '0';

INSERT OR REPLACE INTO metadata (key, value) VALUES ('db_version', 8);
