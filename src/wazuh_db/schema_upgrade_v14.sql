/*
 * SQL Schema for upgrading databases
 * Copyright (C) 2015, Wazuh Inc.
 *
 * March 15, 2024.
 *
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
*/

BEGIN;

CREATE TABLE IF NOT EXISTS _sys_programs (
    scan_id INTEGER,
    scan_time TEXT,
    format TEXT,
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
    cpe TEXT,
    msu_name TEXT,
    checksum TEXT NOT NULL CHECK (checksum <> ''),
    item_id TEXT,
    PRIMARY KEY (scan_id, name, version, architecture, format, location)
);

INSERT INTO _sys_programs
    SELECT scan_id, scan_time, CASE WHEN format IS NOT NULL THEN format ELSE '' END AS format,
    name, priority, section, size, vendor, install_time, version, architecture, multiarch, source, description,
    CASE WHEN location IS NOT NULL THEN location ELSE '' END AS location, cpe, msu_name,
    CASE WHEN checksum <> '' THEN checksum ELSE 'legacy' END AS checksum, item_id FROM sys_programs;

DROP TABLE IF EXISTS sys_programs;
ALTER TABLE _sys_programs RENAME TO sys_programs;
CREATE INDEX IF NOT EXISTS programs_id ON sys_programs (scan_id);

CREATE TABLE IF NOT EXISTS _sys_hotfixes (
    scan_id INTEGER,
    scan_time TEXT,
    hotfix TEXT,
    checksum TEXT NOT NULL CHECK (checksum <> ''),
    PRIMARY KEY (scan_id, hotfix)
);

INSERT INTO _sys_hotfixes
    SELECT scan_id, scan_time, hotfix, CASE WHEN checksum <> '' THEN checksum ELSE 'legacy' END AS checksum FROM sys_hotfixes;

DROP TABLE IF EXISTS sys_hotfixes;
ALTER TABLE _sys_hotfixes RENAME TO sys_hotfixes;
CREATE INDEX IF NOT EXISTS hotfix_id ON sys_hotfixes (scan_id);

CREATE TABLE IF NOT EXISTS _sys_osinfo(
    scan_id INTEGER,
    scan_time TEXT,
    hostname TEXT,
    architecture TEXT,
    os_name TEXT,
    os_version TEXT,
    os_codename TEXT,
    os_major TEXT,
    os_minor TEXT,
    os_patch TEXT,
    os_build TEXT,
    os_platform TEXT,
    sysname TEXT,
    release TEXT,
    version TEXT,
    os_release TEXT,
    checksum TEXT NOT NULL CHECK (checksum <> ''),
    os_display_version TEXT,
    reference TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (scan_id, os_name)
);

INSERT INTO _sys_osinfo
    SELECT scan_id, scan_time, hostname, architecture, os_name, os_version, os_codename, os_major, os_minor, os_patch,
    os_build, os_platform, sysname, release, version, os_release, CASE WHEN checksum <> '' THEN checksum ELSE 'legacy' END AS checksum,
    os_display_version, reference FROM sys_osinfo;

DROP TABLE IF EXISTS sys_osinfo;
ALTER TABLE _sys_osinfo RENAME TO sys_osinfo;

DROP TABLE IF EXISTS vuln_metadata;
DROP TABLE IF EXISTS vuln_cves;

INSERT OR REPLACE INTO metadata (key, value) VALUES ('db_version', 14);

COMMIT;
