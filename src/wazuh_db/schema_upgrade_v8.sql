/*
 * SQL Schema for upgrading databases
 * Copyright (C) 2015, Wazuh Inc.
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

INSERT INTO _sys_programs SELECT scan_id, scan_time, format, name, priority, section, size, vendor, install_time, version, architecture, multiarch, source, description, location, triaged, cpe, msu_name, CASE WHEN checksum <> '' THEN checksum ELSE 'legacy' END AS checksum, item_id FROM sys_programs;
DROP TABLE IF EXISTS sys_programs;
ALTER TABLE _sys_programs RENAME TO sys_programs;
CREATE INDEX IF NOT EXISTS programs_id ON sys_programs (scan_id);

ALTER TABLE sys_osinfo ADD COLUMN os_display_version TEXT DEFAULT NULL;
ALTER TABLE sys_osinfo ADD COLUMN reference TEXT NOT NULL DEFAULT '';
ALTER TABLE sys_osinfo ADD COLUMN triaged INTEGER(1) DEFAULT 0;
ALTER TABLE sync_info ADD COLUMN last_agent_checksum TEXT NOT NULL DEFAULT '';
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

DROP TABLE IF EXISTS vuln_cves;

CREATE TABLE IF NOT EXISTS vuln_cves (
    name TEXT,
    version TEXT,
    architecture TEXT,
    cve TEXT,
    detection_time TEXT DEFAULT '',
    severity TEXT DEFAULT 'Untriaged' CHECK (severity IN ('Critical', 'High', 'Medium', 'Low', 'None', 'Untriaged')),
    cvss2_score REAL DEFAULT 0,
    cvss3_score REAL DEFAULT 0,
    reference TEXT DEFAULT '' NOT NULL,
    type TEXT DEFAULT '' NOT NULL CHECK (type IN ('OS', 'PACKAGE')),
    status TEXT DEFAULT 'PENDING' NOT NULL CHECK (status IN ('VALID', 'PENDING', 'OBSOLETE')),
    external_references TEXT DEFAULT '',
    condition TEXT DEFAULT '',
    title TEXT DEFAULT '',
    published TEXT '',
    updated TEXT '',
    PRIMARY KEY (reference, cve)
);
CREATE INDEX IF NOT EXISTS packages_id ON vuln_cves (name);
CREATE INDEX IF NOT EXISTS cves_id ON vuln_cves (cve);
CREATE INDEX IF NOT EXISTS cve_type ON vuln_cves (type);
CREATE INDEX IF NOT EXISTS cve_status ON vuln_cves (status);

DROP TABLE IF EXISTS vuln_metadata;

CREATE TABLE IF NOT EXISTS vuln_metadata (
    LAST_PARTIAL_SCAN INTEGER,
    LAST_FULL_SCAN INTEGER
);

INSERT INTO vuln_metadata (LAST_PARTIAL_SCAN, LAST_FULL_SCAN) VALUES (0, 0);

CREATE TRIGGER obsolete_vulnerabilities
    AFTER DELETE ON sys_programs
    WHEN (old.checksum = 'legacy' AND NOT EXISTS (SELECT 1 FROM sys_programs
                                                  WHERE item_id = old.item_id
                                                  AND scan_id != old.scan_id ))
    OR old.checksum != 'legacy'
    BEGIN
        UPDATE vuln_cves SET status = 'OBSOLETE' WHERE vuln_cves.reference = old.item_id;
END;

CREATE TRIGGER hotfix_delete
    AFTER DELETE ON sys_hotfixes
    WHEN (old.checksum = 'legacy' AND NOT EXISTS (SELECT 1 FROM sys_hotfixes
                                                  WHERE hotfix = old.hotfix
                                                  AND scan_id != old.scan_id ))
    OR old.checksum != 'legacy'
    BEGIN
        UPDATE sys_osinfo SET triaged = 0;
END;

CREATE TRIGGER hotfix_insert
    AFTER INSERT ON sys_hotfixes
    WHEN (new.checksum = 'legacy' AND NOT EXISTS (SELECT 1 FROM sys_hotfixes
                                                  WHERE hotfix = new.hotfix
                                                  AND scan_id != new.scan_id ))
    OR new.checksum != 'legacy'
    BEGIN
        UPDATE sys_osinfo SET triaged = 0;
END;

INSERT OR REPLACE INTO metadata (key, value) VALUES ('db_version', 8);
