/*
 * SQL Schema for upgrading databases
 * Copyright (C) 2015-2021, Wazuh Inc.
 *
 * March 16, 2021.
 *
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
*/

ALTER TABLE sys_osinfo ADD COLUMN reference TEXT NOT NULL CHECK (checksum <> '');
ALTER TABLE sys_osinfo ADD COLUMN triaged INTEGER(1) DEFAULT 0;

DROP TABLE IF EXISTS vuln_cves;

CREATE TABLE IF NOT EXISTS vuln_cves (
    name TEXT,
    version TEXT,
    architecture TEXT,
    cve TEXT,
    reference TEXT DEFAULT '' NOT NULL,
    type TEXT DEFAULT '' NOT NULL CHECK (type IN ('OS', 'PACKAGE')),
    status TEXT DEFAULT 'PENDING' NOT NULL CHECK (status IN ('VALID', 'PENDING', 'OBSOLETE')),
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
