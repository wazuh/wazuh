/*
 * SQL Schema for upgrading databases
 * Copyright (C) 2015-2021, Wazuh Inc.
 *
 * March 16, 2021.
 *
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
*/

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
