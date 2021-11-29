/*
 * SQL Schema CVE tests
 * Copyright (C) 2015-2021, Wazuh Inc.
 * February 23, 2021.
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
 */

CREATE TABLE IF NOT EXISTS vuln_cves (
    name TEXT,
    version TEXT,
    architecture TEXT,
    cve TEXT,
    detection_time TEXT DEFAULT '',
    severity TEXT DEFAULT '-' CHECK (severity IN ('Critical', 'High', 'Medium', 'Low', 'None', '-')),
    cvss2_score REAL DEFAULT 0,
    cvss3_score REAL DEFAULT 0,
    reference TEXT DEFAULT '' NOT NULL,
    type TEXT DEFAULT '' NOT NULL CHECK (type IN ('OS', 'PACKAGE')),
    status TEXT DEFAULT 'PENDING' NOT NULL CHECK (status IN ('VALID', 'PENDING', 'OBSOLETE')),
    PRIMARY KEY (reference, cve)
);
CREATE INDEX IF NOT EXISTS packages_id ON vuln_cves (name);
CREATE INDEX IF NOT EXISTS cves_id ON vuln_cves (cve);
CREATE INDEX IF NOT EXISTS cve_type ON vuln_cves (type);
CREATE INDEX IF NOT EXISTS cve_status ON vuln_cves (status);

CREATE TABLE IF NOT EXISTS vuln_metadata (
    LAST_PARTIAL_SCAN INTEGER,
    LAST_FULL_SCAN INTEGER
);

BEGIN;

-- Data from https://www.cvedetails.com/vulnerability-list/
INSERT INTO vuln_cves (name,version,architecture,cve,type,status,detection_time,severity,cvss2_score,cvss3_score,reference)
VALUES ('Invenio-previewer', '0.1.0', 'ARM', 'CVE-2019-1020019', 'OS', 'VALID', '1623656751', 'Medium', 4.3, 6.1, '0198aaaadb185181ad323433735248fbf41362b5');

INSERT INTO vuln_cves (name,version,architecture,cve,type,status,detection_time,severity,cvss2_score,cvss3_score,reference)
VALUES ('Discourse', '0.8.0', 'PowerPC', 'CVE-2019-1020018', 'OS', 'VALID', '1623656751', 'High', 7.5, 7.3, '24cbb88312a71cc2fee7b9fb545cfd404ea7c9a8');

INSERT INTO vuln_cves (name,version,architecture,cve,type,status,detection_time,severity,cvss2_score,cvss3_score,reference)
VALUES ('Ash-aio', '2.0.0.0', 'x86', 'CVE-2019-1020016', 'OS', 'OBSOLETE', '1623656751', 'Low', 1.9, 2.5, 'fe22d729473dc47625a583dd97e1d3a779105b19');

INSERT INTO vuln_cves (name,version,architecture,cve,type,status,detection_time,severity,cvss2_score,cvss3_score,reference)
VALUES ('Credential Helpers', '0.1.0', 'x86', 'CVE-2019-1020014', 'PACKAGE', 'OBSOLETE', '1623656949', 'Critical', 7.5, 9.8, '2783fabf4b0d5b5f3217703fb24bb75ec58a8ce3');

INSERT INTO vuln_cves (name,version,architecture,cve,type,status,detection_time,severity,cvss2_score,cvss3_score,reference)
VALUES ('Smokedetector', '-', 'x86', 'CVE-2019-1020011', 'PACKAGE', 'PENDING', '1623656949', 'High', 6.8, 8.1, 'e0680fb636baccbb7484f7b3daf5b4c0ce485960');

INSERT INTO vuln_metadata (LAST_PARTIAL_SCAN, LAST_FULL_SCAN) VALUES (1623656949, 1623656751);
