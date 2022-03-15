/*
 * SQL Schema CVE tests
 * Copyright (C) 2015, Wazuh Inc.
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

CREATE TABLE IF NOT EXISTS vuln_metadata (
    LAST_PARTIAL_SCAN INTEGER,
    LAST_FULL_SCAN INTEGER
);

BEGIN;

-- Data from https://www.cvedetails.com/vulnerability-list/
INSERT INTO vuln_cves (name, version, architecture, cve, type, status, detection_time, severity, cvss2_score,
                       cvss3_score, reference, external_references, condition, title, published, updated)
VALUES ('Invenio-previewer', '0.1.0', 'ARM', 'CVE-2019-1020019', 'OS', 'VALID', '1623656751', 'Medium', 4.3, 6.1,
        '0198aaaadb185181ad323433735248fbf41362b5',
        '["https://github.com/inveniosoftware/invenio-previewer/security/advisories/GHSA-j9m2-6hq2-4r3c"]',
        'Package unfixed', 'invenio-previewer before 1.0.0a12 allows XSS.', '2019-07-29', '2019-07-31');

INSERT INTO vuln_cves (name, version, architecture, cve, type, status, detection_time, severity, cvss2_score,
                       cvss3_score, reference, external_references, condition, title, published, updated)
VALUES ('Discourse', '0.8.0', 'PowerPC', 'CVE-2019-1020018', 'OS', 'VALID', '1623656751', 'High', 7.5, 7.3,
        '24cbb88312a71cc2fee7b9fb545cfd404ea7c9a8',
        '["https://github.com/discourse/discourse/commit/b8340c6c8e50a71ff1bca9654b9126ca5a84ce9a","https://github.com/discourse/discourse/commit/52387be4a44cdeaca5421ee955ba1343e836bade"]',
        'Package unfixed',
        'Discourse before 2.3.0 and 2.4.x before 2.4.0.beta3 lacks a confirmation screen when logging in via an email link.',
        '2019-07-29', '2021-07-21');

INSERT INTO vuln_cves (name, version, architecture, cve, type, status, detection_time, severity, cvss2_score,
                       cvss3_score, reference, external_references, condition, title, published, updated)
VALUES ('Ash-aio', '2.0.0.0', 'x86', 'CVE-2019-1020016', 'OS', 'OBSOLETE', '1623656751', 'Low', 1.9, 2.5,
        'fe22d729473dc47625a583dd97e1d3a779105b19',
        '["https://github.com/ASHTeam/ash-aio-2/security/advisories/GHSA-cg3m-qj5v-8g48"]', 'Package unfixed',
        'ASH-AIO before 2.0.0.3 allows an open redirect.', '2019-07-29', '2019-08-01');

INSERT INTO vuln_cves (name, version, architecture, cve, type, status, detection_time, severity, cvss2_score,
                       cvss3_score, reference, external_references, condition, title, published, updated)
VALUES ('Credential Helpers', '0.1.0', 'x86', 'CVE-2019-1020014', 'PACKAGE', 'OBSOLETE', '1623656949', 'Critical', 7.5,
        9.8, '2783fabf4b0d5b5f3217703fb24bb75ec58a8ce3',
        '["https://usn.ubuntu.com/4103-1/","https://github.com/docker/docker-credential-helpers/releases/tag/v0.6.3","https://usn.ubuntu.com/4103-2/","https://github.com/docker/docker-credential-helpers/commit/1c9f7ede70a5ab9851f4c9cb37d317fd89cd318a","https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6VVFB6UWUK2GQQN7DVUU6GRRAL637A73/"]',
        'Package unfixed','docker-credential-helpers before 0.6.3 has a double free in the List functions.',
        '2019-07-29', '2021-01-14');

INSERT INTO vuln_cves (name, version, architecture, cve, type, status, detection_time, severity, cvss2_score,
                       cvss3_score, reference, external_references, condition, title, published, updated)
VALUES ('Smokedetector', '-', 'x86', 'CVE-2019-1020011', 'PACKAGE', 'PENDING', '1623656949', 'High', 6.8, 8.1,
        'e0680fb636baccbb7484f7b3daf5b4c0ce485960',
        '["https://github.com/Charcoal-SE/SmokeDetector/security/advisories/GHSA-5w85-7mwr-v44q"]',
        'Package unfixed',
        'SmokeDetector intentionally does automatic deployments of updated copies of SmokeDetector without server operator authority.',
        '2019-07-29', '2021-07-21');

INSERT INTO vuln_metadata (LAST_PARTIAL_SCAN, LAST_FULL_SCAN)
VALUES (1623656949, 1623656751);
