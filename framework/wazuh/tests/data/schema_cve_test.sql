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
    PRIMARY KEY (name, version, architecture, cve)
);
CREATE INDEX IF NOT EXISTS packages_id ON vuln_cves (name);
CREATE INDEX IF NOT EXISTS cves_id ON vuln_cves (cve);

BEGIN;

-- Data from https://www.cvedetails.com/vulnerability-list/
INSERT INTO vuln_cves (name,version,architecture,cve) VALUES ('Invenio-previewer', '0.1.0', 'ARM', 'CVE-2019-1020019');
INSERT INTO vuln_cves (name,version,architecture,cve) VALUES ('Discourse', '0.8.0', 'PowerPC', 'CVE-2019-1020018');
INSERT INTO vuln_cves (name,version,architecture,cve) VALUES ('Ash-aio', '2.0.0.0', 'x86', 'CVE-2019-1020016');
INSERT INTO vuln_cves (name,version,architecture,cve) VALUES ('Credential Helpers', '0.1.0', 'x86', 'CVE-2019-1020014');
INSERT INTO vuln_cves (name,version,architecture,cve) VALUES ('Smokedetector', '-', 'x86', 'CVE-2019-1020011');
