/*
 * SQL Schema for upgrading databases
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * February 17, 2021.
 *
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

INSERT OR REPLACE INTO metadata (key, value) VALUES ('db_version', 8);
