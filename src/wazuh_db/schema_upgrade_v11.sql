/*
 * SQL Schema for upgrading databases
 * Copyright (C) 2015, Wazuh Inc.
 *
 * Aug 14, 2023
 *
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
*/

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
    triaged INTEGER(1),
    cpe TEXT,
    msu_name TEXT,
    checksum TEXT NOT NULL CHECK (checksum <> ''),
    item_id TEXT,
    PRIMARY KEY (scan_id, name, version, architecture, format, location)
);

INSERT INTO _sys_programs
    SELECT scan_id, scan_time, CASE WHEN format IS NOT NULL THEN format ELSE '' END AS format,
                   name, priority, section, size, vendor, install_time, version, architecture, multiarch, source, description,
                   CASE WHEN location IS NOT NULL THEN location ELSE '' END AS location, triaged, cpe, msu_name,
                   CASE WHEN checksum <> '' THEN checksum ELSE 'legacy' END AS checksum, item_id FROM sys_programs;
DROP TABLE IF EXISTS sys_programs;
ALTER TABLE _sys_programs RENAME TO sys_programs;

CREATE INDEX IF NOT EXISTS programs_id ON sys_programs (scan_id);

CREATE TRIGGER obsolete_vulnerabilities
    AFTER DELETE ON sys_programs
    WHEN (old.checksum = 'legacy' AND NOT EXISTS (SELECT 1 FROM sys_programs
                                                  WHERE item_id = old.item_id
                                                  AND scan_id != old.scan_id ))
    OR old.checksum != 'legacy'
    BEGIN
        UPDATE vuln_cves SET status = 'OBSOLETE' WHERE vuln_cves.reference = old.item_id;
END;

INSERT OR REPLACE INTO metadata (key, value) VALUES ('db_version', 11);
