/*
 * SQL Schema for upgrading databases
 * Copyright (C) 2015, Wazuh Inc.
 *
 * February 1, 2023.
 *
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
*/

BEGIN;

CREATE TABLE IF NOT EXISTS _sys_hwinfo (
    scan_id INTEGER,
    scan_time TEXT,
    format TEXT NOT NULL CHECK (format IN ('pacman', 'deb', 'rpm', 'win', 'pkg', 'apk', 'snap')),
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
    PRIMARY KEY (scan_id, board_serial)
);

INSERT INTO _sys_hwinfo (scan_id, scan_time, board_serial, cpu_name, cpu_cores,
                         cpu_mhz, ram_total, ram_free, ram_usage, checksum)
    SELECT scan_id, scan_time, board_serial, cpu_name, cpu_cores, cpu_mhz,
           ram_total, ram_free, ram_usage, CASE WHEN checksum <> '' THEN
           checksum ELSE 'legacy' END AS checksum
    FROM sys_hwinfo;

DROP TABLE sys_hwinfo;
ALTER TABLE _sys_hwinfo RENAME TO sys_hwinfo;

INSERT OR REPLACE INTO metadata (key, value) VALUES ('db_version', 11);

COMMIT;
