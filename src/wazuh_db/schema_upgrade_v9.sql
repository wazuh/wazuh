/*
 * SQL Schema for upgrading databases
 * Copyright (C) 2015, Wazuh Inc.
 *
 * June 27, 2022
 *
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
*/


DROP TABLE IF EXISTS sys_hotfixes;

CREATE TABLE IF NOT EXISTS sys_hotfixes (
    scan_id INTEGER,
    scan_time TEXT,
    hotfix TEXT,
    checksum TEXT NOT NULL CHECK (checksum <> ''),
    PRIMARY KEY (scan_id, hotfix)
);

CREATE INDEX IF NOT EXISTS hotfix_id ON sys_hotfixes (scan_id);

