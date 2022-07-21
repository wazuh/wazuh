/*
 * SQL Schema for upgrading databases
 * Copyright (C) 2015, Wazuh Inc.
 * July, 2019.
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
*/

BEGIN;

ALTER TABLE sys_programs ADD COLUMN cpe TEXT DEFAULT NULL;
ALTER TABLE sys_programs ADD COLUMN msu_name TEXT DEFAULT NULL;
ALTER TABLE sys_osinfo ADD COLUMN os_release TEXT DEFAULT NULL;
ALTER TABLE sca_check ADD COLUMN condition TEXT;

UPDATE metadata SET value = 3 WHERE key = 'db_version';

CREATE TABLE IF NOT EXISTS sys_hotfixes (
    scan_id INTEGER,
    scan_time TEXT,
    hotfix TEXT,
    PRIMARY KEY (scan_id, scan_time, hotfix)
);
CREATE INDEX IF NOT EXISTS hotfix_id ON sys_hotfixes (scan_id);

CREATE TABLE IF NOT EXISTS vuln_metadata (
    LAST_SCAN INTEGER,
    WAZUH_VERSION TEXT,
    HOTFIX_SCAN_ID TEXT
);
INSERT INTO vuln_metadata (LAST_SCAN, WAZUH_VERSION, HOTFIX_SCAN_ID)
    SELECT '0', '0', '0' WHERE NOT EXISTS (
        SELECT * FROM vuln_metadata
    );

END;
