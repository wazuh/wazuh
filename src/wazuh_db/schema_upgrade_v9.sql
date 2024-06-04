/*
 * SQL Schema for upgrading databases
 * Copyright (C) 2015, Wazuh Inc.
 *
 * Jun 27, 2022
 *
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
*/

CREATE TABLE IF NOT EXISTS _sys_hotfixes (
    scan_id INTEGER,
    scan_time TEXT,
    hotfix TEXT,
    checksum TEXT NOT NULL CHECK (checksum <> ''),
    PRIMARY KEY (scan_id, hotfix)
);

INSERT INTO _sys_hotfixes SELECT scan_id, min(scan_time) AS scan_time, hotfix, CASE WHEN checksum <> '' THEN checksum ELSE 'legacy' END AS checksum FROM sys_hotfixes WHERE hotfix IS NOT NULL GROUP BY scan_id, hotfix;

DROP TABLE IF EXISTS sys_hotfixes;

ALTER TABLE _sys_hotfixes RENAME TO sys_hotfixes;

CREATE INDEX IF NOT EXISTS hotfix_id ON sys_hotfixes (scan_id);

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

INSERT OR REPLACE INTO metadata (key, value) VALUES ('db_version', 9);
