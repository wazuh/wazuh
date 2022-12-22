/*
 * SQL Schema for upgrading databases
 * Copyright (C) 2015, Wazuh Inc.
 *
 * Dec 22, 2022
 *
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
*/

CREATE TABLE IF NOT EXISTS _sca_check (
   scan_id INTEGER REFERENCES sca_scan_info (id),
   id INTEGER PRIMARY KEY,
   policy_id TEXT REFERENCES sca_policy (id),
   title TEXT,
   description TEXT,
   rationale TEXT,
   remediation TEXT,
   file TEXT,
   process TEXT,
   directory TEXT,
   registry TEXT,
   command TEXT,
   `references` TEXT,
   result TEXT,
   reason TEXT,
   condition TEXT
);

INSERT INTO _sca_check SELECT scan_id, id, policy_id, title, description, rationale, remediation, file, process, directory, registry, command, `references`, CASE WHEN result <> '' THEN result ELSE 'not applicable' END AS result, reason, condition FROM sca_check;

DROP TABLE IF EXISTS sca_check;

ALTER TABLE _sca_check RENAME TO sca_check;

CREATE INDEX IF NOT EXISTS policy_id_index ON sca_check (policy_id);

INSERT OR REPLACE INTO metadata (key, value) VALUES ('db_version', 10);
