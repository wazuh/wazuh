/*
 * SQL Schema for upgrading databases
 * Copyright (C) 2015-2019, Wazuh Inc.
 * February, 2019.
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
*/

BEGIN;

CREATE TABLE IF NOT EXISTS configuration_assessment_policy (
   name TEXT,
   file TEXT,
   id TEXT,
   description TEXT,
   `references` TEXT
);

CREATE TABLE IF NOT EXISTS configuration_assessment_scan_info (
   id INTEGER PRIMARY KEY,
   start_scan INTEGER,
   end_scan INTEGER,
   policy_id TEXT REFERENCES configuration_assessment_policy (id),
   pass INTEGER,
   fail INTEGER,
   score INTEGER,
   hash TEXT
);

CREATE TABLE IF NOT EXISTS configuration_assessment_check (
   scan_id INTEGER REFERENCES configuration_assessment_scan_info (id),
   id INTEGER PRIMARY KEY,
   policy_id TEXT REFERENCES configuration_assessment_policy (id),
   title TEXT,
   description TEXT,
   rationale TEXT,
   remediation TEXT,
   file TEXT,
   process TEXT,
   directory TEXT,
   registry TEXT,
   `references` TEXT,
   result TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS policy_id_index ON configuration_assessment_check (policy_id);

CREATE TABLE IF NOT EXISTS configuration_assessment_check_compliance (
   id_check INTEGER REFERENCES configuration_assessment_check (id),
  `key` TEXT,
  `value` TEXT,
   PRIMARY KEY (id_check, `key`, `value`)
);

CREATE INDEX IF NOT EXISTS id_check_index ON configuration_assessment_check_compliance (id_check);

ALTER TABLE sys_netproto ADD COLUMN metric INTEGER DEFAULT NULL;

UPDATE metadata SET value = 2 WHERE key = 'db_version';

END;