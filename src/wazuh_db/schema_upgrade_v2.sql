/*
 * SQL Schema for upgrading databases
 * Copyright (C) 2015, Wazuh Inc.
 * February, 2019.
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
*/

BEGIN;

CREATE TABLE IF NOT EXISTS sca_policy (
   name TEXT,
   file TEXT,
   id TEXT,
   description TEXT,
   `references` TEXT,
   hash_file TEXT
);

CREATE TABLE IF NOT EXISTS sca_scan_info (
   id INTEGER PRIMARY KEY,
   start_scan INTEGER,
   end_scan INTEGER,
   policy_id TEXT REFERENCES sca_policy (id),
   pass INTEGER,
   fail INTEGER,
   invalid INTEGER,
   total_checks INTEGER,
   score INTEGER,
   hash TEXT
);

CREATE TABLE IF NOT EXISTS sca_check (
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
   `status` TEXT,
   reason TEXT
);

CREATE INDEX IF NOT EXISTS policy_id_index ON sca_check (policy_id);

CREATE TABLE IF NOT EXISTS sca_check_rules (
  id_check INTEGER REFERENCES sca_check (id),
  `type` TEXT,
  rule TEXT,
  PRIMARY KEY (id_check, `type`, rule)
);

CREATE INDEX IF NOT EXISTS rules_id_check_index ON sca_check_rules (id_check);

CREATE TABLE IF NOT EXISTS sca_check_compliance (
   id_check INTEGER REFERENCES sca_check (id),
  `key` TEXT,
  `value` TEXT,
   PRIMARY KEY (id_check, `key`, `value`)
);

CREATE INDEX IF NOT EXISTS comp_id_check_index ON sca_check_compliance (id_check);

ALTER TABLE sys_netproto ADD COLUMN metric INTEGER DEFAULT NULL;

ALTER TABLE fim_entry ADD COLUMN symbolic_path TEXT DEFAULT NULL;

UPDATE metadata SET value = 2 WHERE key = 'db_version';

END;
