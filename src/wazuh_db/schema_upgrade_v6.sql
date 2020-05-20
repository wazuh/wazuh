/*
 * SQL Schema for upgrading databases
 * Copyright (C) 2015-2019, Wazuh Inc.
 * December, 2019.
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
*/

BEGIN;

UPDATE metadata SET value = 5 WHERE key = 'db_version';

CREATE TABLE IF NOT EXISTS sys_scan_info (
   inventory TEXT PRIMARY KEY,
   timestamp INTEGER,
   items INTEGER
);

END;