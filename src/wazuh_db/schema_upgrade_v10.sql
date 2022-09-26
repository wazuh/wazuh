/*
 * SQL Schema for upgrading databases
 * Copyright (C) 2015, Wazuh Inc.
 *
 * Sep 22, 2022
 *
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
*/

ALTER TABLE metadata ADD COLUMN last_vacuum_time INTEGER DEFAULT NULL;
ALTER TABLE metadata ADD COLUMN last_fragmentation_value INTEGER DEFAULT NULL;

INSERT OR REPLACE INTO metadata (key, value) VALUES ('db_version', 10);
