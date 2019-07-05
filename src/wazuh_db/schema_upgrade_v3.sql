/*
 * SQL Schema for upgrading databases
 * Copyright (C) 2015-2019, Wazuh Inc.
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
*/

BEGIN;

ALTER TABLE fim_entry ADD COLUMN level0 INTEGER DEFAULT NULL;
ALTER TABLE fim_entry ADD COLUMN level1 INTEGER DEFAULT NULL;
ALTER TABLE fim_entry ADD COLUMN level2 INTEGER DEFAULT NULL;
ALTER TABLE fim_entry ADD COLUMN integrity_checksum TEXT DEFAULT NULL;

UPDATE metadata SET value = 3 WHERE key = 'db_version';

END;
