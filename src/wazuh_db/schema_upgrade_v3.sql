/*
 * SQL Schema for upgrading databases
 * Copyright (C) 2015-2019, Wazuh Inc.
 * December, 2018.
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
*/

BEGIN;

ALTER TABLE sys_programs ADD COLUMN cpe TEXT DEFAULT NULL;
ALTER TABLE sys_programs ADD COLUMN msb_name TEXT DEFAULT NULL;
ALTER TABLE sys_osinfo ADD COLUMN os_release TEXT DEFAULT NULL;

UPDATE metadata SET value = 3 WHERE key = 'db_version';

END;