/*
 * SQL Schema for upgrading databases
 * Copyright (C) 2015-2019, Wazuh Inc.
 * February, 2019.
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
*/

BEGIN;

ALTER TABLE sys_netproto ADD COLUMN metric INTEGER DEFAULT NULL;

UPDATE metadata SET value = 2 WHERE key = 'db_version';

END;