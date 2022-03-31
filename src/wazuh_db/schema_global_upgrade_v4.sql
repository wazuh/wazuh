/*
 * SQL Schema for upgrading databases
 * Copyright (C) 2015, Wazuh Inc.
 *
 * February, 2022.
 *
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
*/

BEGIN;

ALTER TABLE agent ADD COLUMN group_config_status TEXT NOT NULL CHECK (group_config_status IN ('synced', 'not synced')) DEFAULT 'not synced';

UPDATE metadata SET value = '4' where key = 'db_version';

END;
