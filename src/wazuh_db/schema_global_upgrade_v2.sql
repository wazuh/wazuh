/*
 * SQL Schema for upgrading databases
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * October, 2020.
 *
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
*/


BEGIN;

ALTER TABLE agent ADD COLUMN connection_status TEXT NOT NULL CHECK (connection_status IN ('pending', 'never_connected', 'active', 'disconnected')) DEFAULT 'never_connected';
UPDATE agent SET connection_status = CASE WHEN id = 0 THEN 'active' WHEN last_keepalive IS NOT NULL THEN 'disconnected' ELSE 'never_connected' END;
UPDATE metadata SET value = '2' where key = 'db_version';

END;


