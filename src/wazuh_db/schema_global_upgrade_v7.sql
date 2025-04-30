/*
 * SQL Schema for upgrading databases
 * Copyright (C) 2015-2024, Wazuh Inc.
 *
 * April 30, 2025.
 *
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
*/

BEGIN;

INSERT OR IGNORE INTO `group` (name) VALUES ('default');

UPDATE agent SET `group` = 'default' WHERE `group` IS NULL AND id != 0;

WITH default_group AS (
    SELECT id AS id_group FROM `group` WHERE name = 'default'
) INSERT INTO belongs (id_agent, id_group, priority)
SELECT agent.id, dg.id_group, 0 FROM agent CROSS JOIN default_group dg WHERE agent.id != 0 AND NOT EXISTS (
    SELECT 1 FROM belongs WHERE belongs.id_agent = agent.id
);

UPDATE metadata SET value = '7' WHERE key = 'db_version';

END;
