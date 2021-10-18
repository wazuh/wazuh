/*
 * SQL Schema for upgrading databases
 * Copyright (C) 2015-2021, Wazuh Inc.
 *
 * October, 2021.
 *
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
*/

BEGIN;

CREATE TABLE IF NOT EXISTS _belongs (
    id_agent INTEGER REFERENCES agent (id) ON DELETE CASCADE,
    id_group INTEGER,
    PRIMARY KEY (id_agent, id_group)
);

INSERT INTO _belongs (id_agent, id_group) SELECT id_agent, id_group FROM belongs WHERE id_agent IN (SELECT id FROM agent);
UPDATE metadata SET value = '3' where key = 'db_version';

DROP TABLE IF EXISTS belongs;
ALTER TABLE _belongs RENAME TO belongs;

END;
