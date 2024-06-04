/*
 * SQL Schema for upgrading databases
 * Copyright (C) 2015-2024, Wazuh Inc.
 *
 * April, 2024.
 *
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
*/

DELETE FROM labels WHERE id NOT IN (SELECT id FROM agent);

CREATE TABLE IF NOT EXISTS _labels (
    id INTEGER REFERENCES agent (id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (id,key)
);

BEGIN;

INSERT INTO _labels (id, key, value) SELECT id, key, value FROM labels;

END;

DROP TABLE IF EXISTS labels;
ALTER TABLE _labels RENAME TO labels;

UPDATE metadata SET value = '6' where key = 'db_version';
