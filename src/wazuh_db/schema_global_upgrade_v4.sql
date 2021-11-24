/*
 * SQL Schema for upgrading databases
 * Copyright (C) 2015-2021, Wazuh Inc.
 *
 * November, 2021.
 *
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
*/

CREATE TABLE IF NOT EXISTS _belongs (
    id_agent INTEGER REFERENCES agent (id) ON DELETE CASCADE,
    id_group INTEGER REFERENCES `group`(id),
    PRIMARY KEY (id_agent, id_group)
);

CREATE INDEX IF NOT EXISTS belongs_id_agent ON belongs (id_agent);
CREATE INDEX IF NOT EXISTS belongs_id_group ON belongs (id_group);

BEGIN;

INSERT INTO _belongs (id_agent, id_group) SELECT id_agent, id_group FROM belongs WHERE id_agent IN (SELECT id FROM agent) AND id_group IN (SELECT id FROM `group`);

END;

DROP TABLE IF EXISTS belongs;
ALTER TABLE _belongs RENAME TO belongs;

ALTER TABLE agent ADD COLUMN groups_hash TEXT default NULL;
CREATE INDEX IF NOT EXISTS agent_name ON agent (name);
CREATE INDEX IF NOT EXISTS agent_ip ON agent (ip);
CREATE INDEX IF NOT EXISTS agent_groups_hash ON agent (groups_hash);

UPDATE metadata SET value = '4' where key = 'db_version';
