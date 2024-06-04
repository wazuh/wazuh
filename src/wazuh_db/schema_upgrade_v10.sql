/*
 * SQL Schema for upgrading databases
 * Copyright (C) 2015, Wazuh Inc.
 *
 * Dec 22, 2022
 *
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
*/

UPDATE sca_check SET result='not applicable' WHERE status='Not applicable';
ALTER TABLE sca_check DROP COLUMN status;

INSERT OR REPLACE INTO metadata (key, value) VALUES ('db_version', 10);
