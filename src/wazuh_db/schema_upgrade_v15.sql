/*
 * SQL Schema for upgrading databases
 * Copyright (C) 2015, Wazuh Inc.
 *
 * March 15, 2024.
 *
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
*/

BEGIN;

DROP INDEX IF EXISTS fim_full_path_index;
DROP INDEX IF EXISTS fim_file_index;
DROP INDEX IF EXISTS fim_type_full_path_index;
DROP INDEX IF EXISTS fim_type_file_index;
DROP INDEX IF EXISTS fim_date_index;

INSERT OR REPLACE INTO metadata (key, value) VALUES ('db_version', 15);

COMMIT;
