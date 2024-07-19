/*
 * SQL Schema for upgrading databases
 * Copyright (C) 2015, Wazuh Inc.
 *
 * February 19, 2024.
 *
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
*/

BEGIN;

CREATE INDEX IF NOT EXISTS fim_type_full_path_index ON fim_entry (type, full_path);
CREATE INDEX IF NOT EXISTS fim_type_file_index ON fim_entry (type, file);
CREATE INDEX IF NOT EXISTS fim_type_full_path_checksum_index ON fim_entry(type,full_path,checksum);
CREATE INDEX IF NOT EXISTS fim_type_file_checksum_index ON fim_entry(type,file,checksum);

INSERT OR REPLACE INTO metadata (key, value) VALUES ('db_version', 13);

COMMIT;
