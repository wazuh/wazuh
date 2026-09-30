/*
 * SQL Schema for upgrading databases
 * Copyright (C) 2015-2024, Wazuh Inc.
 *
 * September 30, 2026.
 *
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
*/

/*
 * group_hash widened from an 8-character to a 32-character SHA-256 prefix
 * (WDB_GROUP_HASH_SIZE). The column type does not change; existing values
 * are recalculated by wdb_global_adjust_v4() in wdb_adjust_global_upgrade().
 */
UPDATE metadata SET value = '8' WHERE key = 'db_version';
