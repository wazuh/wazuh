/*
 * Wazuh SQLite integration
 * Copyright (C) 2015, Wazuh Inc.
 * December 12, 2018.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */


#include "wdb.h"


wdb_t * wdb_upgrade_global(wdb_t *wdb) {
    /* Sequential upgrade scripts for global.db.
     * UPDATES[i] migrates the schema from user_version i+1 to i+2.
     * The expected version after all upgrades is (1 + ARRAY_LEN).
     *
     * To add a new upgrade step:
     *   1. Create schemas/schema_global_upgrade_vN.sql
     *   2. Declare `extern char *schema_global_upgrade_vN_sql;` above this function.
     *   3. Append schema_global_upgrade_vN_sql before the NULL sentinel below.
     *   4. Add the corresponding unit tests in test_wdb_upgrade.c.
     */
    const char * UPDATES[] = {
        NULL  /* sentinel */
    };

    int version = 0;
    int updates_length = (int)(sizeof(UPDATES) / sizeof(char *)) - 1;
    int latest_version = 1 + updates_length;

    if (wdb_user_version_get(wdb, &version) != OS_SUCCESS) {
        merror("DB(%s) Error reading schema version.", wdb->id);
        wdb->enabled = false;
        return wdb;
    }

    if (version < 1 || version > latest_version) {
        merror("DB(%s) Unsupported schema version %d (expected: 1..%d). Disabling database.",
               wdb->id, version, latest_version);
        wdb->enabled = false;
        return wdb;
    }

    if (version < latest_version) {
        char output[OS_MAXSTR + 1] = { 0 };
        if (OS_SUCCESS != wdb_global_create_backup(wdb, output, "-pre_upgrade")) {
            merror("Creating pre-upgrade Global DB snapshot failed: %s", output);
            wdb->enabled = false;
        }
        else {
            for (int i = version - 1; i < updates_length; i++) {
                int next_version = i + 2;
                mdebug2("Updating database '%s' to version %d", wdb->id, next_version);
                if (wdb_sql_exec(wdb, UPDATES[i]) == OS_INVALID) {
                    if (OS_INVALID != wdb_global_restore_backup(&wdb, NULL, false, output)) {
                        merror("Failed to update global.db to version %d. The global.db was "
                               "restored to the original state.",
                               next_version);
                    }
                    else {
                        merror("Failed to update global.db to version %d.", next_version);
                        wdb->enabled = false;
                    }
                    break;
                }
            }
        }
    }

    return wdb;
}


