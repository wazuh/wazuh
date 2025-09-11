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

// This function performs those data migrations between
// updates that cannot be resolved with queries
static int wdb_adjust_global_upgrade(wdb_t *wdb, int upgrade_step);

/* SQL statements used for the global.db upgrade */
typedef enum wdb_stmt_global {
    WDB_STMT_GLOBAL_CHECK_MANAGER_KEEPALIVE,
} wdb_stmt_global;

static const char *SQL_GLOBAL_STMT[] = {
    "SELECT COUNT(*) FROM agent WHERE id=0 AND last_keepalive=253402300799;",
};

wdb_t * wdb_upgrade_global(wdb_t *wdb) {
    const char * UPDATES[] = {
        schema_global_upgrade_v1_sql,
        schema_global_upgrade_v2_sql,
        schema_global_upgrade_v3_sql,
        schema_global_upgrade_v4_sql,
        schema_global_upgrade_v5_sql,
        schema_global_upgrade_v6_sql,
        schema_global_upgrade_v7_sql,
    };

    char output[OS_MAXSTR + 1] = { 0 };
    char db_version[OS_SIZE_256 + 2];
    int version = 0;
    int updates_length = (int)(sizeof(UPDATES) / sizeof(char *));

    int count = 0;
    if (wdb_count_tables_with_name(wdb, "metadata", &count) == OS_SUCCESS) {
        if (0 < count) {
            if (wdb_metadata_get_entry(wdb, "db_version", db_version) == OS_SUCCESS) {
                version = atoi(db_version);
            }
            else {
                /**
                 * We can't determine if the database should be upgraded. If we
                 * allow the usage, we could have many errors because of an
                 * operation over an old database version. We should block the
                 * usage until determine whether we should upgrade or not.
                 */
                mwarn("DB(%s): Error trying to get DB version", wdb->id);
                wdb->enabled = false;
            }
        }
        else {
            /*
             * The table does not exist which could mean that we have and old
             * version of the db. If we have an older version than 3.10 we can
             * recreate the global.db database and not lose critical data.
             */
            if (wdb_is_older_than_v310(wdb)) {
                if (OS_SUCCESS != wdb_global_create_backup(wdb, output, "-pre_upgrade")) {
                    merror("Creating pre-upgrade Global DB snapshot failed: %s", output);
                    wdb->enabled = false;
                }
                else {
                    wdb = wdb_recreate_global(wdb);
                }

                return wdb;
            }
        }
    }
    else {
        /*
         * An error occurred trying to get the table count and so we can't
         * determine if the database should be upgraded. If we allow the
         * database usage, we could have many errors because of an operation
         * over an old or corrupted database. If we recreate the database, we
         * have the risk of loosing data of the newer database versions. Instead
         * we block the usage until we can determine whether we should upgrade
         * or not.
         */
        merror("DB(%s) Error trying to find metadata table", wdb->id);
        wdb->enabled = false;
        return wdb;
    }

    if (version < updates_length) {
        if (OS_SUCCESS != wdb_global_create_backup(wdb, output, "-pre_upgrade")) {
            merror("Creating pre-upgrade Global DB snapshot failed: %s", output);
            wdb->enabled = false;
        }
        else {
            for (int i = version; i < updates_length; i++) {
                mdebug2("Updating database '%s' to version %d", wdb->id, i + 1);
                if (wdb_sql_exec(wdb, UPDATES[i]) == OS_INVALID ||
                    wdb_adjust_global_upgrade(wdb, i)) {
                    if (OS_INVALID != wdb_global_restore_backup(&wdb, NULL, false, output)) {
                        merror("Failed to update global.db to version %d. The global.db was "
                               "restored to the original state.",
                               i + 1);
                    }
                    else {
                        merror("Failed to update global.db to version %d.", i + 1);
                        wdb->enabled = false;
                    }
                    break;
                }
            }
        }
    }

    return wdb;
}

wdb_t * wdb_recreate_global(wdb_t *wdb) {
    char path[PATH_MAX];

    snprintf(path, PATH_MAX, "%s/%s.db", WDB2_DIR, WDB_GLOB_NAME);

    if (wdb_close(wdb, TRUE) != OS_INVALID) {
        unlink(path);

        if (OS_SUCCESS != wdb_create_global(path)) {
            merror("Couldn't create SQLite database '%s'", path);
            return NULL;
        }

        if (sqlite3_open_v2(path, &wdb->db, SQLITE_OPEN_READWRITE, NULL)) {
            merror("Can't open SQLite backup database '%s': %s", path, sqlite3_errmsg(wdb->db));
            sqlite3_close_v2(wdb->db);
            wdb->db = NULL;
            return NULL;
        }
    }

    return wdb;
}

int wdb_adjust_global_upgrade(wdb_t *wdb, int upgrade_step) {
    switch (upgrade_step) {
        case 3:
            return wdb_global_adjust_v4(wdb);
        default:
            return 0;
    }
}

bool wdb_is_older_than_v310(wdb_t *wdb) {
    sqlite3_stmt *stmt = NULL;
    int result = OS_INVALID;

    if (sqlite3_prepare_v2(wdb->db, SQL_GLOBAL_STMT[WDB_STMT_GLOBAL_CHECK_MANAGER_KEEPALIVE], -1, &stmt, NULL) !=
        SQLITE_OK) {
        merror("DB(%s) sqlite3_prepare_v2(): %s", wdb->id, sqlite3_errmsg(wdb->db));
    }
    else {
        switch (wdb_step(stmt)) {
            case SQLITE_ROW: {
                result = sqlite3_column_int(stmt, 0);
                break;
            }
            case SQLITE_DONE: {
                result = OS_SUCCESS;
                break;
            }
            default: {
                result = OS_INVALID;
                break;
            }
        }
        sqlite3_finalize(stmt);
    }

    return (result != 1);
}
