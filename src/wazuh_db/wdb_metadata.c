/*
 * Wazuh SQLite integration
 * Copyright (C) 2015, Wazuh Inc.
 * June 06, 2016.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wdb.h"


typedef enum wdb_stmt_metadata {
    WDB_STMT_METADATA_FIND,
    WDB_STMT_METADATA_TABLE_CHECK
} wdb_stmt_metadata;

static const char *SQL_METADATA_STMT[] = {
    "SELECT value FROM metadata WHERE key = ?;",
    "SELECT count(name) FROM sqlite_master WHERE type='table' AND name=?;"
};

int wdb_metadata_get_entry(wdb_t * wdb, const char *key, char *output) {
    sqlite3_stmt *stmt = NULL;

    if (sqlite3_prepare_v2(wdb->db,
                           SQL_METADATA_STMT[WDB_STMT_METADATA_FIND],
                           -1,
                           &stmt,
                           NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_prepare_v2(): %s",
               wdb->id,
               sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    sqlite3_bind_text(stmt, 1, key, -1, NULL);

    int ret = OS_INVALID;
    switch (wdb_step(stmt)) {
        case SQLITE_ROW: {
            strncpy(output, (char *)sqlite3_column_text(stmt, 0), OS_SIZE_256);
            ret = OS_SUCCESS;
            break;
        }
        case SQLITE_DONE: {
            strncpy(output, "0", OS_SIZE_256);
            ret = OS_NOTFOUND;
            break;
        }
        default: {
            mdebug1("DB(%s) SQLite: %s",
                    wdb->id,
                    sqlite3_errmsg(wdb->db));
            ret = OS_INVALID;
            break;
        }
    }

    sqlite3_finalize(stmt);
    return ret;
}

int wdb_count_tables_with_name(wdb_t * wdb, const char * key, int* count) {
    sqlite3_stmt *stmt = NULL;

    if (sqlite3_prepare_v2(wdb->db, SQL_METADATA_STMT[WDB_STMT_METADATA_TABLE_CHECK], -1, &stmt, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_prepare_v2(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    if (sqlite3_bind_text(stmt, 1, key, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        sqlite3_finalize(stmt);
        return OS_INVALID;
    }

    int ret = OS_INVALID;
    switch (wdb_step(stmt)) {
        case SQLITE_ROW: {
            *count = sqlite3_column_int(stmt, 0);
            ret = OS_SUCCESS;
        } break;
        default: {
            mdebug1("DB(%s) SQLite: %s", wdb->id, sqlite3_errmsg(wdb->db));
        }
    }

    sqlite3_finalize(stmt);
    return ret;
}
