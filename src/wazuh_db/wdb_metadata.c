/*
 * Wazuh SQLite integration
 * Copyright (C) 2015-2019, Wazuh Inc.
 * June 06, 2016.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wdb.h"


typedef enum wdb_stmt_metadata {
    WDB_STMT_METADATA_INSERT,
    WDB_STMT_METADATA_UPDATE,
    WDB_STMT_METADATA_FIND
} wdb_stmt_metadata;

static const char *SQL_METADATA_STMT[] = {
    "INSERT INTO metadata (key, value) VALUES (?, ?);",
    "UPDATE metadata SET value = ? WHERE key = ?;",
    "SELECT value FROM metadata WHERE key = ?;"
};

int wdb_metadata_initialize (wdb_t *wdb) {
    int result = 0;

    if (wdb_metadata_insert_entry(wdb, "db_version", "1") < 0) {
        merror("Couldn't fill metadata into database '%s'", wdb->agent_id);
        result = -1;
    }

    return result;
}

int wdb_fim_fill_metadata(wdb_t *wdb, char *data) {
    char *key, *value;

    key = data;
    if (value = strchr(data, ' '), !value) {
        mdebug1("DB(%s) Invalid metadata value.", wdb->agent_id);
        return -1;
    }
    *value++ = '\0';

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        merror("DB(%s) Cannot begin transaction", wdb->agent_id);
        return -1;
    }

    switch (wdb_metadata_find_entry(wdb, key)) {
    case -1:
        mdebug1("DB(%s) Cannot find metadata entry", wdb->agent_id);
        return -1;

    case 0:
        // Adding metadata
        if (wdb_metadata_insert_entry(wdb, key, value) < 0) {
            mdebug1("DB(%s) Cannot insert metadata entry", wdb->agent_id);
            return -1;
        }
        break;

    default:
        // Update metadata entry
        if (wdb_metadata_update_entry(wdb, key, value) < 1) {
            mdebug1("DB(%s) Cannot update metadata entry", wdb->agent_id);
            return -1;
        }
    }

    return 0;
}

// Find metadata entry: returns 1 if found, 0 if not, or -1 on error.
int wdb_metadata_find_entry(wdb_t * wdb, const char * key) {
    sqlite3_stmt *stmt = NULL;

    if (sqlite3_prepare_v2(wdb->db,
                            SQL_METADATA_STMT[WDB_STMT_METADATA_FIND],
                            -1,
                            &stmt,
                            NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_prepare_v2(): %s", wdb->agent_id, sqlite3_errmsg(wdb->db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, key, -1, NULL);

    switch (sqlite3_step(stmt)) {
    case SQLITE_ROW:
        sqlite3_finalize(stmt);
        return 1;
        break;
    case SQLITE_DONE:
        sqlite3_finalize(stmt);
        return 0;
        break;
    default:
        mdebug1("DB(%s) sqlite3_step(): %s", wdb->agent_id, sqlite3_errmsg(wdb->db));
        sqlite3_finalize(stmt);
        return -1;
    }
}

int wdb_metadata_insert_entry (wdb_t * wdb, const char *key, const char *value) {
    sqlite3_stmt *stmt = NULL;

    if (sqlite3_prepare_v2(wdb->db,
                            SQL_METADATA_STMT[WDB_STMT_METADATA_INSERT],
                            -1,
                            &stmt,
                            NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_prepare_v2(): %s", wdb->agent_id, sqlite3_errmsg(wdb->db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, key, -1, NULL);
    sqlite3_bind_text(stmt, 2, value, -1, NULL);

    if (sqlite3_step(stmt) == SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return 0;
    } else {
        mdebug1("DB(%s) sqlite3_step(): %s", wdb->agent_id, sqlite3_errmsg(wdb->db));
        sqlite3_finalize(stmt);
        return -1;
    }
}

int wdb_metadata_update_entry (wdb_t * wdb, const char *key, const char *value) {
    sqlite3_stmt *stmt = NULL;

    if (sqlite3_prepare_v2(wdb->db,
                            SQL_METADATA_STMT[WDB_STMT_METADATA_UPDATE],
                            -1,
                            &stmt,
                            NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_prepare_v2(): %s", wdb->agent_id, sqlite3_errmsg(wdb->db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, value, -1, NULL);
    sqlite3_bind_text(stmt, 2, key, -1, NULL);

    if (sqlite3_step(stmt) == SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return sqlite3_changes(wdb->db);
    } else {
        mdebug1("DB(%s) sqlite3_step(): %s", wdb->agent_id, sqlite3_errmsg(wdb->db));
        sqlite3_finalize(stmt);
        return -1;
    }
}

int wdb_metadata_get_entry (wdb_t * wdb, const char *key, char *output) {
    sqlite3_stmt *stmt = NULL;

    if (sqlite3_prepare_v2(wdb->db,
                            SQL_METADATA_STMT[WDB_STMT_METADATA_FIND],
                            -1,
                            &stmt,
                            NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_prepare_v2(): %s", wdb->agent_id, sqlite3_errmsg(wdb->db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, key, -1, NULL);

    switch (sqlite3_step(stmt)) {
        case SQLITE_ROW:
            snprintf(output, OS_SIZE_256 + 1, "%s", (char *)sqlite3_column_text(stmt, 0));
            sqlite3_finalize(stmt);
            return 1;
            break;
        case SQLITE_DONE:
            sqlite3_finalize(stmt);
            return 0;
            break;
        default:
            mdebug1("DB(%s) sqlite3_step(): %s", wdb->agent_id, sqlite3_errmsg(wdb->db));
            sqlite3_finalize(stmt);
            return -1;
    }
}