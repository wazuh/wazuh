/*
 * Wazuh SQLite integration
 * Copyright (C) 2016 Wazuh Inc.
 * June 06, 2016.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wdb.h"

int wdb_metadata_initialize (wdb_t *wdb, char *path) {
    char version[] = __ossec_version;
    char * strmajor;
    char * strminor;
    char * end;
    int result = 0;

    // Extract version

    strmajor = version + (*version == 'v');

    if (end = strchr(strmajor, '.'), !end) {
        merror("at wdb_metadata_fill_version(): Couldn't parse internal mayor version '%s'", strmajor);
        result = -1;
    } else {
        *end = '\0';
        strminor = end + 1;

        if (end = strchr(strminor, '.'), !end) {
            merror("at wdb_metadata_fill_version(): Couldn't parse internal minor version '%s'", strminor);
            result = -1;
        } else {
            *end = '\0';
            if (wdb_metadata_insert_entry(wdb, "version_major", strmajor) < 0) {
                merror("Couldn't fill metadata into database '%s'", path);
                result = -1;
            }

            if (wdb_metadata_insert_entry(wdb, "version_minor", strminor) < 0) {
                merror("Couldn't fill metadata into database '%s'", path);
                result = -1;
            }
        }
    }

    return result;
}

int wdb_fim_fill_metadata(wdb_t *wdb, char *data) {
    char *key, *value;

    key = data;
    if (value = strchr(data, ' '), !value) {
        mdebug1("at wdb_fim_fill_metadata(): Invalid metadata value.");
        return -1;
    }
    *value++ = '\0';

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        merror("at wdb_fim_fill_metadata(): cannot begin transaction");
        return -1;
    }

    switch (wdb_metadata_find_entry(wdb, key)) {
    case -1:
        mdebug1("at wdb_fim_fill_metadata(): Cannot find metadata entry");
        return -1;

    case 0:
        // Adding metadata
        if (wdb_metadata_insert_entry(wdb, key, value) < 0) {
            mdebug1("at wdb_fim_fill_metadata(): cannot insert metadata entry");
            return -1;
        }
        break;

    default:
        // Update metadata entry
        if (wdb_metadata_update_entry(wdb, key, value) < 1) {
            mdebug1("at wdb_fim_fill_metadata(): cannot update metadata entry");
            return -1;
        }
    }

    return 0;
}

// Find metadata entry: returns 1 if found, 0 if not, or -1 on error.
int wdb_metadata_find_entry(wdb_t * wdb, const char * key) {
    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_METADATA_FIND) < 0) {
        merror("at wdb_fim_find_entry(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_METADATA_FIND];

    sqlite3_bind_text(stmt, 1, key, -1, NULL);

    switch (sqlite3_step(stmt)) {
    case SQLITE_ROW:
        return 1;
        break;
    case SQLITE_DONE:
        return 0;
        break;
    default:
        mdebug1("at wdb_metadata_find_entry(): at sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}

int wdb_metadata_insert_entry (wdb_t * wdb, const char *key, const char *value) {
    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_METADATA_INSERT) < 0) {
        merror("at wdb_fim_insert_entry(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_METADATA_INSERT];

    sqlite3_bind_text(stmt, 1, key, -1, NULL);
    sqlite3_bind_text(stmt, 2, value, -1, NULL);

    if (sqlite3_step(stmt) == SQLITE_DONE) {
        return 0;
    } else {
        mdebug1("at wdb_metadata_insert_entry(): sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}

int wdb_metadata_update_entry (wdb_t * wdb, const char *key, const char *value) {
    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_METADATA_UPDATE) < 0) {
        merror("at wdb_fim_update_entry(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_METADATA_UPDATE];

    sqlite3_bind_text(stmt, 1, value, -1, NULL);
    sqlite3_bind_text(stmt, 2, key, -1, NULL);

    if (sqlite3_step(stmt) == SQLITE_DONE) {
        return sqlite3_changes(wdb->db);
    } else {
        mdebug1("at wdb_metadata_update_entry(): sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}

int wdb_metadata_get_entry (wdb_t * wdb, const char *key, char *output) {
    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_METADATA_FIND) < 0) {
        merror("at wdb_metadata_get_entry(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_METADATA_FIND];

    sqlite3_bind_text(stmt, 1, key, -1, NULL);

    switch (sqlite3_step(stmt)) {
        case SQLITE_ROW:
            snprintf(output, OS_SIZE_256 + 1, "%s", (char *)sqlite3_column_text(stmt, 0));
            return 1;
            break;
        case SQLITE_DONE:
            return 0;
            break;
        default:
            mdebug1("at wdb_metadata_get_entry(): at sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
            return -1;
    }
}