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


int wdb_user_version_get(wdb_t *wdb, int *version) {
    sqlite3_stmt *stmt = NULL;

    if (wdb_prepare(wdb->db, "PRAGMA user_version;", -1, &stmt, NULL)) {
        merror("DB(%s) wdb_prepare(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    int ret = OS_INVALID;
    int rc = wdb_step(stmt);

    if (rc == SQLITE_ROW) {
        *version = sqlite3_column_int(stmt, 0);
        ret = OS_SUCCESS;
    } else {
        merror("DB(%s) wdb_user_version_get(): wdb_step() returned %d: %s",
               wdb->id, rc, sqlite3_errmsg(wdb->db));
    }

    sqlite3_finalize(stmt);
    return ret;
}

