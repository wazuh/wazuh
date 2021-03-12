/*
 * Wazuh SQLite integration
 * Copyright (C) 2015-2020, Wazuh Inc.
 * June 06, 2016.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wdb.h"

// Function to get a MITRE technique's name.

int wdb_mitre_name_get(wdb_t *wdb, char *id, char *output) {
    
    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_MITRE_NAME_GET) < 0) {
        mdebug1("at wdb_mitre_name_get(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_MITRE_NAME_GET];

    if (sqlite3_bind_text(stmt, 1, id, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return -1;
    }

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
        snprintf(output, OS_MAXSTR - WDB_RESPONSE_BEGIN_SIZE, "%s", sqlite3_column_text(stmt, 0));
        return 1;
        break;
    case SQLITE_DONE:
        return 0;
        break;
    default:
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}
