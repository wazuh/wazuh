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

#include "db.h"

static const char *SQL_INSERT_PM = "INSERT INTO pm_event (id_agent, date_first, date_last, log) VALUES (?, ?, ?, ?);";
static const char *SQL_UPDATE_PM = "UPDATE pm_event SET date_last = ? WHERE id_agent = ? AND log = ?;";

/* Insert policy monitoring entry. Returns ID on success or -1 on error. */
int db_insert_pm(int id_agent, long int date, const char *log) {
    static sqlite3_stmt *stmt = NULL;
    int result;

    if (!(stmt || sqlite3_prepare_v2(db, SQL_INSERT_PM, -1, &stmt, NULL) == SQLITE_OK)) {
        debug1("%s: SQLite: %s", ARGV0, sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_int(stmt, 1, id_agent);
    sqlite3_bind_int(stmt, 2, date);
    sqlite3_bind_int(stmt, 3, date);
    sqlite3_bind_text(stmt, 4, log, -1, NULL);

    result = sqlite3_step(stmt) == SQLITE_DONE ? (int)sqlite3_last_insert_rowid(db) : -1;
    sqlite3_reset(stmt);

    return result;
}

/* Update policy monitoring last date. Returns 0 on success or -1 on error. */
int db_update_pm(int id_agent, const char *log, long int date_last) {
    static sqlite3_stmt *stmt = NULL;
    int result;

    if (!(stmt || sqlite3_prepare_v2(db, SQL_UPDATE_PM, -1, &stmt, NULL) == SQLITE_OK)) {
        debug1("%s: SQLite: %s", ARGV0, sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_int(stmt, 1, date_last);
    sqlite3_bind_int(stmt, 2, id_agent);
    sqlite3_bind_text(stmt, 3, log, -1, NULL);

    result = sqlite3_step(stmt) == SQLITE_DONE ? (int)sqlite3_last_insert_rowid(db) : -1;
    sqlite3_reset(stmt);

    return result;
}
