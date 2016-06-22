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
#include "sqlite3.h"

static const char *SQL_INSERT_FIM = "INSERT INTO fim_event (id_agent, id_file, event, date, size, perm, uid, gid, md5, sha1) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";
static const char *SQL_INSERT_FILE = "INSERT INTO fim_file (id_agent, path) VALUES (?, ?);";
static const char *SQL_FIND_FILE = "SELECT id FROM fim_file WHERE id_agent = ? AND path = ?;";

/* Find file: returns ID, or 0 if it doesn't exists, or -1 on error. */
int db_insert_file(int id_agent, const char *path) {
    static sqlite3_stmt *stmt = NULL;
    int result;

    if (!(stmt || sqlite3_prepare_v2(db, SQL_INSERT_FILE, -1, &stmt, NULL) == SQLITE_OK)) {
        debug1("%s: SQLite: %s", ARGV0, sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_int(stmt, 1, id_agent);
    sqlite3_bind_text(stmt, 2, path, -1, NULL);
    result = sqlite3_step(stmt) == SQLITE_DONE ? (int)sqlite3_last_insert_rowid(db) : -1;
    sqlite3_reset(stmt);

     return result;
}

/* Insert file, Returns -1 on error. */
int db_find_file(int id_agent, const char *path) {
    static sqlite3_stmt *stmt = NULL;
    int result;

    if (!(stmt || sqlite3_prepare_v2(db, SQL_FIND_FILE, -1, &stmt, NULL) == SQLITE_OK)) {
        debug1("%s: SQLite: %s", ARGV0, sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_int(stmt, 1, id_agent);
    sqlite3_bind_text(stmt, 2, path, -1, NULL);

    switch (sqlite3_step(stmt)) {
    case SQLITE_ROW:
        result = sqlite3_column_int(stmt, 0);
        break;
    case SQLITE_DONE:
        result = 0;
        break;
    default:
        result = -1;
    }

    sqlite3_reset(stmt);
    return result;
}

/* Insert FIM entry. Returns -1 on error. */
int db_insert_fim(int id_agent, const char *f_name, const char *event, const SyscheckSum *sum, long int time) {
    sqlite3_stmt *stmt = NULL;
    int id_file;
    int result;

    if (!(stmt || sqlite3_prepare_v2(db, SQL_INSERT_FIM, -1, &stmt, NULL) == SQLITE_OK)) {
        debug1("%s: SQLite: %s", ARGV0, sqlite3_errmsg(db));
        return -1;
    }

    switch ((id_file = db_find_file(id_agent, f_name))) {
    case -1:
        return -1;

    case 0:
        if ((id_file = db_insert_file(id_agent, f_name)) < 0)
            return -1;
    }

    sqlite3_bind_int(stmt, 1, id_agent);
    sqlite3_bind_int(stmt, 2, id_file);
    sqlite3_bind_text(stmt, 3, event, -1, NULL);
    sqlite3_bind_int(stmt, 4, time);

    if (sum) {
        sqlite3_bind_int(stmt, 5, atoi(sum->size));
        sqlite3_bind_int(stmt, 6, sum->perm);
        sqlite3_bind_int(stmt, 7, atoi(sum->uid));
        sqlite3_bind_int(stmt, 8, atoi(sum->gid));
        sqlite3_bind_text(stmt, 9, sum->md5, -1, NULL);
        sqlite3_bind_text(stmt, 10, sum->sha1, -1, NULL);
    } else {
        sqlite3_bind_null(stmt, 5);
        sqlite3_bind_null(stmt, 6);
        sqlite3_bind_null(stmt, 7);
        sqlite3_bind_null(stmt, 8);
        sqlite3_bind_null(stmt, 9);
        sqlite3_bind_null(stmt, 10);
    }

    result = sqlite3_step(stmt) == SQLITE_DONE ? (int)sqlite3_last_insert_rowid(db) : -1;
    sqlite3_reset(stmt);
    return result;
}
