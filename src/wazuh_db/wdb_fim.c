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

static const char *SQL_INSERT_FIM = "INSERT INTO fim_event (id_file, type, date, size, perm, uid, gid, md5, sha1) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);";
static const char *SQL_INSERT_FILE = "INSERT INTO fim_file (path, type) VALUES (?, ?);";
static const char *SQL_FIND_FILE = "SELECT id FROM fim_file WHERE type = ? AND path = ?;";

static int get_type(const char *location);

/* Find file: returns ID, or 0 if it doesn't exists, or -1 on error. */
int wdb_insert_file(sqlite3 *db, const char *path, int type) {
    sqlite3_stmt *stmt = NULL;
    int result;

    if (sqlite3_prepare_v2(db, SQL_INSERT_FILE, -1, &stmt, NULL)) {
        debug1("%s: SQLite: %s", ARGV0, sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, path, -1, NULL);
    sqlite3_bind_text(stmt, 2, type == WDB_FILE_TYPE_FILE ? "file" : "registry", -1, NULL);

    if (sqlite3_step(stmt) == SQLITE_DONE)
        result = (int)sqlite3_last_insert_rowid(db);
    else {
        debug1("%s: SQLite: %s", ARGV0, sqlite3_errmsg(db));
        result = -1;
    }

    sqlite3_finalize(stmt);
    return result;
}

/* Find file, Returns ID, or -1 on error. */
int wdb_find_file(sqlite3 *db, const char *path, int type) {
    static sqlite3_stmt *stmt = NULL;
    int result;

    if (sqlite3_prepare_v2(db, SQL_FIND_FILE, -1, &stmt, NULL)) {
        debug1("%s: SQLite: %s", ARGV0, sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, type == WDB_FILE_TYPE_FILE ? "file" : "registry", -1, NULL);
    sqlite3_bind_text(stmt, 2, path, -1, NULL);

    switch (sqlite3_step(stmt)) {
    case SQLITE_ROW:
        result = sqlite3_column_int(stmt, 0);
        break;
    case SQLITE_DONE:
        result = 0;
        break;
    default:
        debug1("%s: SQLite: %s", ARGV0, sqlite3_errmsg(db));
        result = -1;
    }

    sqlite3_finalize(stmt);
    return result;
}

/* Insert FIM entry. Returns ID, or -1 on error. */
int wdb_insert_fim(int id_agent, const char *location, const char *f_name, const char *event, const SyscheckSum *sum, long int time) {
    sqlite3 *db;
    sqlite3_stmt *stmt = NULL;
    int id_file;
    int result;
    int type = get_type(location);
    char *name = wdb_agent_name(location);

    if (!name)
        return -1;

    db = wdb_open_agent(id_agent, name);
    free(name);

    if (!db)
        return -1;

    if (sqlite3_prepare_v2(db, SQL_INSERT_FIM, -1, &stmt, NULL)) {
        debug1("%s: SQLite: %s", ARGV0, sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }

    switch ((id_file = wdb_find_file(db, f_name, type))) {
    case -1:
        sqlite3_close(db);
        return -1;

    case 0:
        if ((id_file = wdb_insert_file(db, f_name, type)) < 0) {
            sqlite3_close(db);
            return -1;
        }
    }

    sqlite3_bind_int(stmt, 1, id_file);
    sqlite3_bind_text(stmt, 2, event, -1, NULL);
    sqlite3_bind_int(stmt, 3, time);

    if (sum) {
        sqlite3_bind_int(stmt, 4, atoi(sum->size));
        sqlite3_bind_int(stmt, 5, sum->perm);
        sqlite3_bind_int(stmt, 6, atoi(sum->uid));
        sqlite3_bind_int(stmt, 7, atoi(sum->gid));
        sqlite3_bind_text(stmt, 8, sum->md5, -1, NULL);
        sqlite3_bind_text(stmt, 9, sum->sha1, -1, NULL);
    } else {
        sqlite3_bind_null(stmt, 4);
        sqlite3_bind_null(stmt, 5);
        sqlite3_bind_null(stmt, 6);
        sqlite3_bind_null(stmt, 7);
        sqlite3_bind_null(stmt, 8);
        sqlite3_bind_null(stmt, 9);
    }

    result = sqlite3_step(stmt) == SQLITE_DONE ? (int)sqlite3_last_insert_rowid(db) : -1;
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return result;
}

int get_type(const char *location) {
    int offset = strlen(location) - 19;
    return (offset >= 0 && strcmp(location + offset, "->syscheck-registry") == 0) ? WDB_FILE_TYPE_REGISTRY : WDB_FILE_TYPE_FILE;
}
