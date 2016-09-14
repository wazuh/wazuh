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

static const char *SQL_INSERT_EVENT = "INSERT INTO fim_event (id_file, type, date, size, perm, uid, gid, md5, sha1, uname, gname, mtime, inode) VALUES (?, ?, datetime(?, 'unixepoch', 'localtime'), ?, ?, ?, ?, ?, ?, ?, ?, datetime(?, 'unixepoch', 'localtime'), ?);";
static const char *SQL_INSERT_FILE = "INSERT INTO fim_file (path, type) VALUES (?, ?);";
static const char *SQL_FIND_FILE = "SELECT id FROM fim_file WHERE type = ? AND path = ?;";
static const char *SQL_DELETE_EVENT = "DELETE FROM fim_event;";
static const char *SQL_DELETE_FILE = "DELETE FROM fim_file;";

static int get_type(const char *location);

/* Find file: returns ID, or 0 if it doesn't exists, or -1 on error. */
int wdb_insert_file(sqlite3 *db, const char *path, int type) {
    sqlite3_stmt *stmt = NULL;
    int result;

    if (wdb_prepare(db, SQL_INSERT_FILE, -1, &stmt, NULL)) {
        debug1("%s: SQLite: %s", ARGV0, sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, path, -1, NULL);
    sqlite3_bind_text(stmt, 2, type == WDB_FILE_TYPE_FILE ? "file" : "registry", -1, NULL);

    if (wdb_step(stmt) == SQLITE_DONE)
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
    sqlite3_stmt *stmt = NULL;
    int result;

    if (wdb_prepare(db, SQL_FIND_FILE, -1, &stmt, NULL)) {
        debug1("%s: SQLite: %s", ARGV0, sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, type == WDB_FILE_TYPE_FILE ? "file" : "registry", -1, NULL);
    sqlite3_bind_text(stmt, 2, path, -1, NULL);

    switch (wdb_step(stmt)) {
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
    char *name = wdb_agent_loc2name(location);

    if (!name)
        return -1;

    db = wdb_open_agent(id_agent, name);
    free(name);

    if (!db)
        return -1;

    if (wdb_prepare(db, SQL_INSERT_EVENT, -1, &stmt, NULL)) {
        debug1("%s: SQLite: %s", ARGV0, sqlite3_errmsg(db));
        sqlite3_close_v2(db);
        return -1;
    }

    switch ((id_file = wdb_find_file(db, f_name, type))) {
    case -1:
        sqlite3_close_v2(db);
        return -1;

    case 0:
        if ((id_file = wdb_insert_file(db, f_name, type)) < 0) {
            sqlite3_close_v2(db);
            return -1;
        }
    }

    sqlite3_bind_int(stmt, 1, id_file);
    sqlite3_bind_text(stmt, 2, event, -1, NULL);
    sqlite3_bind_int64(stmt, 3, time);

    if (sum) {
        char perm[7];
        snprintf(perm, 7, "%06o", sum->perm);

        sqlite3_bind_int64(stmt, 4, atol(sum->size));
        sqlite3_bind_text(stmt, 5, perm, -1, NULL);

        // UID and GID from Windows is 0. It should be NULL
        sqlite3_bind_int(stmt, 6, atoi(sum->uid));
        sqlite3_bind_int(stmt, 7, atoi(sum->gid));

        sqlite3_bind_text(stmt, 8, sum->md5, -1, NULL);
        sqlite3_bind_text(stmt, 9, sum->sha1, -1, NULL);

        if (sum->uname){
            sqlite3_bind_text(stmt, 10, sum->uname, -1, NULL);
            sqlite3_bind_text(stmt, 11, sum->gname, -1, NULL);
        }
        else{ // Old agents
            sqlite3_bind_null(stmt, 10); // uname
            sqlite3_bind_null(stmt, 11); // gname
        }

        if (sum->mtime)
            sqlite3_bind_int64(stmt, 12, sum->mtime);
        else // Old agents
            sqlite3_bind_null(stmt, 12); // mtime

        if (sum->inode)
            sqlite3_bind_int64(stmt, 13, sum->inode);
        else // Old agents
            sqlite3_bind_null(stmt, 13); // inode
    } else {
        sqlite3_bind_null(stmt, 4);
        sqlite3_bind_null(stmt, 5);
        sqlite3_bind_null(stmt, 6);
        sqlite3_bind_null(stmt, 7);
        sqlite3_bind_null(stmt, 8);
        sqlite3_bind_null(stmt, 9);
        sqlite3_bind_null(stmt, 10);
        sqlite3_bind_null(stmt, 11);
        sqlite3_bind_null(stmt, 12);
        sqlite3_bind_null(stmt, 13);
    }

    result = wdb_step(stmt) == SQLITE_DONE ? (int)sqlite3_last_insert_rowid(db) : -1;
    sqlite3_finalize(stmt);
    sqlite3_close_v2(db);
    return result;
}

/* Delete FIM events of an agent. Returns 0 on success or -1 on error. */
int wdb_delete_fim(int id) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    char *name = id ? wdb_agent_name(id) : strdup("localhost");
    int result;

    if (!name)
        return -1;

    db = wdb_open_agent(id, name);
    free(name);

    if (!db)
        return -1;

    // Delete files first to maintain reference integrity on insertion

    if (wdb_prepare(db, SQL_DELETE_FILE, -1, &stmt, NULL)) {
        debug1("%s: SQLite: %s", ARGV0, sqlite3_errmsg(db));
        sqlite3_close_v2(db);
        return -1;
    }

    result = wdb_step(stmt);
    sqlite3_finalize(stmt);

    if (result != SQLITE_DONE) {
        sqlite3_close_v2(db);
        return -1;
    }

    // Delete events

    if (wdb_prepare(db, SQL_DELETE_EVENT, -1, &stmt, NULL)) {
        debug1("%s: SQLite: %s", ARGV0, sqlite3_errmsg(db));
        sqlite3_close_v2(db);
        return -1;
    }

    result = wdb_step(stmt) == SQLITE_DONE ? 0 : -1;
    sqlite3_finalize(stmt);
    sqlite3_close_v2(db);
    return result;
}

/* Delete FIM events of all agents */
void wdb_delete_fim_all() {
    int *agents = wdb_get_all_agents();
    int i;

    if (agents) {
        wdb_delete_fim(0);

        for (i = 0; agents[i] >= 0; i++)
            wdb_delete_fim(agents[i]);

            free(agents);
    }
}

int get_type(const char *location) {
    int offset = strlen(location) - 19;
    return (offset >= 0 && strcmp(location + offset, "->syscheck-registry") == 0) ? WDB_FILE_TYPE_REGISTRY : WDB_FILE_TYPE_FILE;
}
