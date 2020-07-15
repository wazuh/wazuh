/*
 * Wazuh Module for Task management.
 * Copyright (C) 2015-2020, Wazuh Inc.
 * July 13, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WIN32

#include "../wmodules.h"
#include "wm_task_manager_db.h"
#include "wazuh_db/wdb.h"

static int wm_task_manager_prepare(sqlite3 *db, const char *zSql, int nByte, sqlite3_stmt **stmt, const char **pzTail);
static int wm_task_manager_step(sqlite3_stmt *stmt);
static int wm_task_manager_sql_error(sqlite3 *db, sqlite3_stmt *stmt);

static const char *task_statuses[] = {
    [NEW] = "New",
    [IN_PROGRESS] = "In progress",
    [DONE] = "Done",
    [FAILED] = "Failed"
};

int wm_task_manager_prepare(sqlite3 *db, const char *zSql, int nByte, sqlite3_stmt **stmt, const char **pzTail) {
    int attempts;
    int result;
    for (attempts = 0; (result = sqlite3_prepare_v2(db, zSql, nByte, stmt, pzTail)) == SQLITE_BUSY; attempts++) {
        if (attempts == MAX_SQL_ATTEMPTS) {
            mterror(WM_TASK_MANAGER_LOGTAG, "Couldn't access tasks DB.");
            return OS_INVALID;
        }
    }
    return result;
}

int wm_task_manager_step(sqlite3_stmt *stmt) {
    int attempts;
    int result;
    for (attempts = 0; (result = sqlite3_step(stmt)) == SQLITE_BUSY; attempts++) {
        if (attempts == MAX_SQL_ATTEMPTS) {
            mterror(WM_TASK_MANAGER_LOGTAG, "Couldn't access tasks DB.");
            return OS_INVALID;
        }
    }
    return result;
}

int wm_task_manager_sql_error(sqlite3 *db, sqlite3_stmt *stmt) {
    mterror(WM_TASK_MANAGER_LOGTAG, "SQL error: '%s'", sqlite3_errmsg(db));
    wdb_finalize(stmt);
    sqlite3_close_v2(db);
    return OS_INVALID;
}

int wm_task_manager_check_db() {
    const char *ROOT = ROOTUSER;
    const char *path = TASKS_DB;
    const char *sql;
    const char *tail;
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;

    // Open or create the database file
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL)) {
        mterror(WM_TASK_MANAGER_LOGTAG, "DB couldn't be checked or created.");
        return wm_task_manager_sql_error(db, stmt);
    }

    // Load the tables schema
    for (sql = schema_task_manager_sql; sql && *sql; sql = tail) {
        if (wm_task_manager_prepare(db, sql, -1, &stmt, &tail) != SQLITE_OK) {
            mterror(WM_TASK_MANAGER_LOGTAG, "DB couldn't be checked or created.");
            return wm_task_manager_sql_error(db, stmt);
        }

        switch (wm_task_manager_step(stmt)) {
        case SQLITE_MISUSE:
        case SQLITE_ROW:
        case SQLITE_DONE:
            break;
        default:
            return wm_task_manager_sql_error(db, stmt);
        }

        wdb_finalize(stmt);
    }

    sqlite3_close_v2(db);

    uid_t uid = Privsep_GetUser(ROOT);
    gid_t gid = Privsep_GetGroup(GROUPGLOBAL);

    if (uid == (uid_t) - 1 || gid == (gid_t) - 1) {
        mterror(WM_TASK_MANAGER_LOGTAG, USER_ERROR, ROOT, GROUPGLOBAL, strerror(errno), errno);
        return OS_INVALID;
    }

    if (chown(path, uid, gid) < 0) {
        mterror(WM_TASK_MANAGER_LOGTAG, CHOWN_ERROR, path, errno, strerror(errno));
        return OS_INVALID;
    }

    if (chmod(path, 0660) < 0) {
        mterror(WM_TASK_MANAGER_LOGTAG, CHMOD_ERROR, path, errno, strerror(errno));
        return OS_INVALID;
    }

    return 0;
}

int wm_task_manager_insert_task(int agent_id, const char *module, const char *command) {
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int result = 0;
    int task_id = 0;

    if (sqlite3_open_v2(TASKS_DB, &db, SQLITE_OPEN_READWRITE, NULL)) {
        mterror(WM_TASK_MANAGER_LOGTAG, "DB couldn't be opened.");
        return wm_task_manager_sql_error(db, stmt);
    }

    if (wm_task_manager_prepare(db, task_queries[VU_INSERT_TASK], -1, &stmt, NULL) != SQLITE_OK) {
        mterror(WM_TASK_MANAGER_LOGTAG, "Couldn't prepare SQL statement.");
        return wm_task_manager_sql_error(db, stmt);
    }

    sqlite3_bind_int(stmt, 1, agent_id);
    sqlite3_bind_text(stmt, 2, module, -1, NULL);
    sqlite3_bind_text(stmt, 3, command, -1, NULL);
    sqlite3_bind_text(stmt, 4, task_statuses[NEW], -1, NULL);

    if (result = wm_task_manager_step(stmt), result != SQLITE_DONE && result != SQLITE_CONSTRAINT) {
        mterror(WM_TASK_MANAGER_LOGTAG, "Couldn't execute SQL statement.");
        return wm_task_manager_sql_error(db, stmt);
    }

    wdb_finalize(stmt);

    if (wm_task_manager_prepare(db, task_queries[VU_GET_MAX_TASK_ID], -1, &stmt, NULL) != SQLITE_OK) {
        return wm_task_manager_sql_error(db, stmt);
    }

    if (result = wm_task_manager_step(stmt), result != SQLITE_ROW) {
        return wm_task_manager_sql_error(db, stmt);
    }

    task_id = sqlite3_column_int(stmt, 0);

    wdb_finalize(stmt);

    sqlite3_close_v2(db);

    return task_id;
}

#endif
