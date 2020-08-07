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

static int wm_task_manager_sql_error(sqlite3 *db, sqlite3_stmt *stmt);

static const char *task_queries[] = {
    [WM_TASK_INSERT_TASK] = "INSERT INTO " TASKS_TABLE " VALUES(NULL,?,?,?,?);",
    [WM_TASK_GET_MAX_TASK_ID] = "SELECT MAX(TASK_ID) FROM " TASKS_TABLE ";",
    [WM_TASK_GET_LAST_AGENT_TASK] = "SELECT MAX(TASK_ID) FROM " TASKS_TABLE " WHERE AGENT_ID = ? AND MODULE = ?;",
    [WM_TASK_GET_TASK_STATUS] = "SELECT STATUS FROM " TASKS_TABLE " WHERE TASK_ID = ?;",
    [WM_TASK_UPDATE_TASK_STATUS] = "UPDATE " TASKS_TABLE " SET STATUS = ? WHERE TASK_ID = ?;"
};

static const char *task_statuses[] = {
    [WM_TASK_NEW] = "New",
    [WM_TASK_IN_PROGRESS] = "In progress",
    [WM_TASK_DONE] = "Done",
    [WM_TASK_FAILED] = "Failed"
};

int wm_task_manager_sql_error(sqlite3 *db, sqlite3_stmt *stmt) {
    mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_SQL_ERROR, sqlite3_errmsg(db));
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
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_CREATE_DB_ERROR);
        return wm_task_manager_sql_error(db, stmt);
    }

    // Load the tables schema
    for (sql = schema_task_manager_sql; sql && *sql; sql = tail) {
        if (wdb_prepare(db, sql, -1, &stmt, &tail) != SQLITE_OK) {
            mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_SQL_PREPARE_ERROR);
            return wm_task_manager_sql_error(db, stmt);
        }

        switch (wdb_step(stmt)) {
        case SQLITE_MISUSE:
        case SQLITE_ROW:
        case SQLITE_DONE:
            break;
        default:
            mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_SQL_STEP_ERROR);
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
    int task_id = OS_INVALID;

    if (sqlite3_open_v2(TASKS_DB, &db, SQLITE_OPEN_READWRITE, NULL)) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_OPEN_DB_ERROR);
        return wm_task_manager_sql_error(db, stmt);
    }

    if (wdb_prepare(db, task_queries[WM_TASK_INSERT_TASK], -1, &stmt, NULL) != SQLITE_OK) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_SQL_PREPARE_ERROR);
        return wm_task_manager_sql_error(db, stmt);
    }

    sqlite3_bind_int(stmt, 1, agent_id);
    sqlite3_bind_text(stmt, 2, module, -1, NULL);
    sqlite3_bind_text(stmt, 3, command, -1, NULL);
    sqlite3_bind_text(stmt, 4, task_statuses[WM_TASK_NEW], -1, NULL);

    if (result = wdb_step(stmt), result != SQLITE_DONE && result != SQLITE_CONSTRAINT) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_SQL_STEP_ERROR);
        return wm_task_manager_sql_error(db, stmt);
    }

    wdb_finalize(stmt);

    if (wdb_prepare(db, task_queries[WM_TASK_GET_MAX_TASK_ID], -1, &stmt, NULL) != SQLITE_OK) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_SQL_PREPARE_ERROR);
        return wm_task_manager_sql_error(db, stmt);
    }

    if (result = wdb_step(stmt), result != SQLITE_ROW) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_SQL_STEP_ERROR);
        return wm_task_manager_sql_error(db, stmt);
    }

    task_id = sqlite3_column_int(stmt, 0);

    wdb_finalize(stmt);

    sqlite3_close_v2(db);

    return task_id;
}

int wm_task_manager_get_task_status(int agent_id, const char *module, char **status) {
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int result = 0;
    int task_id = OS_INVALID;

    if (sqlite3_open_v2(TASKS_DB, &db, SQLITE_OPEN_READWRITE, NULL)) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_OPEN_DB_ERROR);
        return wm_task_manager_sql_error(db, stmt);
    }

    if (wdb_prepare(db, task_queries[WM_TASK_GET_LAST_AGENT_TASK], -1, &stmt, NULL) != SQLITE_OK) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_SQL_PREPARE_ERROR);
        return wm_task_manager_sql_error(db, stmt);
    }

    sqlite3_bind_int(stmt, 1, agent_id);
    sqlite3_bind_text(stmt, 2, module, -1, NULL);

    if (result = wdb_step(stmt), result != SQLITE_ROW) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_SQL_STEP_ERROR);
        return wm_task_manager_sql_error(db, stmt);
    }

    // Check task id
    task_id = sqlite3_column_int(stmt, 0);
    if (!task_id) {
        wdb_finalize(stmt);
        sqlite3_close_v2(db);
        return WM_TASK_SUCCESS;
    }

    wdb_finalize(stmt);

    if (wdb_prepare(db, task_queries[WM_TASK_GET_TASK_STATUS], -1, &stmt, NULL) != SQLITE_OK) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_SQL_PREPARE_ERROR);
        return wm_task_manager_sql_error(db, stmt);
    }

    sqlite3_bind_int(stmt, 1, task_id);

    if (result = wdb_step(stmt), result != SQLITE_ROW) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_SQL_STEP_ERROR);
        return wm_task_manager_sql_error(db, stmt);
    }

    sqlite_strdup((char *)sqlite3_column_text(stmt, 0), *status);

    wdb_finalize(stmt);

    sqlite3_close_v2(db);

    return WM_TASK_SUCCESS;
}

int wm_task_manager_update_task_status(int agent_id, const char *module, const char *status) {
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int result = 0;
    int task_id = OS_INVALID;
    char *old_status = NULL;

    if (!status || (strcmp(status, task_statuses[WM_TASK_IN_PROGRESS]) && strcmp(status, task_statuses[WM_TASK_DONE]) && strcmp(status, task_statuses[WM_TASK_FAILED]))) {
        return WM_TASK_INVALID_STATUS;
    }

    if (sqlite3_open_v2(TASKS_DB, &db, SQLITE_OPEN_READWRITE, NULL)) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_OPEN_DB_ERROR);
        return wm_task_manager_sql_error(db, stmt);
    }

    if (wdb_prepare(db, task_queries[WM_TASK_GET_LAST_AGENT_TASK], -1, &stmt, NULL) != SQLITE_OK) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_SQL_PREPARE_ERROR);
        return wm_task_manager_sql_error(db, stmt);
    }

    sqlite3_bind_int(stmt, 1, agent_id);
    sqlite3_bind_text(stmt, 2, module, -1, NULL);

    if (result = wdb_step(stmt), result != SQLITE_ROW) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_SQL_STEP_ERROR);
        return wm_task_manager_sql_error(db, stmt);
    }

    // Check task id
    task_id = sqlite3_column_int(stmt, 0);
    if (!task_id) {
        wdb_finalize(stmt);
        sqlite3_close_v2(db);
        return WM_TASK_DATABASE_NO_TASK;
    }

    wdb_finalize(stmt);

    if (wdb_prepare(db, task_queries[WM_TASK_GET_TASK_STATUS], -1, &stmt, NULL) != SQLITE_OK) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_SQL_PREPARE_ERROR);
        return wm_task_manager_sql_error(db, stmt);
    }

    sqlite3_bind_int(stmt, 1, task_id);

    if (result = wdb_step(stmt), result != SQLITE_ROW) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_SQL_STEP_ERROR);
        return wm_task_manager_sql_error(db, stmt);
    }

    // Check old status
    old_status = (char *)sqlite3_column_text(stmt, 0);
    if(!strcmp(old_status, task_statuses[WM_TASK_DONE]) ||
       !strcmp(old_status, task_statuses[WM_TASK_FAILED])) {
        wdb_finalize(stmt);
        sqlite3_close_v2(db);
        return WM_TASK_DATABASE_NO_TASK;
    }

    wdb_finalize(stmt);

    if (wdb_prepare(db, task_queries[WM_TASK_UPDATE_TASK_STATUS], -1, &stmt, NULL) != SQLITE_OK) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_SQL_PREPARE_ERROR);
        return wm_task_manager_sql_error(db, stmt);
    }

    sqlite3_bind_text(stmt, 1, status, -1, NULL);
    sqlite3_bind_int(stmt, 2, task_id);

    if (result = wdb_step(stmt), result != SQLITE_DONE && result != SQLITE_CONSTRAINT) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_SQL_STEP_ERROR);
        return wm_task_manager_sql_error(db, stmt);
    }

    wdb_finalize(stmt);

    sqlite3_close_v2(db);

    return WM_TASK_SUCCESS;
}

#endif
