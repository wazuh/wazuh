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

#ifdef WAZUH_UNIT_TESTING
// Remove static qualifier when unit testing
#define STATIC
#else
#define STATIC static
#endif

#ifndef WIN32

#include "../wmodules.h"
#include "wm_task_manager_db.h"
#include "../wm_task_general.h"
#include "wazuh_db/wdb.h"

// Mutex needed to access tasks DB
pthread_mutex_t db_mutex = PTHREAD_MUTEX_INITIALIZER;

STATIC int wm_task_manager_sql_error(sqlite3 *db, sqlite3_stmt *stmt);

/**
 * Update old tasks with status in progress to status timeout
 * @param now Actual time
 * @param timeout Task timeout
 * @param next_timeout Next task in progress timeout
 * @return OS_SUCCESS on success, OS_INVALID on errors
 * */
STATIC int wm_task_manager_set_timeout_status(time_t now, int timeout, time_t *next_timeout) __attribute__((nonnull));

/**
 * Delete old tasks from the tasks DB
 * @param timestamp Deletion limit time
 * @return OS_SUCCESS on success, OS_INVALID on errors
 * */
STATIC int wm_task_manager_delete_old_entries(int timestamp);

static const char *task_queries[] = {
    [WM_TASK_INSERT_TASK] = "INSERT INTO " TASKS_TABLE " VALUES(NULL,?,?,?,?,?,?,?,?);",
    [WM_TASK_GET_LAST_AGENT_TASK] = "SELECT *, MAX(CREATE_TIME) FROM " TASKS_TABLE " WHERE AGENT_ID = ?;",
    [WM_TASK_GET_LAST_AGENT_UPGRADE_TASK] = "SELECT *, MAX(CREATE_TIME) FROM " TASKS_TABLE " WHERE AGENT_ID = ? AND (COMMAND = 'upgrade' OR COMMAND = 'upgrade_custom');",
    [WM_TASK_UPDATE_TASK_STATUS] = "UPDATE " TASKS_TABLE " SET STATUS = ?, LAST_UPDATE_TIME = ?, ERROR_MESSAGE = ? WHERE TASK_ID = ?;",
    [WM_TASK_GET_TASK_BY_TASK_ID] = "SELECT * FROM " TASKS_TABLE " WHERE TASK_ID = ?;",
    [WM_TASK_GET_TASK_BY_STATUS] = "SELECT * FROM " TASKS_TABLE " WHERE STATUS = ?;",
    [WM_TASK_DELETE_OLD_TASKS] = "DELETE FROM " TASKS_TABLE " WHERE CREATE_TIME <= ?;",
    [WM_TASK_DELETE_TASK] = "DELETE FROM " TASKS_TABLE " WHERE TASK_ID = ?;",
    [WM_TASK_CANCEL_PENDING_UPGRADE_TASKS] = "UPDATE " TASKS_TABLE " SET STATUS = '" WM_TASK_STATUS_CANCELLED "', LAST_UPDATE_TIME = ? WHERE NODE = ? AND STATUS = '" WM_TASK_STATUS_PENDING "';"
};

STATIC int wm_task_manager_sql_error(sqlite3 *db, sqlite3_stmt *stmt) {
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

    w_mutex_lock(&db_mutex);

    // Open or create the database file
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL)) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_CREATE_DB_ERROR);
        w_mutex_unlock(&db_mutex);
        return wm_task_manager_sql_error(db, stmt);
    }

    // Load the tables schema
    for (sql = schema_task_manager_sql; sql && *sql; sql = tail) {
        if (wdb_prepare(db, sql, -1, &stmt, &tail) != SQLITE_OK) {
            mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_SQL_PREPARE_ERROR);
            w_mutex_unlock(&db_mutex);
            return wm_task_manager_sql_error(db, stmt);
        }

        switch (wdb_step(stmt)) {
        case SQLITE_MISUSE:
        case SQLITE_ROW:
        case SQLITE_DONE:
        case SQLITE_CONSTRAINT:
            break;
        default:
            mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_SQL_STEP_ERROR);
            w_mutex_unlock(&db_mutex);
            return wm_task_manager_sql_error(db, stmt);
        }

        wdb_finalize(stmt);
    }

    sqlite3_close_v2(db);

    w_mutex_unlock(&db_mutex);

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

void* wm_task_manager_clean_db(void *arg) {
    wm_task_manager *config = (wm_task_manager *)arg;
    time_t next_clean = time(0);
    time_t next_timeout = time(0);

    while (1) {
        time_t now = time(0);
        time_t sleep_time = 0;

        if (now >= next_timeout) {
            // Set the status of old tasks IN PROGRESS to TIMEOUT
            next_timeout = now + config->task_timeout;
            wm_task_manager_set_timeout_status(now, config->task_timeout, &next_timeout);
        }

        if (now >= next_clean) {
            // Delete entries older than cleanup_time
            next_clean = now + WM_TASK_CLEANUP_DB_SLEEP_TIME;
            wm_task_manager_delete_old_entries((now - config->cleanup_time));
        }

        if (next_timeout < next_clean) {
            sleep_time = next_timeout;
        } else {
            sleep_time = next_clean;
        }

        w_sleep_until(sleep_time);

    #ifdef WAZUH_UNIT_TESTING
        break;
    #endif
    }

    return NULL;
}

STATIC int wm_task_manager_set_timeout_status(time_t now, int timeout, time_t *next_timeout) {
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    sqlite3_stmt *stmt2 = NULL;
    int result = OS_INVALID;

    w_mutex_lock(&db_mutex);

    if (sqlite3_open_v2(TASKS_DB, &db, SQLITE_OPEN_READWRITE, NULL)) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_OPEN_DB_ERROR);
        w_mutex_unlock(&db_mutex);
        return wm_task_manager_sql_error(db, stmt);
    }

    if (wdb_prepare(db, task_queries[WM_TASK_GET_TASK_BY_STATUS], -1, &stmt, NULL) != SQLITE_OK) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_SQL_PREPARE_ERROR);
        w_mutex_unlock(&db_mutex);
        return wm_task_manager_sql_error(db, stmt);
    }

    sqlite3_bind_text(stmt, 1, task_statuses[WM_TASK_IN_PROGRESS], -1, NULL);

    while (result = wdb_step(stmt), result == SQLITE_ROW) {
        int task_id = sqlite3_column_int(stmt, 0);
        int last_update_time = sqlite3_column_int(stmt, 6);

        // Check if the last update time is longer than the timeout
        if (now >= (last_update_time + timeout)) {

            if (wdb_prepare(db, task_queries[WM_TASK_UPDATE_TASK_STATUS], -1, &stmt2, NULL) != SQLITE_OK) {
                mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_SQL_PREPARE_ERROR);
                w_mutex_unlock(&db_mutex);
                wdb_finalize(stmt);
                return wm_task_manager_sql_error(db, stmt2);
            }

            sqlite3_bind_text(stmt2, 1, task_statuses[WM_TASK_TIMEOUT], -1, NULL);
            sqlite3_bind_int(stmt2, 2, time(0));
            sqlite3_bind_int(stmt2, 4, task_id);

            if (result = wdb_step(stmt2), result != SQLITE_DONE && result != SQLITE_CONSTRAINT) {
                mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_SQL_STEP_ERROR);
                w_mutex_unlock(&db_mutex);
                wdb_finalize(stmt);
                return wm_task_manager_sql_error(db, stmt2);
            }

            wdb_finalize(stmt2);

        } else if (*next_timeout > (last_update_time + timeout)) {
            *next_timeout = last_update_time + timeout;
        }
    }

    wdb_finalize(stmt);

    sqlite3_close_v2(db);

    w_mutex_unlock(&db_mutex);

    return OS_SUCCESS;
}

STATIC int wm_task_manager_delete_old_entries(int timestamp) {
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int result = OS_INVALID;

    mtinfo(WM_TASK_MANAGER_LOGTAG, MOD_TASK_RUNNING_CLEAN);

    w_mutex_lock(&db_mutex);

    if (sqlite3_open_v2(TASKS_DB, &db, SQLITE_OPEN_READWRITE, NULL)) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_OPEN_DB_ERROR);
        w_mutex_unlock(&db_mutex);
        return wm_task_manager_sql_error(db, stmt);
    }

    if (wdb_prepare(db, task_queries[WM_TASK_DELETE_OLD_TASKS], -1, &stmt, NULL) != SQLITE_OK) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_SQL_PREPARE_ERROR);
        w_mutex_unlock(&db_mutex);
        return wm_task_manager_sql_error(db, stmt);
    }

    sqlite3_bind_int(stmt, 1, timestamp);

    if (result = wdb_step(stmt), result != SQLITE_DONE) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_SQL_STEP_ERROR);
        w_mutex_unlock(&db_mutex);
        return wm_task_manager_sql_error(db, stmt);
    }

    wdb_finalize(stmt);

    sqlite3_close_v2(db);

    w_mutex_unlock(&db_mutex);

    return OS_SUCCESS;
}

int wm_task_manager_insert_task(int agent_id, const char *node, const char *module, const char *command) {
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int result = 0;
    int task_id = OS_INVALID;

    w_mutex_lock(&db_mutex);

    if (sqlite3_open_v2(TASKS_DB, &db, SQLITE_OPEN_READWRITE, NULL)) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_OPEN_DB_ERROR);
        w_mutex_unlock(&db_mutex);
        return wm_task_manager_sql_error(db, stmt);
    }

    if (wdb_prepare(db, task_queries[WM_TASK_INSERT_TASK], -1, &stmt, NULL) != SQLITE_OK) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_SQL_PREPARE_ERROR);
        w_mutex_unlock(&db_mutex);
        return wm_task_manager_sql_error(db, stmt);
    }

    sqlite3_bind_int(stmt, 1, agent_id);
    sqlite3_bind_text(stmt, 2, node, -1, NULL);
    sqlite3_bind_text(stmt, 3, module, -1, NULL);
    sqlite3_bind_text(stmt, 4, command, -1, NULL);
    sqlite3_bind_int(stmt, 5, time(0));
    sqlite3_bind_text(stmt, 7, task_statuses[WM_TASK_PENDING], -1, NULL);

    if (result = wdb_step(stmt), result != SQLITE_DONE && result != SQLITE_CONSTRAINT) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_SQL_STEP_ERROR);
        w_mutex_unlock(&db_mutex);
        return wm_task_manager_sql_error(db, stmt);
    }

    wdb_finalize(stmt);

    if (wdb_prepare(db, task_queries[WM_TASK_GET_LAST_AGENT_TASK], -1, &stmt, NULL) != SQLITE_OK) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_SQL_PREPARE_ERROR);
        w_mutex_unlock(&db_mutex);
        return wm_task_manager_sql_error(db, stmt);
    }

    sqlite3_bind_int(stmt, 1, agent_id);

    if (result = wdb_step(stmt), result != SQLITE_ROW) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_SQL_STEP_ERROR);
        w_mutex_unlock(&db_mutex);
        return wm_task_manager_sql_error(db, stmt);
    }

    // Check task id
    task_id = sqlite3_column_int(stmt, 0);
    if (!task_id) {
        wdb_finalize(stmt);
        sqlite3_close_v2(db);
        w_mutex_unlock(&db_mutex);
        return OS_INVALID;
    }

    wdb_finalize(stmt);

    sqlite3_close_v2(db);

    w_mutex_unlock(&db_mutex);

    return task_id;
}

int wm_task_manager_get_upgrade_task_status(int agent_id, const char *node, char **status) {
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    sqlite3_stmt *stmt2 = NULL;
    int result = 0;
    int task_id = OS_INVALID;
    char *task_status = NULL;
    char *task_node = NULL;

    w_mutex_lock(&db_mutex);

    if (sqlite3_open_v2(TASKS_DB, &db, SQLITE_OPEN_READWRITE, NULL)) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_OPEN_DB_ERROR);
        w_mutex_unlock(&db_mutex);
        return wm_task_manager_sql_error(db, stmt);
    }

    if (wdb_prepare(db, task_queries[WM_TASK_GET_LAST_AGENT_UPGRADE_TASK], -1, &stmt, NULL) != SQLITE_OK) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_SQL_PREPARE_ERROR);
        w_mutex_unlock(&db_mutex);
        return wm_task_manager_sql_error(db, stmt);
    }

    sqlite3_bind_int(stmt, 1, agent_id);

    if (result = wdb_step(stmt), result != SQLITE_ROW) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_SQL_STEP_ERROR);
        w_mutex_unlock(&db_mutex);
        return wm_task_manager_sql_error(db, stmt);
    }

    // Check task id
    task_id = sqlite3_column_int(stmt, 0);
    if (!task_id) {
        wdb_finalize(stmt);
        sqlite3_close_v2(db);
        w_mutex_unlock(&db_mutex);
        return WM_TASK_SUCCESS;
    }

    // Check current task
    task_node = (char*)sqlite3_column_text(stmt, 2);
    task_status = (char*)sqlite3_column_text(stmt, 7);

    if (!strcmp(task_status, task_statuses[WM_TASK_PENDING]) && strcmp(task_node, node)) {

        // Delete old pending task
        if (wdb_prepare(db, task_queries[WM_TASK_DELETE_TASK], -1, &stmt2, NULL) != SQLITE_OK) {
            mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_SQL_PREPARE_ERROR);
            w_mutex_unlock(&db_mutex);
            wdb_finalize(stmt);
            return wm_task_manager_sql_error(db, stmt2);
        }

        sqlite3_bind_int(stmt2, 1, task_id);

        if (result = wdb_step(stmt2), result != SQLITE_DONE) {
            mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_SQL_STEP_ERROR);
            w_mutex_unlock(&db_mutex);
            wdb_finalize(stmt);
            return wm_task_manager_sql_error(db, stmt2);
        }

        wdb_finalize(stmt2);

    } else {
        sqlite_strdup(task_status, *status);
    }

    wdb_finalize(stmt);

    sqlite3_close_v2(db);

    w_mutex_unlock(&db_mutex);

    return WM_TASK_SUCCESS;
}

int wm_task_manager_update_upgrade_task_status(int agent_id, const char *node, const char *status, const char *error) {
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int result = 0;
    int task_id = OS_INVALID;
    char *old_status = NULL;
    char *old_node = NULL;

    if (!status || (strcmp(status, task_statuses[WM_TASK_IN_PROGRESS]) && strcmp(status, task_statuses[WM_TASK_DONE]) && strcmp(status, task_statuses[WM_TASK_FAILED]) && strcmp(status, task_statuses[WM_TASK_LEGACY]))) {
        return WM_TASK_INVALID_STATUS;
    }

    w_mutex_lock(&db_mutex);

    if (sqlite3_open_v2(TASKS_DB, &db, SQLITE_OPEN_READWRITE, NULL)) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_OPEN_DB_ERROR);
        w_mutex_unlock(&db_mutex);
        return wm_task_manager_sql_error(db, stmt);
    }

    if (wdb_prepare(db, task_queries[WM_TASK_GET_LAST_AGENT_UPGRADE_TASK], -1, &stmt, NULL) != SQLITE_OK) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_SQL_PREPARE_ERROR);
        w_mutex_unlock(&db_mutex);
        return wm_task_manager_sql_error(db, stmt);
    }

    sqlite3_bind_int(stmt, 1, agent_id);

    if (result = wdb_step(stmt), result != SQLITE_ROW) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_SQL_STEP_ERROR);
        w_mutex_unlock(&db_mutex);
        return wm_task_manager_sql_error(db, stmt);
    }

    // Check task id
    task_id = sqlite3_column_int(stmt, 0);
    if (!task_id) {
        wdb_finalize(stmt);
        sqlite3_close_v2(db);
        w_mutex_unlock(&db_mutex);
        return WM_TASK_DATABASE_NO_TASK;
    }

    // Check old task
    old_node = (char*)sqlite3_column_text(stmt, 2);
    old_status = (char *)sqlite3_column_text(stmt, 7);

    if((!strcmp(status, task_statuses[WM_TASK_IN_PROGRESS]) && (strcmp(old_status, task_statuses[WM_TASK_PENDING]) || strcmp(old_node, node))) ||
       (!strcmp(status, task_statuses[WM_TASK_LEGACY]) && (strcmp(old_status, task_statuses[WM_TASK_IN_PROGRESS]) || strcmp(old_node, node))) ||
       (!strcmp(status, task_statuses[WM_TASK_DONE]) && strcmp(old_status, task_statuses[WM_TASK_IN_PROGRESS])) ||
       (!strcmp(status, task_statuses[WM_TASK_FAILED]) && strcmp(old_status, task_statuses[WM_TASK_IN_PROGRESS]))) {
        wdb_finalize(stmt);
        sqlite3_close_v2(db);
        w_mutex_unlock(&db_mutex);
        return WM_TASK_DATABASE_NO_TASK;
    }

    wdb_finalize(stmt);

    if (wdb_prepare(db, task_queries[WM_TASK_UPDATE_TASK_STATUS], -1, &stmt, NULL) != SQLITE_OK) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_SQL_PREPARE_ERROR);
        w_mutex_unlock(&db_mutex);
        return wm_task_manager_sql_error(db, stmt);
    }

    sqlite3_bind_text(stmt, 1, status, -1, NULL);
    sqlite3_bind_int(stmt, 2, time(0));
    if (error) {
        sqlite3_bind_text(stmt, 3, error, -1, NULL);
    }
    sqlite3_bind_int(stmt, 4, task_id);

    if (result = wdb_step(stmt), result != SQLITE_DONE && result != SQLITE_CONSTRAINT) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_SQL_STEP_ERROR);
        w_mutex_unlock(&db_mutex);
        return wm_task_manager_sql_error(db, stmt);
    }

    wdb_finalize(stmt);

    sqlite3_close_v2(db);

    w_mutex_unlock(&db_mutex);

    return WM_TASK_SUCCESS;
}

int wm_task_manager_cancel_upgrade_tasks(const char *node) {
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int result = 0;

    w_mutex_lock(&db_mutex);

    if (sqlite3_open_v2(TASKS_DB, &db, SQLITE_OPEN_READWRITE, NULL)) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_OPEN_DB_ERROR);
        w_mutex_unlock(&db_mutex);
        return wm_task_manager_sql_error(db, stmt);
    }

    if (wdb_prepare(db, task_queries[WM_TASK_CANCEL_PENDING_UPGRADE_TASKS], -1, &stmt, NULL) != SQLITE_OK) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_SQL_PREPARE_ERROR);
        w_mutex_unlock(&db_mutex);
        return wm_task_manager_sql_error(db, stmt);
    }

    sqlite3_bind_int(stmt, 1, time(0));
    sqlite3_bind_text(stmt, 2, node, -1, NULL);

    if (result = wdb_step(stmt), result != SQLITE_DONE && result != SQLITE_CONSTRAINT) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_SQL_STEP_ERROR);
        w_mutex_unlock(&db_mutex);
        return wm_task_manager_sql_error(db, stmt);
    }

    wdb_finalize(stmt);

    sqlite3_close_v2(db);

    w_mutex_unlock(&db_mutex);

    return WM_TASK_SUCCESS;
}

int wm_task_manager_get_upgrade_task_by_agent_id(int agent_id, char **node, char **module, char **command, char **status, char **error, int *create_time, int *last_update_time) {
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int result = OS_INVALID;
    int task_id;

    w_mutex_lock(&db_mutex);

    if (sqlite3_open_v2(TASKS_DB, &db, SQLITE_OPEN_READONLY, NULL)) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_OPEN_DB_ERROR);
        w_mutex_unlock(&db_mutex);
        return wm_task_manager_sql_error(db, stmt);
    }

    if (wdb_prepare(db, task_queries[WM_TASK_GET_LAST_AGENT_UPGRADE_TASK], -1, &stmt, NULL) != SQLITE_OK) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_SQL_PREPARE_ERROR);
        w_mutex_unlock(&db_mutex);
        return wm_task_manager_sql_error(db, stmt);
    }

    sqlite3_bind_int(stmt, 1, agent_id);

    if (result = wdb_step(stmt), result != SQLITE_ROW) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_SQL_STEP_ERROR);
        w_mutex_unlock(&db_mutex);
        return wm_task_manager_sql_error(db, stmt);
    }

    task_id = sqlite3_column_int(stmt, 0);

    if (!task_id) {
        result = OS_NOTFOUND;
    } else {
        sqlite_strdup((char*)sqlite3_column_text(stmt, 2), *node);
        sqlite_strdup((char*)sqlite3_column_text(stmt, 3), *module);
        sqlite_strdup((char*)sqlite3_column_text(stmt, 4), *command);
        *create_time = sqlite3_column_int(stmt, 5);
        *last_update_time = sqlite3_column_int(stmt, 6);
        sqlite_strdup((char*)sqlite3_column_text(stmt, 7), *status);
        sqlite_strdup((char*)sqlite3_column_text(stmt, 8), *error);
        result = task_id;
    }

    wdb_finalize(stmt);

    sqlite3_close_v2(db);

    w_mutex_unlock(&db_mutex);

    return result;
}

int wm_task_manager_get_task_by_task_id(int task_id, char **node, char **module, char **command, char **status, char **error, int *create_time, int *last_update_time) {
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int result = OS_INVALID;
    int agent_id;

    w_mutex_lock(&db_mutex);

    if (sqlite3_open_v2(TASKS_DB, &db, SQLITE_OPEN_READONLY, NULL)) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_OPEN_DB_ERROR);
        w_mutex_unlock(&db_mutex);
        return wm_task_manager_sql_error(db, stmt);
    }

    if (wdb_prepare(db, task_queries[WM_TASK_GET_TASK_BY_TASK_ID], -1, &stmt, NULL) != SQLITE_OK) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_SQL_PREPARE_ERROR);
        w_mutex_unlock(&db_mutex);
        return wm_task_manager_sql_error(db, stmt);
    }

    sqlite3_bind_int(stmt, 1, task_id);

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
        agent_id = sqlite3_column_int(stmt, 1);
        sqlite_strdup((char*)sqlite3_column_text(stmt, 2), *node);
        sqlite_strdup((char*)sqlite3_column_text(stmt, 3), *module);
        sqlite_strdup((char*)sqlite3_column_text(stmt, 4), *command);
        *create_time = sqlite3_column_int(stmt, 5);
        *last_update_time = sqlite3_column_int(stmt, 6);
        sqlite_strdup((char*)sqlite3_column_text(stmt, 7), *status);
        sqlite_strdup((char*)sqlite3_column_text(stmt, 8), *error);
        result = agent_id;
        break;
    case SQLITE_DONE:
        result = OS_NOTFOUND;
        break;
    default:
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_SQL_STEP_ERROR);
        w_mutex_unlock(&db_mutex);
        return wm_task_manager_sql_error(db, stmt);
    }

    wdb_finalize(stmt);

    sqlite3_close_v2(db);

    w_mutex_unlock(&db_mutex);

    return result;
}

#endif
