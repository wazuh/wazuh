/*
 * Wazuh Module for Task management.
 * Copyright (C) 2015, Wazuh Inc.
 * July 13, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wdb.h"

int wdb_task_create(wdb_t* wdb, const char *task_id, const char *agent_id, const char *task_type, const char *payload) {
    sqlite3_stmt *stmt = NULL;
    int result = 0;
    time_t create_time = time(0);

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1(DB_TRANSACTION_ERROR);
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_TASK_CREATE) < 0) {
        mdebug1(DB_CACHE_ERROR);
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_TASK_CREATE];

    sqlite3_bind_text(stmt, 1, task_id, -1, NULL);
    sqlite3_bind_text(stmt, 2, agent_id, -1, NULL);
    sqlite3_bind_text(stmt, 3, task_type, -1, NULL);
    sqlite3_bind_text(stmt, 4, payload, -1, NULL);
    sqlite3_bind_int(stmt, 5, create_time);
    sqlite3_bind_text(stmt, 6, "pending", -1, NULL);

    if (result = wdb_step(stmt), result != SQLITE_DONE && result != SQLITE_CONSTRAINT) {
        merror(DB_SQL_ERROR, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    return OS_SUCCESS;
}

int wdb_task_get_pending(wdb_t* wdb, const char *agent_id, int max_tasks, cJSON **tasks_json) {
    sqlite3_stmt *stmt = NULL;
    int result = 0;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1(DB_TRANSACTION_ERROR);
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_TASK_GET_PENDING) < 0) {
        mdebug1(DB_CACHE_ERROR);
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_TASK_GET_PENDING];

    sqlite3_bind_text(stmt, 1, agent_id, -1, NULL);
    sqlite3_bind_int(stmt, 2, max_tasks);

    *tasks_json = cJSON_CreateArray();
    if (!*tasks_json) {
        merror("Failed to create JSON array for pending tasks");
        return OS_INVALID;
    }

    while ((result = wdb_step(stmt)) == SQLITE_ROW) {
        cJSON *task = cJSON_CreateObject();
        if (!task) {
            cJSON_Delete(*tasks_json);
            *tasks_json = NULL;
            return OS_INVALID;
        }

        const char *task_id = (const char*)sqlite3_column_text(stmt, 0);
        const char *task_type = (const char*)sqlite3_column_text(stmt, 2);
        const char *payload = (const char*)sqlite3_column_text(stmt, 3);
        int create_time = sqlite3_column_int(stmt, 4);

        cJSON_AddStringToObject(task, "task_id", task_id);
        cJSON_AddStringToObject(task, "task_type", task_type);
        cJSON_AddStringToObject(task, "payload", payload);
        cJSON_AddNumberToObject(task, "create_time", create_time);

        cJSON_AddItemToArray(*tasks_json, task);
    }

    if (result != SQLITE_DONE) {
        merror(DB_SQL_ERROR, sqlite3_errmsg(wdb->db));
        cJSON_Delete(*tasks_json);
        *tasks_json = NULL;
        return OS_INVALID;
    }

    return OS_SUCCESS;
}

int wdb_task_mark_delivered(wdb_t* wdb, const char *task_id, time_t delivery_time) {
    sqlite3_stmt *stmt = NULL;
    int result = 0;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1(DB_TRANSACTION_ERROR);
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_TASK_MARK_DELIVERED) < 0) {
        mdebug1(DB_CACHE_ERROR);
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_TASK_MARK_DELIVERED];

    sqlite3_bind_int(stmt, 1, delivery_time);
    sqlite3_bind_text(stmt, 2, task_id, -1, NULL);

    if (result = wdb_step(stmt), result != SQLITE_DONE && result != SQLITE_CONSTRAINT) {
        merror(DB_SQL_ERROR, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    return OS_SUCCESS;
}

int wdb_task_cleanup_expired(wdb_t* wdb, int ttl) {
    sqlite3_stmt *stmt = NULL;
    int result = 0;
    time_t cutoff_time = time(0) - ttl;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1(DB_TRANSACTION_ERROR);
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_TASK_CLEANUP_EXPIRED) < 0) {
        mdebug1(DB_CACHE_ERROR);
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_TASK_CLEANUP_EXPIRED];

    sqlite3_bind_int(stmt, 1, cutoff_time);

    if (result = wdb_step(stmt), result != SQLITE_DONE && result != SQLITE_CONSTRAINT) {
        merror(DB_SQL_ERROR, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    return OS_SUCCESS;
}

/**
 * Delete old expired/delivered tasks from the tasks DB.
 * Keeps tasks for 24 hours after expiry/delivery for debugging.
 * @param wdb The task struct database
 * @param timestamp Cutoff timestamp (tasks older than this are deleted)
 * @return OS_SUCCESS on success, OS_INVALID on errors
 * */
int wdb_task_delete_old(wdb_t* wdb, time_t timestamp) {
    sqlite3_stmt *stmt = NULL;
    int result = OS_INVALID;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1(DB_TRANSACTION_ERROR);
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_TASK_DELETE_OLD) < 0) {
        mdebug1(DB_CACHE_ERROR);
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_TASK_DELETE_OLD];

    sqlite3_bind_int64(stmt, 1, timestamp);
    sqlite3_bind_int64(stmt, 2, timestamp);

    if (result = wdb_step(stmt), result != SQLITE_DONE) {
        merror(DB_SQL_ERROR, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    return OS_SUCCESS;
}
