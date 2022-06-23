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
#include "wazuh_modules/wm_task_general.h"

int wdb_task_insert_task(wdb_t* wdb, int agent_id, const char *node, const char *module, const char *command) {
    sqlite3_stmt *stmt = NULL;
    int result = 0;
    int task_id = OS_INVALID;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1(DB_TRANSACTION_ERROR);
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_TASK_INSERT_TASK) < 0) {
        mdebug1(DB_CACHE_ERROR);
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_TASK_INSERT_TASK];

    sqlite3_bind_int(stmt, 1, agent_id);
    sqlite3_bind_text(stmt, 2, node, -1, NULL);
    sqlite3_bind_text(stmt, 3, module, -1, NULL);
    sqlite3_bind_text(stmt, 4, command, -1, NULL);
    sqlite3_bind_int(stmt, 5, time(0));
    sqlite3_bind_text(stmt, 7, task_statuses[WM_TASK_PENDING], -1, NULL);

    if (result = wdb_step(stmt), result != SQLITE_DONE && result != SQLITE_CONSTRAINT) {
        merror(DB_SQL_ERROR, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_TASK_GET_LAST_AGENT_TASK) < 0) {
        mdebug1(DB_CACHE_ERROR);
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_TASK_GET_LAST_AGENT_TASK];

    sqlite3_bind_int(stmt, 1, agent_id);

    if (result = wdb_step(stmt), result != SQLITE_ROW) {
        merror(DB_SQL_ERROR, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    // Check task id
    task_id = sqlite3_column_int(stmt, 0);
    if (!task_id) {
        return OS_INVALID;
    }

    return task_id;
}

int wdb_task_get_task_status_by_id(wdb_t* wdb, int task_id, char **status) {
    sqlite3_stmt *stmt = NULL;
    int result = 0;
    char *task_status = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1(DB_TRANSACTION_ERROR);
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_TASK_GET_TASK_BY_ID) < 0) {
        mdebug1(DB_CACHE_ERROR);
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_TASK_GET_TASK_BY_ID];

    sqlite3_bind_int(stmt, 1, task_id);

    // Check current task
    if (result = wdb_step(stmt), SQLITE_ROW == result) {
        task_status = (char*)sqlite3_column_text(stmt, 7);
        sqlite_strdup(task_status, *status);
    } else if (result != SQLITE_DONE) {
        merror(DB_SQL_ERROR, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    return OS_SUCCESS;
}

int wdb_task_get_last_task_status(wdb_t* wdb, int agent_id, const char *node, const char *command, char **status) {
    sqlite3_stmt *stmt = NULL;
    int result = 0;
    int task_id = OS_INVALID;
    char *task_status = NULL;
    char *task_node = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1(DB_TRANSACTION_ERROR);
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_TASK_GET_LAST_AGENT_TASK_BY_COMMAND) < 0) {
        mdebug1(DB_CACHE_ERROR);
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_TASK_GET_LAST_AGENT_TASK_BY_COMMAND];

    sqlite3_bind_int(stmt, 1, agent_id);
    sqlite3_bind_text(stmt, 2, command, -1, NULL);

    if (result = wdb_step(stmt), result != SQLITE_ROW) {
        merror(DB_SQL_ERROR, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    // Check task id
    task_id = sqlite3_column_int(stmt, 0);
    if (!task_id) {
        return OS_SUCCESS;
    }

    // Check current task
    task_node = (char*)sqlite3_column_text(stmt, 2);
    task_status = (char*)sqlite3_column_text(stmt, 7);

    if (!strcmp(task_status, task_statuses[WM_TASK_PENDING]) && strcmp(task_node, node)) {

        // Delete old pending task
        if (wdb_stmt_cache(wdb, WDB_STMT_TASK_DELETE_TASK) < 0) {
            mdebug1(DB_CACHE_ERROR);
            return OS_INVALID;
        }

        stmt = wdb->stmt[WDB_STMT_TASK_DELETE_TASK];

        sqlite3_bind_int(stmt, 1, task_id);

        if (result = wdb_step(stmt), result != SQLITE_DONE) {
            merror(DB_SQL_ERROR, sqlite3_errmsg(wdb->db));
            return OS_INVALID;
        }

    } else {
        sqlite_strdup(task_status, *status);
    }

    return OS_SUCCESS;
}

int wdb_task_get_last_task_status_without_agent_id(wdb_t* wdb, const char *node, const char *command, char **status) {
    sqlite3_stmt *stmt = NULL;
    int result = 0;
    int task_id = OS_INVALID;
    char *task_status = NULL;
    char *task_node = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1(DB_TRANSACTION_ERROR);
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_TASK_GET_LAST_AGENT_TASK_BY_COMMAND_WITHOUT_AGENT_ID) < 0) {
        mdebug1(DB_CACHE_ERROR);
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_TASK_GET_LAST_AGENT_TASK_BY_COMMAND_WITHOUT_AGENT_ID];

    sqlite3_bind_text(stmt, 1, node, -1, NULL);
    sqlite3_bind_text(stmt, 2, command, -1, NULL);

    if (result = wdb_step(stmt), result != SQLITE_ROW) {
        merror(DB_SQL_ERROR, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    // Check task id
    task_id = sqlite3_column_int(stmt, 0);
    if (!task_id) {
        return OS_SUCCESS;
    }

    // Check current task
    task_node = (char*)sqlite3_column_text(stmt, 2);
    task_status = (char*)sqlite3_column_text(stmt, 7);

    if (!strcmp(task_status, task_statuses[WM_TASK_PENDING]) && strcmp(task_node, node)) {

        // Delete old pending task
        if (wdb_stmt_cache(wdb, WDB_STMT_TASK_DELETE_TASK) < 0) {
            mdebug1(DB_CACHE_ERROR);
            return OS_INVALID;
        }

        stmt = wdb->stmt[WDB_STMT_TASK_DELETE_TASK];

        sqlite3_bind_int(stmt, 1, task_id);

        if (result = wdb_step(stmt), result != SQLITE_DONE) {
            merror(DB_SQL_ERROR, sqlite3_errmsg(wdb->db));
            return OS_INVALID;
        }

    } else {
        sqlite_strdup(task_status, *status);
    }

    return OS_SUCCESS;
}

int wdb_task_update_task_status(wdb_t* wdb, int agent_id, const char *node, const char *status, const char* command, const char *error) {
    sqlite3_stmt *stmt = NULL;
    int result = 0;
    int task_id = OS_INVALID;
    char *old_status = NULL;
    char *old_node = NULL;

    if (strcmp(status, task_statuses[WM_TASK_IN_PROGRESS]) &&
        strcmp(status, task_statuses[WM_TASK_DONE]) &&
        strcmp(status, task_statuses[WM_TASK_FAILED]) &&
        strcmp(status, task_statuses[WM_TASK_LEGACY])) {
        return OS_INVALID;
    }

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1(DB_TRANSACTION_ERROR);
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_TASK_GET_LAST_AGENT_TASK_BY_COMMAND) < 0) {
        mdebug1(DB_CACHE_ERROR);
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_TASK_GET_LAST_AGENT_TASK_BY_COMMAND];

    sqlite3_bind_int(stmt, 1, agent_id);
    sqlite3_bind_text(stmt, 2, command, -1, NULL);

    if (result = wdb_step(stmt), result != SQLITE_ROW) {
        merror(DB_SQL_ERROR, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    // Check task id
    task_id = sqlite3_column_int(stmt, 0);
    if (!task_id) {
        return OS_NOTFOUND;
    }

    // Check old task
    old_node = (char*)sqlite3_column_text(stmt, 2);
    old_status = (char *)sqlite3_column_text(stmt, 7);

    if((!strcmp(status, task_statuses[WM_TASK_IN_PROGRESS]) && (strcmp(old_status, task_statuses[WM_TASK_PENDING]) || strcmp(old_node, node))) ||
       (!strcmp(status, task_statuses[WM_TASK_LEGACY]) && (strcmp(old_status, task_statuses[WM_TASK_IN_PROGRESS]) || strcmp(old_node, node))) ||
       (!strcmp(status, task_statuses[WM_TASK_DONE]) && strcmp(old_status, task_statuses[WM_TASK_IN_PROGRESS])) ||
       (!strcmp(status, task_statuses[WM_TASK_FAILED]) && strcmp(old_status, task_statuses[WM_TASK_IN_PROGRESS]))) {
        return OS_NOTFOUND;
    }

    return wdb_task_update_task_status_by_id(wdb, task_id, status, error);
}

int wdb_task_update_task_status_without_agent_id(wdb_t* wdb, const char *node, const char *status, const char* command, const char *error) {
    sqlite3_stmt *stmt = NULL;
    int result = 0;
    int task_id = OS_INVALID;
    char *old_status = NULL;
    char *old_node = NULL;

    if (strcmp(status, task_statuses[WM_TASK_IN_PROGRESS]) &&
        strcmp(status, task_statuses[WM_TASK_DONE]) &&
        strcmp(status, task_statuses[WM_TASK_FAILED]) &&
        strcmp(status, task_statuses[WM_TASK_LEGACY])) {
        return OS_INVALID;
    }

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1(DB_TRANSACTION_ERROR);
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_TASK_GET_LAST_AGENT_TASK_BY_COMMAND_WITHOUT_AGENT_ID) < 0) {
        mdebug1(DB_CACHE_ERROR);
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_TASK_GET_LAST_AGENT_TASK_BY_COMMAND_WITHOUT_AGENT_ID];

    sqlite3_bind_text(stmt, 1, node, -1, NULL);
    sqlite3_bind_text(stmt, 2, command, -1, NULL);

    if (result = wdb_step(stmt), result != SQLITE_ROW) {
        merror(DB_SQL_ERROR, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    // Check task id
    task_id = sqlite3_column_int(stmt, 0);
    if (!task_id) {
        return OS_NOTFOUND;
    }

    // Check old task
    old_node = (char*)sqlite3_column_text(stmt, 2);
    old_status = (char *)sqlite3_column_text(stmt, 7);

    if((!strcmp(status, task_statuses[WM_TASK_IN_PROGRESS]) && (strcmp(old_status, task_statuses[WM_TASK_PENDING]) || strcmp(old_node, node))) ||
       (!strcmp(status, task_statuses[WM_TASK_LEGACY]) && (strcmp(old_status, task_statuses[WM_TASK_IN_PROGRESS]) || strcmp(old_node, node))) ||
       (!strcmp(status, task_statuses[WM_TASK_DONE]) && strcmp(old_status, task_statuses[WM_TASK_IN_PROGRESS])) ||
       (!strcmp(status, task_statuses[WM_TASK_FAILED]) && strcmp(old_status, task_statuses[WM_TASK_IN_PROGRESS]))) {
        return OS_NOTFOUND;
    }

    return wdb_task_update_task_status_by_id(wdb, task_id, status, error);
}


int wdb_task_update_task_status_by_id(wdb_t* wdb, int task_id, const char *status, const char* error) {
    sqlite3_stmt *stmt = NULL;
    int result = 0;

    if (wdb_stmt_cache(wdb, WDB_STMT_TASK_UPDATE_TASK_STATUS) < 0) {
        mdebug1(DB_CACHE_ERROR);
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_TASK_UPDATE_TASK_STATUS];

    sqlite3_bind_text(stmt, 1, status, -1, NULL);
    sqlite3_bind_int(stmt, 2, time(0));
    sqlite3_bind_text(stmt, 3, error, -1, NULL);
    sqlite3_bind_int(stmt, 4, task_id);

    if (result = wdb_step(stmt), result != SQLITE_DONE && result != SQLITE_CONSTRAINT) {
        merror(DB_SQL_ERROR, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    return OS_SUCCESS;
}

int wdb_task_get_task_by_agent_id(wdb_t* wdb, int agent_id, const char* module, char **node, char **module_result, char **command, char **status, char **error, int *create_time, int *last_update_time) {
    sqlite3_stmt *stmt = NULL;
    int result = OS_INVALID;
    int task_id;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1(DB_TRANSACTION_ERROR);
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_TASK_GET_LAST_AGENT_TASK_BY_COMMAND) < 0) {
        mdebug1(DB_CACHE_ERROR);
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_TASK_GET_LAST_AGENT_TASK_BY_COMMAND];

    sqlite3_bind_int(stmt, 1, agent_id);
    sqlite3_bind_text(stmt, 2, module, -1, NULL);

    if (result = wdb_step(stmt), result != SQLITE_ROW) {
        merror(DB_SQL_ERROR, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    task_id = sqlite3_column_int(stmt, 0);

    if (!task_id) {
        result = OS_NOTFOUND;
    } else {
        sqlite_strdup((char*)sqlite3_column_text(stmt, 2), *node);
        sqlite_strdup((char*)sqlite3_column_text(stmt, 3), *module_result);
        sqlite_strdup((char*)sqlite3_column_text(stmt, 4), *command);
        *create_time = sqlite3_column_int(stmt, 5);
        *last_update_time = sqlite3_column_int(stmt, 6);
        sqlite_strdup((char*)sqlite3_column_text(stmt, 7), *status);
        sqlite_strdup((char*)sqlite3_column_text(stmt, 8), *error);
        result = task_id;
    }

    return result;
}

int wdb_task_cancel_upgrade_tasks(wdb_t* wdb, const char *node) {
    sqlite3_stmt *stmt = NULL;
    int result = 0;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1(DB_TRANSACTION_ERROR);
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_TASK_CANCEL_PENDING_UPGRADE_TASKS) < 0) {
        mdebug1(DB_CACHE_ERROR);
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_TASK_CANCEL_PENDING_UPGRADE_TASKS];

    sqlite3_bind_int(stmt, 1, time(0));
    sqlite3_bind_text(stmt, 2, node, -1, NULL);

    if (result = wdb_step(stmt), result != SQLITE_DONE && result != SQLITE_CONSTRAINT) {
        merror(DB_SQL_ERROR, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    return OS_SUCCESS;
}

int wdb_task_set_timeout_status(wdb_t* wdb, time_t now, int interval, time_t *next_timeout) {
    sqlite3_stmt *stmt = NULL;
    sqlite3_stmt *stmt2 = NULL;
    int result = OS_INVALID;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1(DB_TRANSACTION_ERROR);
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_TASK_GET_TASK_BY_STATUS) < 0) {
        mdebug1(DB_CACHE_ERROR);
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_TASK_GET_TASK_BY_STATUS];

    sqlite3_bind_text(stmt, 1, task_statuses[WM_TASK_IN_PROGRESS], -1, NULL);

    while (result = wdb_step(stmt), result == SQLITE_ROW) {
        int task_id = sqlite3_column_int(stmt, 0);
        int last_update_time = sqlite3_column_int(stmt, 6);

        // Check if the last update time is longer than the timeout
        if (now >= (last_update_time + interval)) {

            if (wdb_stmt_cache(wdb, WDB_STMT_TASK_UPDATE_TASK_STATUS) < 0) {
                mdebug1(DB_CACHE_ERROR);
                return OS_INVALID;
            }

            stmt2 = wdb->stmt[WDB_STMT_TASK_UPDATE_TASK_STATUS];

            sqlite3_bind_text(stmt2, 1, task_statuses[WM_TASK_TIMEOUT], -1, NULL);
            sqlite3_bind_int(stmt2, 2, time(0));
            sqlite3_bind_int(stmt2, 4, task_id);

            if (result = wdb_step(stmt2), result != SQLITE_DONE && result != SQLITE_CONSTRAINT) {
                merror(DB_SQL_ERROR, sqlite3_errmsg(wdb->db));
                return OS_INVALID;
            }

        } else if (*next_timeout > (last_update_time + interval)) {
            *next_timeout = last_update_time + interval;
        }
    }

    return OS_SUCCESS;
}

int wdb_task_delete_old_entries(wdb_t* wdb, int timestamp) {
    sqlite3_stmt *stmt = NULL;
    int result = OS_INVALID;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1(DB_TRANSACTION_ERROR);
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_TASK_DELETE_OLD_TASKS) < 0) {
        mdebug1(DB_CACHE_ERROR);
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_TASK_DELETE_OLD_TASKS];

    sqlite3_bind_int(stmt, 1, timestamp);

    if (result = wdb_step(stmt), result != SQLITE_DONE) {
        merror(DB_SQL_ERROR, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    return OS_SUCCESS;
}

const char* wdb_task_command_translate(const char *command) {
    if (!strncmp(command, task_manager_commands_list[WM_TASK_UPGRADE], strlen(task_manager_commands_list[WM_TASK_UPGRADE]))) {
        return task_manager_commands_list[WM_TASK_UPGRADE];
    } else if (!strncmp(command, task_manager_commands_list[WM_TASK_SYSCOLLECTOR_SCAN], strlen(task_manager_commands_list[WM_TASK_SYSCOLLECTOR_SCAN]))) {
        return task_manager_commands_list[WM_TASK_SYSCOLLECTOR_SCAN];
    } else if (!strncmp(command, task_manager_commands_list[WM_TASK_VULN_DET_SCAN], strlen(task_manager_commands_list[WM_TASK_VULN_DET_SCAN]))) {
        return task_manager_commands_list[WM_TASK_VULN_DET_SCAN];
    } else if (!strncmp(command, task_manager_commands_list[WM_TASK_VULN_DET_FEEDS_UPDATE], strlen(task_manager_commands_list[WM_TASK_VULN_DET_FEEDS_UPDATE]))) {
        return task_manager_commands_list[WM_TASK_VULN_DET_FEEDS_UPDATE];
    } else {
        return NULL;
    }
}
