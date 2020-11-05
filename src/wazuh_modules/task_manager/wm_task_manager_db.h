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

#ifndef CLIENT

#ifndef WM_TASK_MANAGER_DB
#define WM_TASK_MANAGER_DB

#define TASKS_PATH              "queue/tasks/"
#define TASKS_DB TASKS_PATH     "tasks.db"

#define TASKS_TABLE             "TASKS"
#define MAX_SQL_ATTEMPTS        1000

typedef enum _task_query {
    WM_TASK_INSERT_TASK,
    WM_TASK_GET_LAST_AGENT_TASK,
    WM_TASK_GET_LAST_AGENT_UPGRADE_TASK,
    WM_TASK_UPDATE_TASK_STATUS,
    WM_TASK_GET_TASK_BY_TASK_ID,
    WM_TASK_GET_TASK_BY_STATUS,
    WM_TASK_DELETE_OLD_TASKS,
    WM_TASK_DELETE_TASK,
    WM_TASK_CANCEL_PENDING_UPGRADE_TASKS
} task_query;

extern char *schema_task_manager_sql;

/**
 * Create the tasks DB or check that it already exists.
 * @return 0 when succeed, -1 otherwise.
 * */
int wm_task_manager_check_db();

/**
 * Set tasks status to TIMEOUT after they are IN PROGRESS for a long period of time.
 * Delete entries older than a configurable period of time from the tasks DB.
 * @param arg Module configuration.
 * */
void* wm_task_manager_clean_db(void *arg) __attribute__((nonnull));

/**
 * Insert a new task in the tasks DB.
 * @param agent_id ID of the agent where the task will be executed.
 * @param node Node that executed the command.
 * @param module Name of the module where the message comes from.
 * @param command Command to be executed in the agent.
 * @return ID of the task recently created when succeed, <=0 otherwise.
 * */
int wm_task_manager_insert_task(int agent_id, const char *node, const char *module, const char *command) __attribute__((nonnull));

/**
 * Get the status of an upgrade task from the tasks DB.
 * @param agent_id ID of the agent where the task is being executed.
 * @param node Node that executed the command.
 * @param status String where the status of the task will be stored.
 * @return 0 when succeed, !=0 otherwise.
 * */
int wm_task_manager_get_upgrade_task_status(int agent_id, const char *node, char **status) __attribute__((nonnull));

/**
 * Update the status of a upgrade task in the tasks DB.
 * @param agent_id ID of the agent where the task is being executed.
 * @param node Node that executed the command.
 * @param status New status of the task.
 * @param error Error string of the task in case of failure.
 * @return 0 when succeed, !=0 otherwise.
 * */
int wm_task_manager_update_upgrade_task_status(int agent_id, const char *node, const char *status, const char *error);

/**
 * Cancel the upgrade tasks of a given node in the tasks DB.
 * @param node Node that executed the upgrades.
 * @return 0 when succeed, !=0 otherwise.
 * */
int wm_task_manager_cancel_upgrade_tasks(const char *node) __attribute__((nonnull));

/**
 * Get task by agent_id and module from the tasks DB.
 * @param agent_id ID of the agent where the task is being executed.
 * @param node Node that executed the command.
 * @param module Name of the module where the command comes from.
 * @param command String where the command of the task will be stored.
 * @param status String where the status of the task will be stored.
 * @param error String where the error message of the task will be stored.
 * @param create_time Integer where the create_time of the task will be stored.
 * @param last_update_time Integer where the last_update_time of the task will be stored.
 * @return task_id when succeed, < 0 otherwise.
 * */
int wm_task_manager_get_upgrade_task_by_agent_id(int agent_id, char **node, char **module, char **command, char **status, char **error, int *create_time, int *last_update_time) __attribute__((nonnull));

/**
 * Get task by task_id from the tasks DB.
 * @param task_id ID of the task_id where the task is being executed.
 * @param node Node that executed the command.
 * @param module Name of the module where the command comes from.
 * @param command String where the command of the task will be stored.
 * @param status String where the status of the task will be stored.
 * @param error String where the error message of the task will be stored.
 * @param create_time Integer where the create_time of the task will be stored.
 * @param last_update_time Integer where the last_update_time of the task will be stored.
 * @return result
 * @retval OS_INVALID on errors
 * @retval agent_id if the task was found
 * @retval OS_NOTFOUND if the task was not found
 * */
int wm_task_manager_get_task_by_task_id(int task_id, char **node, char **module, char **command, char **status, char **error, int *create_time, int *last_update_time) __attribute__((nonnull));

#endif
#endif
