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

#ifndef CLIENT

#ifndef WM_TASK_MANAGER_H
#define WM_TASK_MANAGER_H

#include "../wm_task_general.h"

#define WM_TASK_MANAGER_LOGTAG ARGV0 ":" TASK_MANAGER_WM_NAME

#define WM_TASK_MAX_IN_PROGRESS_TIME 900 // 15 minutes
#define WM_TASK_CLEANUP_DB_SLEEP_TIME 86400 // A day
#define WM_TASK_DEFAULT_CLEANUP_TIME 604800 // A week

typedef struct _wm_task_manager {
    int enabled:1;
    int cleanup_time;
    int task_timeout;
} wm_task_manager;

typedef enum _error_code {
    WM_TASK_SUCCESS = 0,
    WM_TASK_INVALID_MESSAGE,
    WM_TASK_INVALID_COMMAND,
    WM_TASK_DATABASE_NO_TASK,
    WM_TASK_DATABASE_ERROR,
    WM_TASK_DATABASE_PARSE_ERROR,
    WM_TASK_DATABASE_REQUEST_ERROR,
    WM_TASK_UNKNOWN_ERROR
} error_code;

/**
 * Definition of upgrade parameters
 */
typedef struct _wm_task_manager_upgrade {
    char *node;
    char *module;
    int *agent_ids;
} wm_task_manager_upgrade;

/**
 * Definition of upgrade get status parameters
 */
typedef struct _wm_task_manager_upgrade_get_status {
    char *node;
    int *agent_ids;
} wm_task_manager_upgrade_get_status;

/**
 * Definition of upgrade update status parameters
 */
typedef struct _wm_task_manager_upgrade_update_status {
    char *node;
    int *agent_ids;
    char *status;
    char *error_msg;
} wm_task_manager_upgrade_update_status;

/**
 * Definition of upgrade result parameters
 */
typedef struct _wm_task_manager_upgrade_result {
    int *agent_ids;
} wm_task_manager_upgrade_result;

/**
 * Definition of upgrade cancel tasks parameters
 */
typedef struct _wm_task_manager_upgrade_cancel_tasks {
    char *node;
} wm_task_manager_upgrade_cancel_tasks;

/**
 * Definition of task structure
 */
typedef struct _wm_task_manager_task {
    command_list command;
    void *parameters;
} wm_task_manager_task;

extern const wm_context WM_TASK_MANAGER_CONTEXT;   // Context

// Parse XML configuration
int wm_task_manager_read(const OS_XML *xml, xml_node **nodes, wmodule *module);

/**
 * Do all the analysis of the incomming message and returns a response.
 * @param msg Incomming message from a connection.
 * @param response Response to be sent to the connection.
 * @return Size of the response string.
 * */
size_t wm_task_manager_dispatch(const char *msg, char **response) __attribute__((nonnull));

/**
 * Process a task and call appropiate command function.
 * @param task Task to be processed.
 * @param error_code Variable to store an error code if something is wrong.
 * @return JSON object with the response for this task.
 * */
cJSON* wm_task_manager_process_task(const wm_task_manager_task *task, int *error_code) __attribute__((nonnull));

/**
 * Set tasks status to TIMEOUT after they are IN PROGRESS for a long period of time.
 * Delete entries older than a configurable period of time from the tasks DB.
 * @param arg Module configuration.
 * */
void* wm_task_manager_clean_tasks(void *arg) __attribute__((nonnull));

#endif
#endif
