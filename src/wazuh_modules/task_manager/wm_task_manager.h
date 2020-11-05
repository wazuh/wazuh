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

#ifndef WM_TASK_MANAGER_H
#define WM_TASK_MANAGER_H

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
    WM_TASK_INVALID_NODE,
    WM_TASK_INVALID_MODULE,
    WM_TASK_INVALID_COMMAND,
    WM_TASK_INVALID_AGENT_ID,
    WM_TASK_INVALID_TASK_ID,
    WM_TASK_INVALID_STATUS,
    WM_TASK_DATABASE_NO_TASK,
    WM_TASK_DATABASE_ERROR,
    WM_TASK_UNKNOWN_ERROR
} error_code;

extern const wm_context WM_TASK_MANAGER_CONTEXT;   // Context

// Parse XML configuration
int wm_task_manager_read(xml_node **nodes, wmodule *module);

/**
 * Do all the analysis of the incomming message and returns a response.
 * @param msg Incomming message from a connection.
 * @param response Response to be sent to the connection.
 * @return Size of the response string.
 * */
size_t wm_task_manager_dispatch(const char *msg, char **response) __attribute__((nonnull));

/**
 * Analyze a task by module and call appropiate analyze function.
 * @param task_object JSON object with a task to be analyzed.
 * @param error_code Variable to store an error code if something is wrong.
 * @return JSON object with the response for this task.
 * */
cJSON* wm_task_manager_analyze_task(const cJSON *task_object, int *error_code) __attribute__((nonnull));

#endif
#endif
