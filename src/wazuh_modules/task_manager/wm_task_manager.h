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

typedef struct _wm_task_manager {
    int enabled:1;
} wm_task_manager;

typedef enum _json_key {
    MODULE = 0,
    COMMAND,
    AGENT_ID,
    TASK_ID,
    ERROR,
    ERROR_DATA
} json_key;

typedef enum _module_list {
    UPGRADE_MODULE = 0
} module_list;

typedef enum _command_list {
    UPGRADE = 0
} command_list;

typedef enum _error_code {
    SUCCESS = 0,
    INVALID_MESSAGE,
    DATABASE_ERROR,
    UNKNOWN_ERROR
} error_code;

extern const wm_context WM_TASK_MANAGER_CONTEXT;   // Context

// Parse XML configuration
int wm_task_manager_read(xml_node **nodes, wmodule *module);

// Function headers
size_t wm_task_manager_dispatch(const char *msg, char **response);
cJSON* wm_task_manager_parse_message(const char *msg);
cJSON* wm_task_manager_build_response_insert(int agent_id, int task_id);
char* wm_task_manager_build_response_error(int error_code);

// Database function headers
int wm_task_manager_check_db();
int wm_task_manager_insert_task(int agent_id, const char *module, const char *command);

#endif
#endif
