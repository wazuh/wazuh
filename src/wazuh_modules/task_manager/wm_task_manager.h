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

extern const wm_context WM_TASK_MANAGER_CONTEXT;   // Context

// Parse XML configuration
int wm_task_manager_read(xml_node **nodes, wmodule *module);

// Function headers
int wm_task_manager_check_db();
size_t wm_task_manager_dispatch(const char *msg, char **response);
cJSON* wm_task_manager_parse_message(const char *msg);
char* wm_task_manager_error_message(int error_code);

#endif
#endif
