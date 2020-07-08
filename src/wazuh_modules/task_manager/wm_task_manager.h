/*
 * Wazuh Module for Security Configuration Assessment
 * Copyright (C) 2015-2020, Wazuh Inc.
 * November 25, 2018.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef CLIENT

#ifndef WM_TASK_MANAGER_H
#define WM_TASK_MANAGER_H

#include "../wmodules.h"

#define WM_TASK_MANAGER_LOGTAG TASK_MANAGER_WM_NAME

typedef struct _wm_task_manager {
    int enabled;
} wm_task_manager;

extern const wm_context WM_TASK_MANAGER_CONTEXT;   // Context

// Parse XML configuration
int wm_task_manager_read(xml_node **nodes, wmodule *module);

#endif
#endif
