/*
 * Copyright (C) 2015-2019, Wazuh Inc.
 * May 27, 2019.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _WMODULESCONFIG_H
#define _WMODULESCONFIG_H

// Wazuh modules configuration structure

typedef struct _wmodules_config {
    int task_nice;
    int max_eps;
    int kill_timeout;
    int log_level;
    int thread_stack_size;
} wmodules_config;

#endif