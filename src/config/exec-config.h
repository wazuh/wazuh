/*
 * Copyright (C) 2015-2019, Wazuh Inc.
 * May 27, 2019.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _EXECDCONFIG_H
#define _EXECDCONFIG_H

typedef struct _ExecConfig {
    int req_timeout;
    int max_restart_lock;
    int log_level;
    int thread_stack_size;
} ExecConfig;

#endif