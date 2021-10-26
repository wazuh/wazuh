/*
 * Wazuh shared modules utils
 * Copyright (C) 2015-2021, Wazuh Inc.
 * Oct 6, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */


#ifndef _LOGGINGHELPER_H
#define _LOGGINGHELPER_H

typedef enum modules_log_level_t {
    LOG_ERROR,
    LOG_INFO,
    LOG_DEBUG,
    LOG_DEBUG_VERBOSE
} modules_log_level_t;

void taggedLogFunction(modules_log_level_t level, const char* log, const char* tag);
void loggingFunction(modules_log_level_t level, const char* log);


#endif //_LOGGINGHELPER_H
