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

#include "logging_helper.h"
#include "debug_op.h"

void taggedLogFunction(modules_log_level_t level, const char* log, const char* tag) {

    switch(level) {
        case LOG_ERROR:
            mterror(tag, "%s", log);
            break;
        case LOG_INFO:
            mtinfo(tag, "%s", log);
            break;
        case LOG_DEBUG:
            mtdebug1(tag, "%s", log);
            break;
        case LOG_DEBUG_VERBOSE:
            mtdebug2(tag, "%s", log);
            break;
        default:;
    }
}

void loggingFunction(modules_log_level_t level, const char* log) {

    switch(level) {
        case LOG_ERROR:
            merror("%s", log);
            break;
        case LOG_INFO:
            minfo("%s", log);
            break;
        case LOG_DEBUG:
            mdebug1("%s", log);
            break;
        case LOG_DEBUG_VERBOSE:
            mdebug2("%s", log);
            break;
        default:;
    }
}
