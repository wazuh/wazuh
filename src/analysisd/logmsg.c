/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "logmsg.h"

void _os_analysisd_add_logmsg(OSList * list, int level, int line, const char * func,
                                const char * file, char * msg, ...) {

    va_list args;
    os_analysisd_log_msg_t * new_msg;

    if (list == NULL) {
        va_start(args, msg);
        switch (level) {

        case LOGLEVEL_ERROR:
            _mverror(file, line, func, msg, args);
            break;

        case LOGLEVEL_WARNING:
            _mvwarn(file, line, func, msg, args);
            break;

        default:
            _mvinfo(file, line, func, msg, args);
            break;
        }
        va_end(args);
        return;
    }

    os_malloc(sizeof(os_analysisd_log_msg_t), new_msg);

    /* Debug information */
    new_msg->line = line;
    os_strdup(func, new_msg->func);
    os_strdup(file, new_msg->file);

    /* Generic message */
    new_msg->level = level;
    os_calloc(1, OS_BUFFER_SIZE, new_msg->msg);
    va_start(args, msg);
    (void)vsnprintf(new_msg->msg, OS_BUFFER_SIZE, msg, args);
    va_end(args);
    os_realloc(new_msg->msg, strlen(new_msg->msg) + 1, new_msg->msg);

    OSList_AddData(list, new_msg);
    return;
}

char * os_analysisd_string_log_msg(os_analysisd_log_msg_t * log_msg) {
    char * str;

    if (log_msg == NULL) {
        return NULL;
    }

    if (isDebug()) {
        os_malloc(OS_BUFFER_SIZE, str);
        (void)snprintf(str, OS_BUFFER_SIZE, "%s:%d at %s(): %s", log_msg->file, log_msg->line, log_msg->func,
                       log_msg->msg);
        os_realloc(str, strlen(str) + 1, str);
    } else {
        os_strdup(log_msg->msg, str);
    }

    return str;
}

void os_analysisd_free_log_msg(os_analysisd_log_msg_t * log_msg) {

    if (!log_msg) {
        return;
    }

    os_free(log_msg->file);
    os_free(log_msg->func);
    os_free(log_msg->msg);
    os_free(log_msg);
}
