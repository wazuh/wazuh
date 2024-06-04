/* Copyright (C) 2015, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef LOGMSG_H
#define LOGMSG_H

#include "shared.h"

#define smerror(list, msg, ...) _os_analysisd_add_logmsg(list, LOGLEVEL_ERROR, __LINE__, __func__, __FILE__, msg, ##__VA_ARGS__)
#define smwarn(list, msg, ...) _os_analysisd_add_logmsg(list, LOGLEVEL_WARNING, __LINE__, __func__, __FILE__, msg, ##__VA_ARGS__)
#define sminfo(list, msg, ...) _os_analysisd_add_logmsg(list, LOGLEVEL_INFO, __LINE__, __func__, __FILE__, msg, ##__VA_ARGS__)

#define ERRORLIST_MAXSIZE   50 ///< Max size of log messages list

/**
 * @brief Structure to save information of log messages
 */
typedef struct os_analysisd_log_msg_t {
    int level;   ///< Log level of message.
    int line;    ///< Line number from where the function was called. the __LINE__ macro should be used.
    char * func; ///< Function name from where the function was called. the __func__ macro should be used.
    char * file; ///< File name from where the function was called. the __FILE__ macro should be used.
    char * msg;  ///< Generic message.
} os_analysisd_log_msg_t;

/**
 * @brief Add a new message to list of \ref OSList*.
 * @param list list to add.
 * @param level  Log level of message.
 * @param line   line number from where the function was called. the __LINE__ macro should be used.
 * @param func   function name from where the function was called. the __func__ macro should be used.
 * @param file   file name from where the function was called. the __FILE__ macro should be used.
 * @param msg    format includes format specifiers (subsequences beginning with %) for sprintf.
 * @param ...    additional arguments following format are formatted and inserted in the
 *                   resulting string replacing their respective specifiers.
 */
void _os_analysisd_add_logmsg(OSList * list, int level, int line, const char * func,
                                const char * file, char * msg, ...) __attribute__ ((format (_PRINTF_FORMAT, 6, 7)))
                                                                    __attribute__((nonnull (4, 5, 6)));

/**
 * @brief Create string message with the information from \ref os_analysisd_log_msg_t.
 * @param log_msg Message information.
 * @return char* string message, NULL if log_msg is NULL
 */
char * os_analysisd_string_log_msg(os_analysisd_log_msg_t * log_msg);

/**
 * @brief Free \ref os_analysisd_log_msg_t
 * @param log_msg elements to free.
 */
void os_analysisd_free_log_msg(os_analysisd_log_msg_t * log_msg);

#endif
