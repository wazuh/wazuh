/* Copyright (C) 2015-2020, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef LIST_LOG_H
#define LIST_LOG_H

#include "shared.h"

#define log_emsg(list, msg, ...) _os_analysisd_add_list_log(list, LOGLEVEL_ERROR, __LINE__, __func__, __FILE__, msg, ##__VA_ARGS__)
#define log_wmsg(list, msg, ...) _os_analysisd_add_list_log(list, LOGLEVEL_WARNING, __LINE__, __func__, __FILE__, msg, ##__VA_ARGS__) 

/**
 * @brief  Structure to save information of log messages
 */
typedef struct os_analysisd_log_msg_t {
    int level;    ///< Log level of message.
    int line;     ///< Line number from where the function was called. the __LINE__ macro should be used.
    char* func;   ///< Function name from where the function was called. the __func__ macro should be used.
    char* file;   ///< File name from where the function was called. the __FILE__ macro should be used.
    char* msg;    ///< Error/Warning message.
    struct os_analysisd_log_msg_t* next;
} os_analysisd_log_msg_t;

/**
 * @brief List of log mesagges
 */
typedef struct os_analysisd_list_log_msg_t {
    os_analysisd_log_msg_t* head; ///< Top  of list
} os_analysisd_list_log_msg_t;

/**
 * @brief Create and initialize list of \ref os_analysisd_list_log_msg_t
 * @return os_analysisd_list_log_msg_t* 
 */
os_analysisd_list_log_msg_t*  os_analysisd_create_list_log();

/**
 * @brief Add a new message to list of \ref os_analysisd_list_log_msg_t.
 * @param[in] list list to add.
 * @param[in] level  Log level of message.
 * @param[in] line   line number from where the function was called. the __LINE__ macro should be used.
 * @param[in] func   function name from where the function was called. the __func__ macro should be used.
 * @param[in] file   file name from where the function was called. the __FILE__ macro should be used.
 * @param[in] msg    format includes format specifiers (subsequences beginning with %) for sprintf.
 * @param[in] ...    additional arguments following format are formatted and inserted in the
 *                   resulting string replacing their respective specifiers.
 */
void _os_analysisd_add_list_log(os_analysisd_list_log_msg_t* list, int level,
                                int line, const char* func, const char* file, char* msg, ...) __attribute__((nonnull));

/**
 * @brief Remove the first element from the list and return it.
 * @param[in] list list to remove item.
 * @return os_analysisd_log_msg_t* First element of the list, NULL if the list is empty.
 * @note The next element of the node is set to null before returning it.
 */
os_analysisd_log_msg_t* os_analysisd_pop_list_log(os_analysisd_list_log_msg_t* list) __attribute__((nonnull));

/**
 * @brief Create string message with the information from \ref os_analysisd_log_msg_t node.
 * @param log_msg[in] Node with message information.
 * @return char* string message, NULL if log_msg is NULL
 */
char* os_analysisd_string_log_msg(os_analysisd_log_msg_t* log_msg);

/**
 * @brief Free the elements of the \ref os_analysisd_log_msg_t
 * @param log_msg 
 */
void os_analysisd_free_log_msg(os_analysisd_log_msg_t* log_msg);


#endif
