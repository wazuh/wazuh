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

typedef enum modules_log_level_t
{
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARNING,
    LOG_ERROR,
    LOG_ERROR_EXIT,
    LOG_DEBUG_VERBOSE
} modules_log_level_t;

/**
 * @brief Global function to send a log message
 *
 * @param level Represent the log mode: ERROR, ERROR_EXIT, INFO, WARNING, DEBUG and DEBUG_VERBOSE
 * @param log Message to send into the log
 * @param tag Tag representing the module sending the log
 */
void taggedLogFunction(modules_log_level_t level, const char* log, const char* tag);

/**
 * @brief Global function to send a log message
 *
 * @param level Represent the log mode: ERROR, ERROR_EXIT, INFO, WARNING, DEBUG and DEBUG_VERBOSE
 * @param log Message to send into the log
 */
void loggingFunction(modules_log_level_t level, const char* log);

/**
 * @brief Global function to send a error log message
 *
 * @param log Message to send into the log as error
 */
void loggingErrorFunction(const char* log);

#endif //_LOGGINGHELPER_H
