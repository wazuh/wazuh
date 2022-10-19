/**
 * @file log_builder.h
 * @brief Declaration of the shared log builder library
 * @date 2019-12-06
 *
 * @copyright Copyright (C) 2015 Wazuh, Inc.
 */

/*
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef LOG_BUILDER_H
#define LOG_BUILDER_H

#define LOG_BUILDER_HOSTNAME_LEN 512

/**
 * @brief Log builder type
 *
 * This structure holds the pattern values that change rarely.
 *
 */
typedef struct {
    char host_name[LOG_BUILDER_HOSTNAME_LEN];   ///< Host name
    char host_ip[IPSIZE];                       ///< Host's primary IP
    rwlock_t rwlock;                            ///< Read-write lock
} log_builder_t;

/**
 * @brief Initialize a log builder structure
 *
 * @param update Selects if the initializer should populate the data.
 * @return Pointer to an initialized log builder structure.
 */
log_builder_t * log_builder_init(bool update);

/**
 * @brief Free a log builder structure.
 *
 * @param builder Pointer to a log builder structure.
 */
void log_builder_destroy(log_builder_t * builder);

/**
 * @brief Update the pattern values
 *
 * @param builder Pointer to a log builder structure.
 * @retval 0 All the values were updated successfully.
 * @retval -1 Any of the values failed to update.
 */
int log_builder_update(log_builder_t * builder);

/**
 * @brief Build a log string
 *
 * Supported patterns:
 * - $(log) or $(output): Message from the log.
 * - $(json_escaped_log): Message from the log, with JSON string escapes applied.
 * - $(location) or $(command): Source of the message.
 * - $(timestamp): Current timestamp in RFC3164 format.
 * - $(timestamp <format>): Current timestamp, in strftime string format.
 * - $(hostname): System's host name.
 * - $(host_ip): Host's primary IP.
 *
 * @param builder Pointer to a log builder structure.
 * @param pattern String holding the log format.
 * @param logmsg String containing the input log.
 * @param location String representing the log location.
 * @return Pointer to a new string holding the output log. It will never be NULL.
 */
char * log_builder_build(log_builder_t * builder, const char * pattern, const char * logmsg, const char * location);

#endif // LOG_BUILDER_H
