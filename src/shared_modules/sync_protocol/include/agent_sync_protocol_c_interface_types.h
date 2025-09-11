/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <stdint.h>
#include <stddef.h>

#include "logging_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

/// @brief Defines the type of modification operation.
typedef enum
{
    OPERATION_CREATE = 0,   ///< The operation is to create a new record.
    OPERATION_MODIFY = 1,   ///< The operation is to modify an existing record.
    OPERATION_DELETE = 2,   ///< The operation is to delete a record.
    OPERATION_NO_OP  = 3    ///< No specific operation is being synchronized. Represents a neutral state.
} Operation_t;

/// @brief Defines the type of mode synchronization.
typedef enum
{
    MODE_FULL  = 0,  ///< Full synchronization
    MODE_DELTA = 1   ///< Delta synchronization
} Mode_t;

/// @brief Opaque handle to the AgentSyncProtocol C++ object.
///
/// Used to interact with the AgentSyncProtocol instance from C code.
typedef struct AgentSyncProtocol AgentSyncProtocolHandle;

/// @brief Function pointer type for starting a message queue.
///
/// @param key The identifier key for the message queue.
/// @param type The type of queue or message.
/// @param attempts The number of connection attempts.
/// @return Integer status code (0 on success, non-zero on failure).
typedef int (*mq_start_fn)(const char* key, short type, short attempts);

/// @brief Function pointer type for sending a message to the queue.
///
/// @param queue The queue identifier.
/// @param message The message payload to send.
/// @param message_len The length of the message payload in bytes.
/// @param locmsg Additional location/context message (optional).
/// @param loc A character representing the message location or type.
/// @return Integer status code (0 on success, non-zero on failure).
typedef int (*mq_send_binary_fn)(int queue, const void* message, size_t message_len, const char* locmsg, char loc);


/// @brief Callback type for logging messages from the AgentSyncProtocol.
/// @param level Logging level of the message (e.g., LOG_ERROR, LOG_INFO, LOG_DEBUG).
/// @param log   Null-terminated string containing the log message.
typedef void (*asp_logger_t)(modules_log_level_t level, const char* log);

/// @brief Struct containing function pointers for MQ operations.
///
/// This structure provides the implementation of MQ start and send operations.
typedef struct MQ_Functions
{
    /// Callback to start a message queue.
    mq_start_fn start;

    /// Callback to send a message.
    mq_send_binary_fn send_binary;
} MQ_Functions;

#ifdef __cplusplus
}
#endif
