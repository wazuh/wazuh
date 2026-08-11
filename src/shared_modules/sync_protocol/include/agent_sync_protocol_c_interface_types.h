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
#include <stdbool.h>

#define SYNC_FAILURE_REASON_MAX_LEN 2048

/// @brief Consecutive failed synchronizations tolerated before a module escalates a
/// manager-not-ready failure from INFO to WARNING.
///
/// The first failures are expected while the manager is still not ready for this agent (mostly right
/// after an agent restart) and clear on the next cycle. Beyond this many in a row the condition is not
/// clearing on its own (for example the manager has no indexer available), so it must stay visible.
#define SYNC_MANAGER_NOT_READY_TOLERANCE 3U

#include "logging_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

/// @brief Result of a module synchronization operation.
///
/// Returned by sync entry points to report both outcome and failure detail.
/// @var success        true if synchronization completed successfully; false otherwise.
/// @var failure_reason Human-readable reason string when available; may be empty if no specific reason was recorded.
/// @var stopped        true if the operation was aborted because a stop/shutdown was requested; lets the
///                     caller demote an expected shutdown-time failure from WARNING to INFO/DEBUG.
/// @var manager_not_ready true if the manager did not answer the handshake, or answered that it cannot
///                     serve this agent yet (Offline). Describes what happened, not whether it is
///                     harmless: use it together with consecutive_failures to decide the log level.
/// @var consecutive_failures number of consecutive failed synchronizations for this module, including
///                     this one; reset to zero on the first success.
typedef struct SyncModuleResult_t
{
    bool success;
    char failure_reason[SYNC_FAILURE_REASON_MAX_LEN];
    bool stopped;
    bool manager_not_ready;
    unsigned int consecutive_failures;
    /// @brief True when the sync was aborted because a prerequisite the manager has to supply
    /// first (assigned groups, or a VD feed offset) has not arrived yet. See
    /// SyncModuleResult::awaitingPrerequisite (agent_sync_protocol_types.hpp) for the full doc.
    bool awaiting_prerequisite;
} SyncModuleResult_t;

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
    MODE_DELTA = 0,         ///< Delta synchronization
    MODE_CHECK = 1,         ///< Integrity check mode
    MODE_METADATA_DELTA = 2, ///< Metadata delta synchronization
    MODE_METADATA_CHECK = 3, ///< Metadata integrity check
    MODE_GROUP_DELTA = 4,    ///< Group delta synchronization
    MODE_GROUP_CHECK = 5     ///< Group integrity check
} Mode_t;

/// @brief Defines additional synchronization options.
typedef enum
{
    OPTION_SYNC    = 0,     ///< Standard synchronization option.
    OPTION_VD_FIRST = 1,    ///< Vulnerability detection first synchronization option.
    OPTION_VD_SYNC  = 2,    ///< Vulnerability detection synchronization option.
    OPTION_VD_CLEAN = 3     ///< Vulnerability detection cleanup synchronization option.
} Option_t;

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

/// @brief Function pointer type for delivering one whole sync session in-process instead of
/// over a local socket (Windows only -- POSIX's SyncSocketTransport uses its own AF_UNIX socket
/// and never calls this). The id already carries the "<module>-<session>" prefix
/// (SyncSocketTransport::frameSessionId()); the receiving side is expected to be https_client's
/// own hc_submit_sync_session().
/// @param session_id Null-terminated frame id.
/// @param buffer Serialized FullSession message bytes.
/// @param length Length of buffer in bytes.
/// @return true once the receiving client queued the session; false if it is not running, or
///         its queue is full.
typedef bool (*asp_sync_session_sender_fn)(const char* session_id, const uint8_t* buffer, size_t length);

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
