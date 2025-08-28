/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "agent_sync_protocol_c_interface_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/// @brief Creates an instance of AgentSyncProtocol.
///
/// @param module Name of the module associated with this instance.
/// @param db_path The full path to the SQLite database file to be used.
/// @param mq_funcs Pointer to a MQ_Functions struct containing the MQ callbacks.
/// @param logger Callback function used for logging messages.
/// @return A pointer to an opaque AgentSyncProtocol handle, or NULL on failure.
AgentSyncProtocolHandle* asp_create(const char* module, const char* db_path, const MQ_Functions* mq_funcs, asp_logger_t logger);

/// @brief Destroys an AgentSyncProtocol instance.
///
/// @param handle Pointer to the AgentSyncProtocol handle to destroy.
void asp_destroy(AgentSyncProtocolHandle* handle);

/// @brief Persists a difference (diff) for synchronization.
///
/// @param handle Pointer to the AgentSyncProtocol handle.
/// @param id Unique identifier for the diff (usually a hash).
/// @param operation Type of operation (create, modify, delete).
/// @param index Target index or destination for the diff.
/// @param data JSON string representing the data to persist.
void asp_persist_diff(AgentSyncProtocolHandle* handle,
                      const char* id,
                      Operation_t operation,
                      const char* index,
                      const char* data);

// @brief Triggers synchronization of a module.
///
/// @param handle Pointer to the AgentSyncProtocol handle.
/// @param mode Synchronization mode (e.g., full, delta).
/// @param sync_timeout The timeout for each attempt to receive a response, in seconds.
/// @param sync_retries The maximum number of attempts for re-sending Start and End messages.
/// @param max_eps The maximum event reporting throughput. 0 means disabled.
/// @return true if the sync was successfully processed; false otherwise.
bool asp_sync_module(AgentSyncProtocolHandle* handle,
                     Mode_t mode,
                     unsigned int sync_timeout,
                     unsigned int sync_retries,
                     size_t max_eps);

/// @brief Parses a response buffer encoded in FlatBuffer format.
/// @param handle Protocol handle.
/// @param data Pointer to the FlatBuffer-encoded message.
/// @param length Size of the FlatBuffer message in bytes.
/// @return true if parsed successfully, false on error.
bool asp_parse_response_buffer(AgentSyncProtocolHandle* handle, const uint8_t* data, size_t length);

#ifdef __cplusplus
}
#endif
