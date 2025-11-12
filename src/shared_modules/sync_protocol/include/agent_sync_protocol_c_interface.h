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
/// @param syncEndDelay Delay for synchronization end message in seconds
/// @param timeout Default timeout for synchronization operations in seconds.
/// @param retries Default number of retries for synchronization operations.
/// @param maxEps Default maximum events per second for synchronization operations.
/// @return A pointer to an opaque AgentSyncProtocol handle, or NULL on failure.
AgentSyncProtocolHandle* asp_create(const char* module, const char* db_path, const MQ_Functions* mq_funcs, asp_logger_t logger, unsigned int syncEndDelay, unsigned int timeout, unsigned int retries, size_t maxEps);

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
/// @param version Version of the data (64-bit unsigned integer).
void asp_persist_diff(AgentSyncProtocolHandle* handle,
                      const char* id,
                      Operation_t operation,
                      const char* index,
                      const char* data,
                      uint64_t version);

/// @brief Persists a difference to in-memory vector instead of database.
///
/// This method is used for recovery scenarios where data should be kept in memory.
/// @param handle Pointer to the AgentSyncProtocol handle.
/// @param id Unique identifier for the data item.
/// @param operation Type of operation (create, modify, delete).
/// @param index Logical index for the data item.
/// @param data Serialized content of the message.
/// @param version Version of the data (64-bit unsigned integer).
void asp_persist_diff_in_memory(AgentSyncProtocolHandle* handle,
                                const char* id,
                                Operation_t operation,
                                const char* index,
                                const char* data,
                                uint64_t version);

// @brief Triggers synchronization of a module.
///
/// @param handle Pointer to the AgentSyncProtocol handle.
/// @param mode Synchronization mode (e.g., full, delta).
/// @return true if the sync was successfully processed; false otherwise.
bool asp_sync_module(AgentSyncProtocolHandle* handle,
                     Mode_t mode);

/// @brief Checks if a module index requires full synchronization.
///
/// @param handle Pointer to the AgentSyncProtocol handle.
/// @param index The index/table to check.
/// @param checksum The calculated checksum for the index.
/// @return true if full sync is required (checksum mismatch); false if integrity is valid.
bool asp_requires_full_sync(AgentSyncProtocolHandle* handle,
                            const char* index,
                            const char* checksum);

/// @brief Parses a response buffer encoded in FlatBuffer format.
/// @param handle Protocol handle.
/// @param data Pointer to the FlatBuffer-encoded message.
/// @param length Size of the FlatBuffer message in bytes.
/// @return true if parsed successfully, false on error.
bool asp_parse_response_buffer(AgentSyncProtocolHandle* handle, const uint8_t* data, size_t length);

/// @brief Clears the in-memory data queue.
/// @param handle Protocol handle.
void asp_clear_in_memory_data(AgentSyncProtocolHandle* handle);

/// @brief Synchronizes metadata or groups with the server without sending data.
///
/// This function handles the following modes: MetadataDelta, MetadataCheck, GroupDelta, GroupCheck.
/// The sequence is: Start → StartAck → End → EndAck (no Data messages).
/// @param handle Pointer to the AgentSyncProtocol handle.
/// @param mode Synchronization mode (must be MODE_METADATA_DELTA, MODE_METADATA_CHECK, MODE_GROUP_DELTA, or MODE_GROUP_CHECK)
/// @param indices Array of index name strings that will be updated by the manager.
/// @param indices_count Number of indices in the array.
/// @param global_version Global version to include in the Start message
/// @return true if synchronization completed successfully, false otherwise
bool asp_sync_metadata_or_groups(AgentSyncProtocolHandle* handle,
                                 Mode_t mode,
                                 const char** indices,
                                 size_t indices_count,
                                 uint64_t global_version);

/// @brief Notifies the manager about data cleaning for specified indices.
///
/// This function sends DataClean messages for each index in the provided array.
/// The sequence is: Start → StartAck → DataClean (for each index) → End → EndAck.
/// Upon receiving Ok/PartialOk, it clears the local database and returns true.
/// @param handle Pointer to the AgentSyncProtocol handle.
/// @param indices Array of index name strings to clean.
/// @param indices_count Number of indices in the array.
/// @return true if notification completed successfully and database was cleared, false otherwise
bool asp_notify_data_clean(AgentSyncProtocolHandle* handle,
                           const char** indices,
                           size_t indices_count);

/// @brief Deletes the database file.
///
/// This function closes the database connection and removes the database file from disk.
/// @param handle Pointer to the AgentSyncProtocol handle.
void asp_delete_database(AgentSyncProtocolHandle* handle);

/// @brief Signals the sync protocol to stop all operations.
///
/// This function should be called when a module is shutting down to abort any ongoing
/// or pending synchronization operations.
/// @param handle Pointer to the AgentSyncProtocol handle.
void asp_stop(AgentSyncProtocolHandle* handle);

/// @brief Resets the stop flag to allow restarting operations.
///
/// This function should be called when a module is restarted after being stopped.
/// It clears the stop flag, allowing synchronization operations to proceed again.
/// @param handle Pointer to the AgentSyncProtocol handle.
void asp_reset(AgentSyncProtocolHandle* handle);

/// @brief Checks if stop has been requested.
/// @param handle Pointer to the AgentSyncProtocol handle.
/// @return true if stop was requested, false otherwise.
bool asp_should_stop(const AgentSyncProtocolHandle* handle);

#ifdef __cplusplus
}
#endif
