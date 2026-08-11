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

/// @brief Sets the ceiling on how many bytes one sync session may carry.
///
/// The value belongs to <agent><batch><size>, which this library cannot read: it links
/// neither the configuration layer nor an XML parser. The daemon hosting the modules
/// reads it and calls this before any module builds its protocol instance. Zero leaves
/// the built-in default in place.
///
/// @param max_session_bytes Maximum bytes per session, or 0 to keep the default.
void asp_set_session_max_bytes(uint64_t max_session_bytes);

/// @brief Creates an instance of AgentSyncProtocol.
///
/// @param module Name of the module associated with this instance.
/// @param db_path Optional full path to the SQLite database file (nullptr for in-memory only).
/// @param logger Callback function used for logging messages.
/// @return A pointer to an opaque AgentSyncProtocol handle, or NULL on failure.
AgentSyncProtocolHandle* asp_create(const char* module, const char* db_path, asp_logger_t logger);

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

/// @brief Triggers synchronization of a module.
///
/// @param handle Pointer to the AgentSyncProtocol handle.
/// @param mode Synchronization mode (e.g., full, delta).
/// @return SyncModuleResult_t with success flag and an optional failure reason string.
SyncModuleResult_t asp_sync_module(AgentSyncProtocolHandle* handle,
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

/// @brief Synchronizes metadata or groups with the server without sending data.
///
/// This function handles the following modes: MetadataDelta, MetadataCheck, GroupDelta, GroupCheck.
/// Sent as one FullSession carrying Start and End (no data items).
/// @param handle Pointer to the AgentSyncProtocol handle.
/// @param mode Synchronization mode (must be MODE_METADATA_DELTA, MODE_METADATA_CHECK, MODE_GROUP_DELTA, or MODE_GROUP_CHECK)
/// @param indices Array of index name strings that will be updated by the manager.
/// @param indices_count Number of indices in the array.
/// @param global_version Global version to include in the Start message
/// @return SyncModuleResult_t with success flag and failure reason if unsuccessful
SyncModuleResult_t asp_sync_metadata_or_groups(AgentSyncProtocolHandle* handle,
                                               Mode_t mode,
                                               const char** indices,
                                               size_t indices_count,
                                               uint64_t global_version);

/// @brief Notifies the manager about data cleaning for specified indices.
///
/// This function sends DataClean messages for each index in the provided array.
/// Sent as one FullSession carrying Start, a DataClean per index, and End.
/// Upon receiving Ok, it clears the local database and returns true.
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

/// @brief Registers the in-process sender SyncSocketTransport's Windows stub uses to hand a
/// session directly to https_client, since Windows has no local socket intake for it (see
/// SyncSocketTransport's own class doc). Call with NULL to deregister (e.g. https_client is
/// stopping). Process-global: this library is one instance per process regardless of how many
/// modules (agent-info, SCA, syscollector, FIM) use it, and there is only ever one https_client
/// to reach.
///
/// @param sender Function to call for each session, or NULL to deregister.
void asp_set_session_sender(asp_sync_session_sender_fn sender);

#ifdef __cplusplus
}
#endif
