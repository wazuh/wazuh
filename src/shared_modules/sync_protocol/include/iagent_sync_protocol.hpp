/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include "inventorySync_generated.h"
#include "ipersistent_queue.hpp"
#include "agent_sync_protocol_types.hpp"

#include <string>
#include <chrono>

class IAgentSyncProtocol
{
    public:
        /// @brief Persist a difference in the buffer
        /// @param id Difference id (hash ok PKs)
        /// @param operation Operation type
        /// @param index Index where to send the difference
        /// @param data Difference data
        /// @param version Version of the data.
        /// @param isDataContext Flag to mark data as DataContext (true) or DataValue (false).
        virtual void persistDifference(const std::string& id,
                                       Operation operation,
                                       const std::string& index,
                                       const std::string& data,
                                       uint64_t version,
                                       bool isDataContext = false) = 0;

        /// @brief Synchronize a module with the server
        /// @param mode Sync mode
        /// @param option Synchronization option.
        /// @return SyncModuleResult with success flag and an optional failure reason string.
        virtual SyncModuleResult synchronizeModule(Mode mode, Option option = Option::SYNC) = 0;

        /// @brief Checks if a module index requires full synchronization
        ///
        /// A 409 (checksum mismatch) is retried against the manager up to
        /// CHECKSUM_MISMATCH_MAX_ATTEMPTS times, spaced out, before being trusted as a
        /// genuine mismatch -- a recent bulk write may not be visible in the indexer yet.
        /// Any other failure (communication error, manager offline) returns false
        /// immediately without spending this retry budget.
        /// @param index The index/table to check
        /// @param checksum The calculated checksum for the index
        /// @return true if full sync is required (checksum mismatch); false if integrity is valid.
        virtual bool requiresFullSync(const std::string& index,
                                      const std::string& checksum) = 0;

        /// @brief Synchronizes metadata or groups with the server without sending data.
        ///
        /// This method handles the following modes: MetadataDelta, MetadataCheck, GroupDelta, GroupCheck.
        /// Sent as one FullSession carrying Start and End (no data items).
        /// @param mode Synchronization mode (must be MetadataDelta, MetadataCheck, GroupDelta, or GroupCheck)
        /// @param indices Vector of index names that will be updated by the manager
        /// @param globalVersion Global version to include in the Start message (optional, only for Delta modes)
        /// @return SyncModuleResult with success flag and failure reason if unsuccessful
        virtual SyncModuleResult synchronizeMetadataOrGroups(Mode mode, const std::vector<std::string>& indices, uint64_t globalVersion = 0) = 0;

        /// @brief Notifies the manager about data cleaning for specified indices.
        ///
        /// This method sends DataClean messages for each index in the provided vector.
        /// Sent as one FullSession carrying Start, a DataClean per index, and End.
        /// Upon receiving Ok, it clears the local database and returns true.
        /// @param indices Vector of index names to clean
        /// @param option Synchronization option.
        /// @return true if notification completed successfully and database was cleared, false otherwise
        virtual bool notifyDataClean(const std::vector<std::string>& indices, Option option = Option::SYNC) = 0;

        /// @brief Fetches pending DataValue items from the persistent queue without marking them.
        /// @param onlyDataValues If true, only returns items with is_data_context=false
        /// @return Vector of pending items
        virtual std::vector<PersistedData> fetchPendingItems(bool onlyDataValues = true) = 0;

        /// @brief Clears all DataContext items from the persistent queue.
        /// This should be called before adding new DataContext to prevent inconsistencies.
        virtual void clearAllDataContext() = 0;

        /// @brief Deletes the database file.
        /// This method closes the database connection and removes the database file from disk.
        virtual void deleteDatabase() = 0;

        /// @brief Signals the sync protocol to stop all operations.
        /// This method should be called when a module is shutting down to abort any ongoing or pending synchronization operations.
        virtual void stop() = 0;

        /// @brief Resets the stop flag to allow restarting operations.
        /// This method should be called when restarting the module after a stop to clear the stop flag.
        virtual void reset() = 0;

        /// @brief Checks if stop has been requested.
        /// @return true if stop was requested, false otherwise.
        virtual bool shouldStop() const = 0;

        /// @brief Destructor
        virtual ~IAgentSyncProtocol() = default;

        /// @brief Parses a FlatBuffer response message received from the manager.
        /// @param data Pointer to the FlatBuffer-encoded message buffer.
        /// @param length Size of the FlatBuffer message in bytes.
        /// @return true if the message was successfully parsed and processed; false otherwise.
        virtual bool parseResponseBuffer(const uint8_t* data, size_t length) = 0;
};
