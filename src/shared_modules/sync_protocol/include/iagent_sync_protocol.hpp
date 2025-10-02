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
        virtual void persistDifference(const std::string& id,
                                       Operation operation,
                                       const std::string& index,
                                       const std::string& data) = 0;

        /// @brief Persist a difference to in-memory vector instead of database.
        /// This method is used for recovery scenarios where data should be kept in memory.
        /// @param id Unique identifier for the data item.
        /// @param operation Type of operation (CREATE, MODIFY, DELETE).
        /// @param index Logical index for the data item.
        /// @param data Serialized content of the message.
        virtual void persistDifferenceInMemory(const std::string& id,
                                               Operation operation,
                                               const std::string& index,
                                               const std::string& data) = 0;

        /// @brief Synchronize a module with the server
        /// @param mode Sync mode
        /// @param timeout The timeout for each response wait.
        /// @param retries The maximum number of re-send attempts.
        /// @param maxEps The maximum event reporting throughput. 0 means disabled.
        /// @return true if the sync was successfully processed; false otherwise.
        virtual bool synchronizeModule(Mode mode, std::chrono::seconds timeout, unsigned int retries, size_t maxEps) = 0;

        /// @brief Checks if a module index requires full synchronization
        /// @param index The index/table to check
        /// @param checksum The calculated checksum for the index
        /// @param timeout The timeout for each response wait.
        /// @param retries The maximum number of re-send attempts.
        /// @param maxEps The maximum event reporting throughput. 0 means disabled.
        /// @return true if full sync is required (checksum mismatch); false if integrity is valid.
        virtual bool requiresFullSync(const std::string& index,
                                      const std::string& checksum,
                                      std::chrono::seconds timeout,
                                      unsigned int retries,
                                      size_t maxEps) = 0;


        /// @brief Destructor
        virtual ~IAgentSyncProtocol() = default;

        /// @brief Parses a FlatBuffer response message received from the manager.
        /// @param data Pointer to the FlatBuffer-encoded message buffer.
        /// @param length Size of the FlatBuffer message in bytes.
        /// @return true if the message was successfully parsed and processed; false otherwise.
        virtual bool parseResponseBuffer(const uint8_t* data, size_t length) = 0;
};
