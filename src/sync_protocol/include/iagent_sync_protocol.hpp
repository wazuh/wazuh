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

        /// @brief Synchronize a module with the server
        /// @param mode Sync mode
        /// @param timeout The timeout for each response wait.
        /// @param retries The maximum number of re-send attempts.
        /// @param maxEps The maximum event reporting throughput. 0 means disabled.
        /// @return true if the sync was successfully processed; false otherwise.
        virtual bool synchronizeModule(Wazuh::SyncSchema::Mode mode, std::chrono::seconds timeout, unsigned int retries, size_t maxEps) = 0;

        /// @brief Destructor
        virtual ~IAgentSyncProtocol() = default;

        /// @brief Parses a FlatBuffer response message received from the manager.
        /// @param data Pointer to the FlatBuffer-encoded message buffer.
        /// @return true if the message was successfully parsed and processed; false otherwise.
        virtual bool parseResponseBuffer(const uint8_t* data) = 0;
};
