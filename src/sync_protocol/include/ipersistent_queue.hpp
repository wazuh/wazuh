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

#include <optional>
#include <vector>

/// @brief Represents a persisted message used in module synchronization.
///
/// This structure encapsulates the minimal data required to represent a
/// stateful message that can be stored, replayed, or synchronized.
struct PersistedData
{
    /// @brief Sequence number of the message (scoped per module).
    uint64_t seq;

    /// @brief Unique identifier of the message.
    std::string id;

    /// @brief Logical index
    std::string index;

    /// @brief Serialized content of the message.
    std::string data;

    /// @brief Type of operation (e.g., Upsert, Delete) defined by the schema.
    Wazuh::SyncSchema::Operation operation;
};

/// @brief Interface for persistent message queues.
///
/// This abstraction allows storing, retrieving, and deleting messages
/// tied to individual agent modules (e.g., FIM, SCA).
/// It decouples in-memory logic from the actual storage backend.
class IPersistentQueue
{
    public:
        /// @brief Virtual destructor.
        virtual ~IPersistentQueue() = default;

        /// @brief Adds a new message to the queue and returns its assigned sequence number.
        /// @param module The module name the message belongs to.
        /// @param id The message ID.
        /// @param index The message grouping key.
        /// @param data The serialized payload of the message.
        /// @param operation The type of operation (e.g., Upsert, Delete).
        /// @return Assigned sequence number of the inserted message.
        virtual uint64_t submit(const std::string& module, const std::string& id,
                                const std::string& index,
                                const std::string& data,
                                Wazuh::SyncSchema::Operation operation) = 0;

        /// @brief Fetches the next message in the queue for a given module.
        /// @param module The module name.
        /// @return The next message if available, otherwise std::nullopt.
        virtual std::optional<PersistedData> fetchNext(const std::string& module) = 0;

        /// @brief Returns all messages queued for a given module.
        /// @param module The module name.
        /// @return A vector of all queued messages.
        virtual std::vector<PersistedData> fetchAll(const std::string& module) = 0;

        /// @brief Fetches messages whose sequence numbers fall within any of the provided ranges.
        /// @param module The module name.
        /// @param ranges A list of (start, end) inclusive ranges to filter messages.
        /// @return A vector containing all matching messages.
        virtual std::vector<PersistedData> fetchRange(const std::string& module, const std::vector<std::pair<uint64_t, uint64_t>>& ranges) = 0;

        /// @brief Removes a single message from the queue.
        /// @param module The module name.
        /// @param sequence The sequence number of the message to remove.
        virtual void remove(const std::string& module, uint64_t sequence) = 0;

        /// @brief Removes all messages queued for a given module.
        /// @param module The module name.
        virtual void removeAll(const std::string& module) = 0;
};
