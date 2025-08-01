/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <cstdint>
#include <string>
#include <optional>
#include <vector>

/// @brief Defines the type of modification operation.
enum class Operation : int
{
    CREATE = 0, ///< The operation is to create a new record.
    MODIFY = 1, ///< The operation is to modify an existing record.
    DELETE = 2 ///< The operation is to delete a record.
};

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

    /// @brief Type of operation (CREATE, MODIFY, Delete).
    Operation operation;
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
        /// @param id The message ID.
        /// @param index The message grouping key.
        /// @param data The serialized payload of the message.
        /// @param operation The type of operation (CREATE, MODIFY, Delete).
        /// @return The total number of items for that module in the queue after submission.
        virtual size_t submit(const std::string& id,
                              const std::string& index,
                              const std::string& data,
                              Operation operation) = 0;

        /// @brief Removes all messages queued for a given module.
        virtual void removeAll() = 0;

        /// @brief Fetches a batch of pending messages and marks them for synchronization.
        /// @param maxAmount The maximum number of messages to fetch. If 0, fetches all.
        /// @return A vector of messages now marked as SYNCING.
        virtual std::vector<PersistedData> fetchAndMarkForSync(size_t maxAmount) = 0;

        /// @brief Clears items that were successfully synchronized.
        virtual void clearSyncedItems() = 0;

        /// @brief Resets items that failed to synchronize.
        virtual void resetSyncingItems() = 0;
};
