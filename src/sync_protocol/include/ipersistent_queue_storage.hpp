/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <vector>
#include "ipersistent_queue.hpp"

/// @brief Interface for persistent storage backend used by PersistentQueue.
///
/// Implementations of this interface are responsible for saving, retrieving,
/// and deleting queued messages from a persistent store (e.g., SQLite).
class IPersistentQueueStorage
{
    public:
        /// @brief Virtual destructor.
        virtual ~IPersistentQueueStorage() = default;

        /// @brief Submits a new message, applying coalescing logic.
        /// This method finds if a message with the same ID already exists
        /// and applies coalescing rules before inserting, updating, or deleting.
        /// The entire operation is atomic.
        /// @param data The new message data to submit.
        /// @return The total number of messages in the queue after the operation.
        virtual size_t submitOrCoalesce(const PersistedData& data) = 0;

        /// @brief Deletes all messages belonging to a specific module.
        virtual void removeAll() = 0;

        /// @brief Loads all persisted messages for the given module.
        /// @return A vector containing all messages found.
        virtual std::vector<PersistedData> loadAll() = 0;

        /// @brief Fetches a batch of pending messages and marks them as SYNCING.
        /// @param maxAmount The maximum number of messages to fetch. If 0, fetches all.
        /// @return A vector of messages now marked as SYNCING.
        virtual std::vector<PersistedData> fetchAndMarkForSync(size_t maxAmount) = 0;

        /// @brief Deletes all messages for a module currently marked as SYNCING.
        virtual void removeAllSynced() = 0;

        /// @brief Resets the status of all SYNCING messages for a module back to PENDING.
        virtual void resetAllSyncing() = 0;
};
