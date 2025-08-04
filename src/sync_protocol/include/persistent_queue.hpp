/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include "ipersistent_queue.hpp"
#include "ipersistent_queue_storage.hpp"

#include <string>
#include <map>
#include <vector>
#include <optional>
#include <mutex>
#include <memory>
#include <atomic>

/// @brief Implementation of IPersistentQueue with persistent storage backend.
///
/// This class provides a module-scoped message queue.
/// Messages are held in memory and synchronized with a storage backend
/// implementing IPersistentQueueStorage (e.g., SQLite).
///
/// Each module has its own queue and sequence counter, ensuring isolation and ordering.
class PersistentQueue : public IPersistentQueue
{
    public:
        /// @brief Constructs a PersistentQueue with the given storage backend.
        /// @param storage Optional shared pointer to a custom storage backend.
        ///                If null, a default PersistentQueueStorage is used.
        explicit PersistentQueue(std::shared_ptr<IPersistentQueueStorage> storage = nullptr);

        /// @brief Destructor.
        ~PersistentQueue() override;

        /// @brief Adds a new message to the queue and returns its assigned sequence number.
        /// @param id The message ID.
        /// @param index The message grouping key.
        /// @param data The serialized payload of the message.
        /// @param operation The type of operation (e.g., Upsert, Delete).
        /// @return The total number of items for that module in the queue after submission.
        size_t submit(const std::string& id,
                      const std::string& index,
                      const std::string& data,
                      Operation operation) override;

        /// @brief Fetches a batch of pending messages and marks them for synchronization.
        /// @param maxAmount The maximum number of messages to fetch. If 0, fetches all.
        /// @return A vector of messages now marked as SYNCING.
        std::vector<PersistedData> fetchAndMarkForSync(size_t maxAmount) override;

        /// @brief Clears items that were successfully synchronized.
        void clearSyncedItems() override;

        /// @brief Resets items that failed to synchronize.
        void resetSyncingItems() override;

    private:
        /// @brief Mutex to protect concurrent access to internal maps.
        std::mutex m_mutex;

        /// @brief Storage backend to persist and restore messages.
        std::shared_ptr<IPersistentQueueStorage> m_storage;
};
