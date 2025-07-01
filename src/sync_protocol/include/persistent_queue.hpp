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
        /// @param module The module name the message belongs to.
        /// @param id The message ID.
        /// @param index The message grouping key.
        /// @param data The serialized payload of the message.
        /// @param operation The type of operation (e.g., Upsert, Delete).
        /// @return Assigned sequence number of the inserted message.
        uint64_t submit(const std::string& module, const std::string& id,
                        const std::string& index,
                        const std::string& data,
                        Wazuh::SyncSchema::Operation operation) override;

        /// @brief Returns all messages queued for a given module.
        /// @param module The module name.
        /// @return A vector of all queued messages.
        std::vector<PersistedData> fetchAll(const std::string& module) override;

        /// @brief Fetches messages whose sequence numbers fall within any of the provided ranges.
        /// @param module The module name.
        /// @param ranges A list of (start, end) inclusive ranges to filter messages.
        /// @return A vector containing all matching messages.
        std::vector<PersistedData> fetchRange(const std::string& module, const std::vector<std::pair<uint64_t, uint64_t>>& ranges) override;

        /// @brief Removes all messages queued for a given module.
        /// @param module The module name.
        void removeAll(const std::string& module) override;

    private:
        /// @brief Mutex to protect concurrent access to internal maps.
        std::mutex m_mutex;

        /// @brief In-memory message queue for each module.
        std::map<std::string, std::vector<PersistedData>> m_store;

        /// @brief Sequence number counter per module.
        std::map<std::string, std::atomic<uint64_t>> m_seqCounter;

        /// @brief Storage backend to persist and restore messages.
        std::shared_ptr<IPersistentQueueStorage> m_storage;

        /// @brief Loads persisted messages from storage into memory.
        /// @param module Module name.
        void loadFromStorage(const std::string& module);

        /// @brief Persists a message using the storage backend.
        /// @param module Module name.
        /// @param data Message to persist.
        void persistMessage(const std::string& module, const PersistedData& data);

        /// @brief Deletes all messages for a module from storage.
        /// @param module Module name.
        void deleteAllMessages(const std::string& module);
};
