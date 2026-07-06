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
#include "agent_sync_protocol_types.hpp"

#include <string>
#include <array>
#include <map>
#include <vector>
#include <optional>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <chrono>
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
        /// @param dbPath Path to the SQLite database file for this protocol instance.
        /// @param logger Logger function
        /// @param storage Optional shared pointer to a custom storage backend.
        ///                If null, a default PersistentQueueStorage is used.
        explicit PersistentQueue(const std::string& dbPath, LoggerFunc logger, std::shared_ptr<IPersistentQueueStorage> storage = nullptr);

        /// @brief Destructor.
        ~PersistentQueue() override;

        /// @brief Adds a new message to the queue and returns its assigned sequence number.
        /// @param id The message ID.
        /// @param index The message grouping key.
        /// @param data The serialized payload of the message.
        /// @param operation The type of operation (e.g., Upsert, Delete).
        /// @param version Version of the data.
        /// @param isDataContext Flag to mark data as DataContext (true) or DataValue (false).
        void submit(const std::string& id,
                    const std::string& index,
                    const std::string& data,
                    Operation operation,
                    uint64_t version,
                    bool isDataContext = false) override;

        /// @brief Fetches a batch of pending messages and marks them for synchronization.
        /// @return A vector of messages now marked as SYNCING.
        std::vector<PersistedData> fetchAndMarkForSync() override;

        /// @brief Fetches pending items without marking them for sync.
        /// @param onlyDataValues If true, only returns items with is_data_context=false
        /// @return A vector of pending messages.
        std::vector<PersistedData> fetchPendingItems(bool onlyDataValues = true) override;

        /// @brief Clears items that were successfully synchronized.
        void clearSyncedItems() override;

        /// @brief Resets items that failed to synchronize.
        void resetSyncingItems() override;

        /// @brief Clears all items belonging to a specific index.
        /// @param index The index for which all items should be cleared.
        void clearItemsByIndex(const std::string& index) override;

        /// @brief Clears all DataContext items (where is_data_context = true).
        void clearAllDataContext() override;

        /// @brief Deletes the database file.
        /// This method closes the database connection and removes the database file from disk.
        void deleteDatabase() override;

    private:
        /// @brief Maximum number of buffered events before triggering an immediate flush.
        static constexpr std::size_t FLUSH_BATCH_SIZE = 100;

        /// @brief Maximum time to wait before flushing a non-full buffer.
        static constexpr std::chrono::milliseconds FLUSH_INTERVAL{500};

        /// @brief Mutex protecting m_buffer.
        std::mutex m_mutex;

        /// @brief Mutex serializing all m_storage access across threads.
        std::mutex m_storageMutex;

        /// @brief Condition variable signalling the flush thread.
        std::condition_variable m_cv;

        /// @brief Double buffer (ping-pong): producers write to m_buffers[m_currentIdx],
        ///        the flush thread swaps the index and drains the old slot.
        std::array<std::vector<PersistedData>, 2> m_buffers;

        /// @brief Index (0 or 1) of the buffer currently accepting new events.
        std::size_t m_currentIdx{0};

        /// @brief Background thread that drains m_buffer into storage.
        std::thread m_flushThread;

        /// @brief Set to true to request flush thread shutdown.
        std::atomic<bool> m_stop{false};

        /// @brief Storage backend to persist and restore messages.
        std::shared_ptr<IPersistentQueueStorage> m_storage;

        /// @brief Logger function
        LoggerFunc m_logger;

        /// @brief Main loop executed by m_flushThread.
        void flushLoop();

        /// @brief Writes a batch to storage in a single transaction.
        void flushBuffer(const std::vector<PersistedData>& batch);

        /// @brief Steals any items currently in m_buffer and flushes them to storage.
        void flushPendingBuffer();
};
