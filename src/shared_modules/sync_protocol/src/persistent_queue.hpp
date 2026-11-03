/* Copyright (C) Wazuh Inc.
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
#include "monotonicCondition.hpp"

#include <string>
#include <functional>
#include <array>
#include <map>
#include <vector>
#include <optional>
#include <mutex>
#include <thread>
#include <chrono>
#include <memory>
#include <atomic>
#include <cstdint>

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
        /// @param flushBatchSize Maximum buffered events before an immediate flush. If unset, DEFAULT_FLUSH_BATCH_SIZE is used.
        /// @param flushInterval Maximum time to wait before flushing a non-full buffer. If unset, DEFAULT_FLUSH_INTERVAL is used.
        /// @param walAutocheckpointPages Optional override for the default storage backend's WAL auto-checkpoint
        ///                               threshold, in pages. Ignored when an explicit @p storage is given.
        explicit PersistentQueue(const std::string& dbPath,
                                 LoggerFunc logger,
                                 std::shared_ptr<IPersistentQueueStorage> storage = nullptr,
                                 std::optional<std::size_t> flushBatchSize = std::nullopt,
                                 std::optional<std::chrono::milliseconds> flushInterval = std::nullopt,
                                 std::optional<int32_t> walAutocheckpointPages = std::nullopt);

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

        /// @brief Fetches a batch of pending messages up to a byte budget and marks them for synchronization.
        /// @param maxBytes Maximum estimated payload size to collect. 0 means no byte cap.
        /// @return A vector of messages now marked as SYNCING.
        std::vector<PersistedData> fetchAndMarkForSync(size_t maxBytes = 0) override;

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
        /// @brief Used when no flush batch size override is given.
        static constexpr std::size_t DEFAULT_FLUSH_BATCH_SIZE = 100;

        /// @brief Used when no flush interval override is given.
        static constexpr std::chrono::milliseconds DEFAULT_FLUSH_INTERVAL{500};

        /// @brief Caps the upfront buffer reservation so a large configured batch size does not eagerly allocate that much.
        static constexpr std::size_t MAX_RESERVE_HINT = 10000;

        /// @brief Maximum number of buffered events before triggering an immediate flush.
        const std::size_t FLUSH_BATCH_SIZE;

        /// @brief Maximum time to wait before flushing a non-full buffer.
        const std::chrono::milliseconds FLUSH_INTERVAL;

        /// @brief Drops buffered items matching the predicate from both slots.
        ///        Must be called with m_storageMutex held.
        void discardBuffered(const std::function<bool(const PersistedData&)>& matches);

        /// @brief Mutex protecting m_buffers.
        std::mutex m_mutex;

        /// @brief Mutex serializing all m_storage access across threads, and every flush as a
        ///        whole (swap, write and clear). Always taken before m_mutex, never after it.
        std::mutex m_storageMutex;

        /// @brief Condition variable signalling the flush thread.
        MonotonicCondition m_cv;

        /// @brief Double buffer (ping-pong): producers write to m_buffers[m_currentIdx], and a
        ///        flush (background thread or sync) swaps the index and drains the old slot.
        std::array<std::vector<PersistedData>, 2> m_buffers;

        /// @brief Index (0 or 1) of the buffer currently accepting new events.
        std::size_t m_currentIdx{0};

        /// @brief Background thread that drains m_buffers into storage.
        std::thread m_flushThread;

        /// @brief Set to true to request flush thread shutdown.
        std::atomic<bool> m_stop{false};

        /// @brief Storage backend to persist and restore messages.
        std::shared_ptr<IPersistentQueueStorage> m_storage;

        /// @brief Logger function
        LoggerFunc m_logger;

        /// @brief Main loop executed by m_flushThread.
        void flushLoop();

        /// @brief Swaps out the active buffer and writes it to storage in a single transaction.
        ///        Used by both the background thread and the sync paths; a failed batch stays
        ///        in its slot for the next flush of that slot.
        /// @return true if the active buffer held items (whether or not the write succeeded),
        ///         false if it was empty and nothing was flushed.
        bool flushActiveBuffer();
};
