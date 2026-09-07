/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <cstddef>
#include <vector>
#include "ipersistent_queue.hpp"

/// @brief Defines the synchronization status of a persisted message.
enum class SyncStatus : int
{
    PENDING = 0,        ///< The message is waiting to be synchronized.
    SYNCING = 1,        ///< The message is currently being synchronized.
    SYNCING_UPDATED = 2 ///< The message is being synchronized and its contents have been updated.
};

/// @brief Tracks the creation state of a persisted message, particularly for newly created items.
enum class CreateStatus : int
{
    EXISTING = 0,     ///< The message existed prior to the current session; it was not newly created.
    NEW = 1,          ///< The message was newly created during the current session.
    NEW_DELETED = 2   ///< The message was newly created, but then deleted before it could be synchronized.
};

/// @brief A single stored row, including the internal coalescing state.
///
/// Used to move the full queue state between the runtime backend (in-memory) and the
/// on-disk snapshot format (SQLite) via fetchAll()/saveAll() — the two boundaries where
/// the queue is persisted (agent startup / graceful shutdown).
struct QueueRow
{
    /// @brief Row insertion order, used to preserve FIFO ordering across a save/load round trip.
    uint64_t rowId{};

    /// @brief The message payload.
    PersistedData data;

    /// @brief Current synchronization status.
    SyncStatus syncStatus{SyncStatus::PENDING};

    /// @brief Current creation status.
    CreateStatus createStatus{CreateStatus::EXISTING};

    /// @brief Operation captured while the previous version of this row was mid-sync.
    Operation operationSyncing{Operation::NO_OP};
};

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
        virtual void submitOrCoalesce(const PersistedData& data) = 0;

        /// @brief Submits a batch of messages in a single transaction, applying coalescing logic
        /// to each item. Reduces per-event transaction overhead compared to calling
        /// submitOrCoalesce() individually.
        /// @param batch Vector of messages to persist atomically.
        virtual void submitBatch(const std::vector<PersistedData>& batch) = 0;

        /// @brief Fetches a batch of pending messages up to a byte budget and marks them as SYNCING.
        /// @param maxBytes Maximum estimated payload size to collect. 0 means no byte cap.
        /// @return A vector of messages now marked as SYNCING.
        virtual std::vector<PersistedData> fetchAndMarkForSync(size_t maxBytes = 0) = 0;

        /// @brief Fetches pending items without marking them for sync.
        /// @param onlyDataValues If true, only returns items with is_data_context=false
        /// @return A vector of pending messages.
        virtual std::vector<PersistedData> fetchPending(bool onlyDataValues = true) = 0;

        /// @brief Deletes all messages for a module currently marked as SYNCING.
        virtual void removeAllSynced() = 0;

        /// @brief Resets the status of all SYNCING messages for a module back to PENDING.
        virtual void resetAllSyncing() = 0;

        /// @brief Deletes all messages belonging to a specific index.
        /// @param index The index for which all messages should be removed.
        virtual void removeByIndex(const std::string& index) = 0;

        /// @brief Deletes all DataContext messages (where is_data_context = 1).
        virtual void removeAllDataContext() = 0;

        /// @brief Deletes the database file.
        /// This method closes the database connection and removes the database file from disk.
        virtual void deleteDatabase() = 0;

        /// @brief Fetches every row regardless of status, including internal coalescing state.
        /// Used to load a full snapshot (e.g. from disk into memory at startup).
        /// @return All rows in insertion order.
        virtual std::vector<QueueRow> fetchAll() = 0;

        /// @brief Replaces the entire contents of the store with the given rows, in one
        /// transaction. Used to persist a full snapshot (e.g. from memory to disk at shutdown).
        /// @param rows The complete set of rows to persist, in insertion order.
        virtual void saveAll(const std::vector<QueueRow>& rows) = 0;
};
