/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include "ipersistent_queue_storage.hpp"
#include "agent_sync_protocol_types.hpp"
#include "ifilesystem_wrapper.hpp"

#include <list>
#include <memory>
#include <string>
#include <unordered_map>

/// @brief In-memory implementation of IPersistentQueueStorage.
///
/// Holds the full queue state in memory for the lifetime of the process; no disk I/O
/// happens on submit/fetch/clear. The on-disk file (in the SQLite format produced by
/// PersistentQueueStorage) is only touched at the two lifecycle boundaries: it is loaded
/// once at construction (if present, from a previous graceful shutdown) and written once
/// at destruction. An ungraceful termination (crash, SIGKILL) skips the destructor, so no
/// snapshot is written — the queue reverts to its last gracefully-saved state on the next
/// run, which is the accepted trade-off for removing continuous disk I/O from this queue.
class InMemoryQueueStorage : public IPersistentQueueStorage
{
    public:
        /// @brief Constructs the storage, loading any existing on-disk snapshot at dbPath.
        /// @param dbPath Path to the on-disk snapshot file (SQLite format).
        /// @param logger Logger function.
        /// @param fileSystemWrapper Filesystem wrapper for operations (for testing). If nullptr, uses default implementation.
        explicit InMemoryQueueStorage(const std::string& dbPath, LoggerFunc logger, std::shared_ptr<IFileSystemWrapper> fileSystemWrapper = nullptr);

        /// @brief Destructor. Writes the full in-memory state back to dbPath.
        ~InMemoryQueueStorage() override;

        void submitOrCoalesce(const PersistedData& data) override;
        void submitBatch(const std::vector<PersistedData>& batch) override;
        std::vector<PersistedData> fetchAndMarkForSync(size_t maxBytes = 0) override;
        std::vector<PersistedData> fetchPending(bool onlyDataValues = true) override;
        void removeAllSynced() override;
        void resetAllSyncing() override;
        void removeByIndex(const std::string& index) override;
        void removeAllDataContext() override;
        void deleteDatabase() override;
        std::vector<QueueRow> fetchAll() override;
        void saveAll(const std::vector<QueueRow>& rows) override;

    private:
        /// @brief Rows in insertion order.
        std::list<QueueRow> m_rows;

        /// @brief Index from message id to its position in m_rows, for O(1) lookup.
        std::unordered_map<std::string, std::list<QueueRow>::iterator> m_index;

        /// @brief Monotonically increasing counter assigned to each row on insertion.
        uint64_t m_nextRowId{1};

        /// @brief Id of the pending item currently stuck as a lone oversized block, if any.
        /// Mirrors PersistentQueueStorage's own oversized-item tracking.
        std::string m_oversizedItemId;

        /// @brief Consecutive fetchAndMarkForSync() calls in which m_oversizedItemId was
        ///        resent alone because it exceeds the byte cap on its own.
        unsigned int m_oversizedItemAttempts = 0;

        /// @brief Path to the on-disk snapshot file.
        std::string m_dbPath;

        /// @brief Logger function.
        LoggerFunc m_logger;

        /// @brief Filesystem wrapper for operations.
        std::shared_ptr<IFileSystemWrapper> m_fileSystemWrapper;

        /// @brief Applies coalescing logic for a single item against the in-memory rows.
        /// Mirrors PersistentQueueStorage::applyCoalesceLogic's SQL semantics exactly.
        void applyCoalesceLogic(const PersistedData& newData);

        /// @brief Appends a fully-formed row, assigning it the next row id.
        void addRow(QueueRow row);

        /// @brief Loads a previously-saved snapshot from m_dbPath, if it exists.
        void loadFromDisk();

        /// @brief Writes the current in-memory rows to m_dbPath.
        void saveToDisk();
};
