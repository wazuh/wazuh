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
#include "sqlite3Wrapper.hpp"

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
    NO_NEW_CREATED = 0,         ///< The message existed prior to the current session; it was not newly created.
    NEW_CREATED = 1,            ///< The message was newly created during the current session.
    DELETED_AFTER_CREATED = 2   ///< The message was newly created, but then deleted before it could be synchronized.
};

/// @brief Defines the type of modification operation that is being synchronized.
enum class OperationSyncing : int
{
    CREATE = 0, ///< The operation is to create a new record.
    MODIFY = 1, ///< The operation is to modify an existing record.
    DELETE = 2, ///< The operation is to delete a record.
    NO_OP = 3   ///< No specific operation is being synchronized. Represents a neutral state.
};

/// @brief SQLite-backed implementation of IPersistentQueueStorage.
///
/// Persists module messages into a local SQLite database file.
/// Each message is stored with a module-scoped sequence number,
/// and the data is durable across agent restarts or crashes.
class PersistentQueueStorage : public IPersistentQueueStorage
{
    public:
        /// @brief Default path where the persistent SQLite database is created.
        inline static constexpr const char* DEFAULT_DB_PATH = "queue/agent_modules_state.db";

        /// @brief Constructs the storage with the given database path.
        /// @param dbPath Path to the SQLite database file. If empty, DEFAULT_DB_PATH is used.
        explicit PersistentQueueStorage(const std::string& dbPath = DEFAULT_DB_PATH);

        /// @brief Default destructor.
        ~PersistentQueueStorage() override = default;

        /// @brief Submits a new message, applying coalescing logic.
        /// This method finds if a message with the same ID already exists
        /// and applies coalescing rules before inserting, updating, or deleting.
        /// The entire operation is atomic.
        /// @param data The new message data to submit.
        virtual void submitOrCoalesce(const PersistedData& data) override;

        /// @brief Fetches a batch of pending messages and marks them as SYNCING.
        /// @return A vector of messages now marked as SYNCING.
        std::vector<PersistedData> fetchAndMarkForSync() override;

        /// @brief Deletes all messages for a module currently marked as SYNCING.
        void removeAllSynced() override;

        /// @brief Resets the status of all SYNCING messages for a module back to PENDING.
        void resetAllSyncing() override;

    private:
        /// @brief Active SQLite database connection.
        SQLite::Connection m_connection;

        /// @brief Creates the persistent_queue table if it doesn't already exist.
        void createTableIfNotExists();

        /// @brief Opens the database file or creates it if it doesn't exist.
        /// @param dbPath Path to the SQLite file.
        /// @return Initialized SQLite connection.
        SQLite::Connection createOrOpenDatabase(const std::string& dbPath);
};
