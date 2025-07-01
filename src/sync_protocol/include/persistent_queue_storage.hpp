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
#include "../../shared_modules/utils/sqlite3Wrapper.hpp"

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

        /// @brief Saves a new message entry into the persistent storage.
        /// @param module The module identifier.
        /// @param data The message data to persist.
        void save(const std::string& module, const PersistedData& data) override;

        /// @brief Deletes all messages belonging to a specific module.
        /// @param module The module whose messages will be removed.
        void removeAll(const std::string& module) override;

        /// @brief Loads all persisted messages for the given module.
        /// @param module The module to load messages for.
        /// @return A vector containing all messages found.
        std::vector<PersistedData> loadAll(const std::string& module) override;

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
