/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "persistent_queue_storage.hpp"
#include "filesystem_wrapper.hpp"
#include "logging_helper.hpp"
#include <filesystem>

PersistentQueueStorage::PersistentQueueStorage(const std::string& dbPath, LoggerFunc logger, std::shared_ptr<IFileSystemWrapper> fileSystemWrapper)
    : m_connection(createOrOpenDatabase(dbPath)),
      m_dbPath(dbPath),
      m_logger(std::move(logger)),
      m_fileSystemWrapper(fileSystemWrapper ? std::move(fileSystemWrapper) : std::make_shared<file_system::FileSystemWrapper>())
{
    if (!m_logger)
    {
        throw std::invalid_argument("Logger provided to PersistentQueueStorage cannot be null.");
    }

    try
    {
        createTableIfNotExists();
        m_connection.execute("PRAGMA synchronous = NORMAL;");
        m_connection.execute("PRAGMA journal_mode = WAL;");
    }
    // LCOV_EXCL_START
    catch (const std::exception& ex)
    {
        m_logger(LOG_ERROR, std::string("PersistentQueueStorage: SQLite error: ") + ex.what());
        throw;
    }

    // LCOV_EXCL_STOP
}

SQLite3Wrapper::Connection PersistentQueueStorage::createOrOpenDatabase(const std::string& dbPath)
{
    return SQLite3Wrapper::Connection(dbPath);
}

void PersistentQueueStorage::createTableIfNotExists()
{
    try
    {
        const std::string query =
            "CREATE TABLE IF NOT EXISTS persistent_queue ("
            "id TEXT PRIMARY KEY NOT NULL,"
            "idx TEXT NOT NULL,"
            "data TEXT NOT NULL,"
            "operation INTEGER NOT NULL,"
            "sync_status INTEGER NOT NULL DEFAULT 0,"
            "create_status INTEGER NOT NULL DEFAULT 0,"
            "operation_syncing INTEGER NOT NULL DEFAULT 3);";

        m_connection.execute(query);
    }
    // LCOV_EXCL_START
    catch (const std::exception& ex)
    {
        m_logger(LOG_ERROR, std::string("PersistentQueueStorage: SQLite error: ") + ex.what());
        throw;
    }

    // LCOV_EXCL_STOP
}

void PersistentQueueStorage::submitOrCoalesce(const PersistedData& newData)
{
    m_connection.execute("BEGIN IMMEDIATE TRANSACTION;");

    try
    {
        bool oldDataFound = false;
        CreateStatus oldCreateStatus = CreateStatus::EXISTING;
        CreateStatus newCreateStatus = CreateStatus::EXISTING;
        SyncStatus oldSyncStatus = SyncStatus::PENDING;
        SyncStatus newSyncStatus = SyncStatus::PENDING;
        Operation oldOperationSyncing = Operation::NO_OP;
        Operation newOperationSyncing = Operation::NO_OP;
        int oldOperation = -1;

        const std::string findQuery = "SELECT operation, sync_status, create_status, operation_syncing FROM persistent_queue WHERE id = ?;";
        SQLite3Wrapper::Statement findStmt(m_connection, findQuery);
        findStmt.bind(1, newData.id);

        if (findStmt.step() == SQLITE_ROW)
        {
            oldOperation = findStmt.value<int>(0);
            oldSyncStatus = static_cast<SyncStatus>(findStmt.value<int>(1));
            oldCreateStatus = static_cast<CreateStatus>(findStmt.value<int>(2));
            oldOperationSyncing = static_cast<Operation>(findStmt.value<int>(3));
            oldDataFound = true;
        }

        if (oldSyncStatus != SyncStatus::PENDING)
        {
            newOperationSyncing = (oldOperationSyncing == Operation::NO_OP)
                                  ? static_cast<Operation>(oldOperation)
                                  : oldOperationSyncing;
        }

        if (!oldDataFound)
        {
            const std::string insertQuery = "INSERT INTO persistent_queue (id, idx, data, operation, create_status) VALUES (?, ?, ?, ?, ?);";
            SQLite3Wrapper::Statement insertStmt(m_connection, insertQuery);
            insertStmt.bind(1, newData.id);
            insertStmt.bind(2, newData.index);
            insertStmt.bind(3, newData.data);
            insertStmt.bind(4, static_cast<int>(newData.operation));
            insertStmt.bind(5, (newData.operation == Operation::CREATE)
                            ? static_cast<int>(CreateStatus::NEW)
                            : static_cast<int>(CreateStatus::EXISTING));
            insertStmt.step();
        }
        else
        {
            newSyncStatus = (oldSyncStatus == SyncStatus::PENDING)
                            ? SyncStatus::PENDING
                            : SyncStatus::SYNCING_UPDATED;

            if (newData.operation == Operation::DELETE_)
            {
                if (oldCreateStatus == CreateStatus::NEW && oldSyncStatus == SyncStatus::PENDING)
                {
                    const std::string deleteQuery = "DELETE FROM persistent_queue WHERE id = ?;";
                    SQLite3Wrapper::Statement deleteStmt(m_connection, deleteQuery);
                    deleteStmt.bind(1, newData.id);
                    deleteStmt.step();
                }
                else
                {
                    newCreateStatus = (oldCreateStatus == CreateStatus::NEW)
                                      ? CreateStatus::NEW_DELETED
                                      : oldCreateStatus;

                    const std::string updateQuery = "UPDATE persistent_queue SET idx = ?, data = ?, operation = ?, sync_status = ?, create_status = ?, operation_syncing = ? WHERE id = ?;";
                    SQLite3Wrapper::Statement updateStmt(m_connection, updateQuery);
                    updateStmt.bind(1, newData.index);
                    updateStmt.bind(2, newData.data);
                    updateStmt.bind(3, static_cast<int>(Operation::DELETE_));
                    updateStmt.bind(4, static_cast<int>(newSyncStatus));
                    updateStmt.bind(5, static_cast<int>(newCreateStatus));
                    updateStmt.bind(6, static_cast<int>(newOperationSyncing));
                    updateStmt.bind(7, newData.id);
                    updateStmt.step();
                }
            }
            else
            {
                newCreateStatus = (oldCreateStatus == CreateStatus::NEW_DELETED)
                                  ? CreateStatus::NEW
                                  : oldCreateStatus;

                const std::string updateQuery = "UPDATE persistent_queue SET idx = ?, data = ?, operation = ?, sync_status = ?, create_status = ?, operation_syncing = ? WHERE id = ?;";
                SQLite3Wrapper::Statement updateStmt(m_connection, updateQuery);
                updateStmt.bind(1, newData.index);
                updateStmt.bind(2, newData.data);
                updateStmt.bind(3, static_cast<int>(newData.operation));
                updateStmt.bind(4, static_cast<int>(newSyncStatus));
                updateStmt.bind(5, static_cast<int>(newCreateStatus));
                updateStmt.bind(6, static_cast<int>(newOperationSyncing));
                updateStmt.bind(7, newData.id);
                updateStmt.step();
            }
        }

        m_connection.execute("COMMIT;");
    }
    // LCOV_EXCL_START
    catch (const std::exception& e)
    {
        m_logger(LOG_ERROR, std::string("PersistentQueueStorage: Transaction failed in submitOrCoalesce: ") + e.what());
        m_connection.execute("ROLLBACK;");
        throw;
    }

    // LCOV_EXCL_STOP
}

std::vector<PersistedData> PersistentQueueStorage::fetchAndMarkForSync()
{
    std::vector<PersistedData> result;
    std::vector<int64_t> idsToUpdate;

    m_connection.execute("BEGIN IMMEDIATE TRANSACTION;");

    try
    {
        std::string selectQuery =
            "SELECT rowid, id, idx, data, operation "
            "FROM persistent_queue "
            "WHERE sync_status = ? "
            "ORDER BY rowid ASC;";

        SQLite3Wrapper::Statement selectStmt(m_connection, selectQuery);
        selectStmt.bind(1, static_cast<int>(SyncStatus::PENDING));

        while (selectStmt.step() == SQLITE_ROW)
        {
            PersistedData data;
            int64_t rowid = selectStmt.value<int64_t>(0);
            data.id = selectStmt.value<std::string>(1);
            data.index = selectStmt.value<std::string>(2);
            data.data = selectStmt.value<std::string>(3);
            data.operation = static_cast<Operation>(selectStmt.value<int>(4));

            idsToUpdate.push_back(rowid);
            result.emplace_back(std::move(data));
        }

        if (idsToUpdate.empty())
        {
            m_connection.execute("COMMIT;");
            return result;
        }

        // SQLite has a limit on the number of parameters in a single query
        // (typically 999). To handle an unlimited number of pending items,
        // we process the UPDATE statement in batches.
        constexpr size_t BATCH_SIZE = 500;

        for (size_t i = 0; i < idsToUpdate.size(); i += BATCH_SIZE)
        {
            std::string updateQuery = "UPDATE persistent_queue SET sync_status = ? WHERE rowid IN (";

            size_t batch_end = std::min(i + BATCH_SIZE, idsToUpdate.size());

            for (size_t j = i; j < batch_end; ++j)
            {
                updateQuery += (j == i ? "?" : ",?");
            }

            updateQuery += ");";

            SQLite3Wrapper::Statement updateStmt(m_connection, updateQuery);
            updateStmt.bind(1, static_cast<int>(SyncStatus::SYNCING));

            for (size_t j = i; j < batch_end; ++j)
            {
                updateStmt.bind(static_cast<int32_t>((j - i) + 2), idsToUpdate[j]);
            }

            updateStmt.step();
        }

        m_connection.execute("COMMIT;");
    }
    // LCOV_EXCL_START
    catch (const std::exception& e)
    {
        m_logger(LOG_ERROR, std::string("PersistentQueueStorage: Transaction failed in fetchAndMarkForSync: ") + e.what());
        m_connection.execute("ROLLBACK;");
        throw;
    }

    // LCOV_EXCL_STOP

    return result;
}

void PersistentQueueStorage::removeAllSynced()
{
    m_connection.execute("BEGIN IMMEDIATE TRANSACTION;");

    try
    {
        const std::string query = "DELETE FROM persistent_queue WHERE sync_status = ? OR (create_status = ? AND (operation_syncing = ? OR operation_syncing = ?));";
        SQLite3Wrapper::Statement stmt(m_connection, query);
        stmt.bind(1, static_cast<int>(SyncStatus::SYNCING));
        stmt.bind(2, static_cast<int>(CreateStatus::NEW_DELETED));
        stmt.bind(3, static_cast<int>(Operation::NO_OP));
        stmt.bind(4, static_cast<int>(Operation::DELETE_));
        stmt.step();

        const std::string queryUpdate = "UPDATE persistent_queue SET sync_status = ?, create_status = ?, operation_syncing = ? WHERE (sync_status = ? OR sync_status = ?);";
        SQLite3Wrapper::Statement stmtUpdate(m_connection, queryUpdate);
        stmtUpdate.bind(1, static_cast<int>(SyncStatus::PENDING));
        stmtUpdate.bind(2, static_cast<int>(CreateStatus::EXISTING));
        stmtUpdate.bind(3, static_cast<int>(Operation::NO_OP));
        stmtUpdate.bind(4, static_cast<int>(SyncStatus::SYNCING));
        stmtUpdate.bind(5, static_cast<int>(SyncStatus::SYNCING_UPDATED));
        stmtUpdate.step();

        m_connection.execute("COMMIT;");
    }
    // LCOV_EXCL_START
    catch (const std::exception& ex)
    {
        m_logger(LOG_ERROR, std::string("PersistentQueueStorage: SQLite error: ") + ex.what());
        m_connection.execute("ROLLBACK;");
        throw;
    }

    // LCOV_EXCL_STOP
}

void PersistentQueueStorage::resetAllSyncing()
{
    m_connection.execute("BEGIN IMMEDIATE TRANSACTION;");

    try
    {
        const std::string queryUpdate = "UPDATE persistent_queue SET sync_status = ?, operation_syncing = ? WHERE sync_status IN (?, ?);";
        SQLite3Wrapper::Statement stmtUpdate(m_connection, queryUpdate);
        stmtUpdate.bind(1, static_cast<int>(SyncStatus::PENDING));
        stmtUpdate.bind(2, static_cast<int>(Operation::NO_OP));
        stmtUpdate.bind(3, static_cast<int>(SyncStatus::SYNCING));
        stmtUpdate.bind(4, static_cast<int>(SyncStatus::SYNCING_UPDATED));
        stmtUpdate.step();

        const std::string queryDelete = "DELETE FROM persistent_queue WHERE operation = ? AND create_status = ?;";
        SQLite3Wrapper::Statement stmtDelete(m_connection, queryDelete);
        stmtDelete.bind(1, static_cast<int>(Operation::DELETE_));
        stmtDelete.bind(2, static_cast<int>(CreateStatus::NEW_DELETED));
        stmtDelete.step();

        m_connection.execute("COMMIT;");
    }
    // LCOV_EXCL_START
    catch (const std::exception& ex)
    {
        m_logger(LOG_ERROR, std::string("PersistentQueueStorage: SQLite error: ") + ex.what());
        m_connection.execute("ROLLBACK;");
        throw;
    }

    // LCOV_EXCL_STOP
}

void PersistentQueueStorage::removeByIndex(const std::string& index)
{
    m_connection.execute("BEGIN IMMEDIATE TRANSACTION;");

    try
    {
        const std::string query = "DELETE FROM persistent_queue WHERE idx = ?;";
        SQLite3Wrapper::Statement stmt(m_connection, query);
        stmt.bind(1, index);
        stmt.step();

        m_connection.execute("COMMIT;");
    }
    // LCOV_EXCL_START
    catch (const std::exception& ex)
    {
        m_logger(LOG_ERROR, std::string("PersistentQueueStorage: SQLite error in removeByIndex: ") + ex.what());
        m_connection.execute("ROLLBACK;");
        throw;
    }

    // LCOV_EXCL_STOP
}

void PersistentQueueStorage::deleteDatabase()
{
    try
    {
        // Close the database connection first
        m_connection.close();

        // Remove the database file from the filesystem
        if (m_fileSystemWrapper->exists(m_dbPath))
        {
            m_fileSystemWrapper->remove(m_dbPath);
            m_logger(LOG_DEBUG, std::string("PersistentQueueStorage: Database file deleted: ") + m_dbPath);
        }
        else
        {
            m_logger(LOG_WARNING, std::string("PersistentQueueStorage: Database file not found: ") + m_dbPath);
        }
    }
    catch (const std::filesystem::filesystem_error& ex)
    {
        m_logger(LOG_ERROR, std::string("PersistentQueueStorage: Filesystem error deleting database: ") + ex.what());
        throw;
    }
    catch (const std::exception& ex)
    {
        m_logger(LOG_ERROR, std::string("PersistentQueueStorage: Error deleting database: ") + ex.what());
        throw;
    }
}
