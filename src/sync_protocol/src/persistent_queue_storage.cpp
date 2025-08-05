/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "persistent_queue_storage.hpp"
#include <filesystem>

using namespace SQLite;

PersistentQueueStorage::PersistentQueueStorage(const std::string& dbPath)
    : m_connection(createOrOpenDatabase(dbPath.empty() ? DEFAULT_DB_PATH : dbPath))
{
    try
    {
        createTableIfNotExists();
    }
    catch (const Sqlite3Error& ex)
    {
        std::cerr << "[PersistentQueueStorage] SQLite error: " << ex.what() << std::endl;
        throw;
    }
}

Connection PersistentQueueStorage::createOrOpenDatabase(const std::string& dbPath)
{
    return Connection(dbPath);
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
    catch (const std::exception& ex)
    {
        std::cerr << "[PersistentQueueStorage] SQLite error: " << ex.what() << std::endl;
        throw;
    }
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
        Statement findStmt(m_connection, findQuery);
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
            Statement insertStmt(m_connection, insertQuery);
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

            if (newData.operation == Operation::DELETE)
            {
                if (oldCreateStatus == CreateStatus::NEW && oldSyncStatus == SyncStatus::PENDING)
                {
                    const std::string deleteQuery = "DELETE FROM persistent_queue WHERE id = ?;";
                    Statement deleteStmt(m_connection, deleteQuery);
                    deleteStmt.bind(1, newData.id);
                    deleteStmt.step();
                }
                else
                {
                    newCreateStatus = (oldCreateStatus == CreateStatus::NEW)
                                      ? CreateStatus::NEW_DELETED
                                      : oldCreateStatus;

                    const std::string updateQuery = "UPDATE persistent_queue SET idx = ?, data = ?, operation = ?, sync_status = ?, create_status = ?, operation_syncing = ? WHERE id = ?;";
                    Statement updateStmt(m_connection, updateQuery);
                    updateStmt.bind(1, newData.index);
                    updateStmt.bind(2, newData.data);
                    updateStmt.bind(3, static_cast<int>(Operation::DELETE));
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
                Statement updateStmt(m_connection, updateQuery);
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
    catch (const std::exception& e)
    {
        std::cerr << "[PersistentQueueStorage] Transaction failed in submitOrCoalesce: " << e.what() << ". Rolling back." << std::endl;
        m_connection.execute("ROLLBACK;");
        throw;
    }
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

        Statement selectStmt(m_connection, selectQuery);
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

        std::string updateQuery = "UPDATE persistent_queue SET sync_status = ? WHERE rowid IN (";

        for (size_t i = 0; i < idsToUpdate.size(); ++i)
        {
            updateQuery += (i == 0 ? "?" : ",?");
        }

        updateQuery += ");";

        Statement updateStmt(m_connection, updateQuery);
        updateStmt.bind(1, static_cast<int>(SyncStatus::SYNCING));

        for (size_t i = 0; i < idsToUpdate.size(); ++i)
        {
            updateStmt.bind(static_cast<int32_t>(i + 2), idsToUpdate[i]);
        }

        updateStmt.step();

        m_connection.execute("COMMIT;");
    }
    catch (const std::exception& e)
    {
        std::cerr << "[PersistentQueueStorage] Transaction failed in fetchAndMarkForSync: "
                  << e.what() << ". Rolling back." << std::endl;
        m_connection.execute("ROLLBACK;");
        throw;
    }

    return result;
}

void PersistentQueueStorage::removeAllSynced()
{
    m_connection.execute("BEGIN IMMEDIATE TRANSACTION;");

    try
    {
        const std::string query = "DELETE FROM persistent_queue WHERE sync_status = ? OR (create_status = ? AND (operation_syncing = ? OR operation_syncing = ?));";
        Statement stmt(m_connection, query);
        stmt.bind(1, static_cast<int>(SyncStatus::SYNCING));
        stmt.bind(2, static_cast<int>(CreateStatus::NEW_DELETED));
        stmt.bind(3, static_cast<int>(Operation::NO_OP));
        stmt.bind(4, static_cast<int>(Operation::DELETE));
        stmt.step();

        const std::string queryUpdate = "UPDATE persistent_queue SET sync_status = ?, create_status = ?, operation_syncing = ? WHERE (sync_status = ? OR sync_status = ?);";
        Statement stmtUpdate(m_connection, queryUpdate);
        stmtUpdate.bind(1, static_cast<int>(SyncStatus::PENDING));
        stmtUpdate.bind(2, static_cast<int>(CreateStatus::EXISTING));
        stmtUpdate.bind(3, static_cast<int>(Operation::NO_OP));
        stmtUpdate.bind(4, static_cast<int>(SyncStatus::SYNCING));
        stmtUpdate.bind(5, static_cast<int>(SyncStatus::SYNCING_UPDATED));
        stmtUpdate.step();

        m_connection.execute("COMMIT;");
    }
    catch (const Sqlite3Error& ex)
    {
        std::cerr << "[PersistentQueueStorage] SQLite error: " << ex.what() << std::endl;
        m_connection.execute("ROLLBACK;");
        throw;
    }
}

void PersistentQueueStorage::resetAllSyncing()
{
    m_connection.execute("BEGIN IMMEDIATE TRANSACTION;");

    try
    {
        const std::string queryUpdate = "UPDATE persistent_queue SET sync_status = ?, operation_syncing = ? WHERE sync_status IN (?, ?);";
        Statement stmtUpdate(m_connection, queryUpdate);
        stmtUpdate.bind(1, static_cast<int>(SyncStatus::PENDING));
        stmtUpdate.bind(2, static_cast<int>(Operation::NO_OP));
        stmtUpdate.bind(3, static_cast<int>(SyncStatus::SYNCING));
        stmtUpdate.bind(4, static_cast<int>(SyncStatus::SYNCING_UPDATED));
        stmtUpdate.step();

        const std::string queryDelete = "DELETE FROM persistent_queue WHERE operation = ? AND create_status = ?;";
        Statement stmtDelete(m_connection, queryDelete);
        stmtDelete.bind(1, static_cast<int>(Operation::DELETE));
        stmtDelete.bind(2, static_cast<int>(CreateStatus::NEW_DELETED));
        stmtDelete.step();

        m_connection.execute("COMMIT;");
    }
    catch (const Sqlite3Error& ex)
    {
        std::cerr << "[PersistentQueueStorage] SQLite error: " << ex.what() << std::endl;
        m_connection.execute("ROLLBACK;");
        throw;
    }
}
