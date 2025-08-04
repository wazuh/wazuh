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

size_t PersistentQueueStorage::submitOrCoalesce(const PersistedData& newData)
{
    m_connection.execute("BEGIN IMMEDIATE TRANSACTION;");

    try
    {
        bool oldDataFound = false;
        CreateStatus oldCreateStatus = CreateStatus::NO_NEW_CREATED;
        CreateStatus newCreateStatus = CreateStatus::NO_NEW_CREATED;
        SyncStatus oldSyncStatus = SyncStatus::PENDING;
        SyncStatus newSyncStatus = SyncStatus::PENDING;
        OperationSyncing oldOperationSyncing = OperationSyncing::NO_OP;
        OperationSyncing newOperationSyncing = OperationSyncing::NO_OP;
        int oldOperation = -1;

        const std::string findQuery = "SELECT operation, sync_status, create_status, operation_syncing FROM persistent_queue WHERE id = ?;";
        Statement findStmt(m_connection, findQuery);
        findStmt.bind(1, newData.id);

        if (findStmt.step() == SQLITE_ROW)
        {
            oldOperation = findStmt.value<int>(0);
            oldSyncStatus = static_cast<SyncStatus>(findStmt.value<int>(1));
            oldCreateStatus = static_cast<CreateStatus>(findStmt.value<int>(2));
            oldOperationSyncing = static_cast<OperationSyncing>(findStmt.value<int>(3));
            oldDataFound = true;
        }

        if (oldSyncStatus != SyncStatus::PENDING)
        {
            newOperationSyncing = (oldOperationSyncing == OperationSyncing::NO_OP)
                                  ? static_cast<OperationSyncing>(oldOperation)
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
                            ? static_cast<int>(CreateStatus::NEW_CREATED)
                            : static_cast<int>(CreateStatus::NO_NEW_CREATED));
            insertStmt.step();
        }
        else
        {
            newSyncStatus = (oldSyncStatus == SyncStatus::PENDING)
                            ? SyncStatus::PENDING
                            : SyncStatus::SYNCING_UPDATED;

            if (newData.operation == Operation::DELETE)
            {
                if (oldCreateStatus == CreateStatus::NEW_CREATED && oldSyncStatus == SyncStatus::PENDING)
                {
                    const std::string deleteQuery = "DELETE FROM persistent_queue WHERE id = ?;";
                    Statement deleteStmt(m_connection, deleteQuery);
                    deleteStmt.bind(1, newData.id);
                    deleteStmt.step();
                }
                else
                {
                    newCreateStatus = (oldCreateStatus == CreateStatus::NEW_CREATED)
                                      ? CreateStatus::DELETED_AFTER_CREATED
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
                newCreateStatus = (oldCreateStatus == CreateStatus::DELETED_AFTER_CREATED)
                                  ? CreateStatus::NEW_CREATED
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

        size_t final_count = 0;
        const std::string countQuery = "SELECT COUNT(*) FROM persistent_queue;";
        Statement countStmt(m_connection, countQuery);

        if (countStmt.step() == SQLITE_ROW)
        {
            final_count = countStmt.value<int64_t>(0);
        }

        m_connection.execute("COMMIT;");
        return final_count;
    }
    catch (const std::exception& e)
    {
        std::cerr << "[PersistentQueueStorage] Transaction failed in submitOrCoalesce: " << e.what() << ". Rolling back." << std::endl;
        m_connection.execute("ROLLBACK;");
        throw;
    }
}

std::vector<PersistedData> PersistentQueueStorage::fetchAndMarkForSync(size_t maxAmount)
{
    std::vector<PersistedData> result;
    std::vector<sqlite3_int64> idsToUpdate;

    m_connection.execute("BEGIN IMMEDIATE TRANSACTION;");

    try
    {
        std::string selectQuery =
            "SELECT rowid FROM persistent_queue WHERE sync_status = ? ORDER BY rowid ASC";

        if (maxAmount > 0)
        {
            selectQuery += " LIMIT ?;";
        }

        Statement selectStmt(m_connection, selectQuery);
        selectStmt.bind(1, static_cast<int>(SyncStatus::PENDING));

        if (maxAmount > 0)
        {
            selectStmt.bind(2, static_cast<int64_t>(maxAmount));
        }

        while (selectStmt.step() == SQLITE_ROW)
        {
            idsToUpdate.push_back(selectStmt.value<int64_t>(0));
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
            updateStmt.bind(i + 2, static_cast<int64_t>(idsToUpdate[i]));
        }

        updateStmt.step();

        std::string selectDataQuery = "SELECT id, idx, data, operation FROM persistent_queue WHERE rowid IN (";

        for (size_t i = 0; i < idsToUpdate.size(); ++i)
        {
            selectDataQuery += (i == 0 ? "?" : ",?");
        }

        selectDataQuery += ") ORDER BY rowid ASC;";

        Statement dataStmt(m_connection, selectDataQuery);

        for (size_t i = 0; i < idsToUpdate.size(); ++i)
        {
            dataStmt.bind(i + 1, static_cast<int64_t>(idsToUpdate[i]));
        }

        while (dataStmt.step() == SQLITE_ROW)
        {
            PersistedData data;
            data.id = dataStmt.value<std::string>(0);
            data.index = dataStmt.value<std::string>(1);
            data.data = dataStmt.value<std::string>(2);
            data.operation = static_cast<Operation>(dataStmt.value<int>(3));
            result.emplace_back(std::move(data));
        }

        m_connection.execute("COMMIT;");
    }
    catch (const std::exception& e)
    {
        std::cerr << "[PersistentQueueStorage] Transaction failed in fetchAndMarkForSync: " << e.what() << ". Rolling back." << std::endl;
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
        const std::string query = "DELETE FROM persistent_queue WHERE sync_status = ?;";
        Statement stmt(m_connection, query);
        stmt.bind(1, static_cast<int>(SyncStatus::SYNCING));
        stmt.step();

        const std::string query2 = "DELETE FROM persistent_queue WHERE create_status = ? AND (operation_syncing = ? OR operation_syncing = ?);";
        Statement stmt2(m_connection, query2);
        stmt2.bind(1, static_cast<int>(CreateStatus::DELETED_AFTER_CREATED));
        stmt2.bind(2, static_cast<int>(OperationSyncing::NO_OP));
        stmt2.bind(3, static_cast<int>(OperationSyncing::DELETE));
        stmt2.step();

        const std::string queryUpdate = "UPDATE persistent_queue SET sync_status = ?, create_status = ?, operation_syncing = ? WHERE (sync_status = ? OR sync_status = ?);";
        Statement stmtUpdate(m_connection, queryUpdate);
        stmtUpdate.bind(1, static_cast<int>(SyncStatus::PENDING));
        stmtUpdate.bind(2, static_cast<int>(CreateStatus::NO_NEW_CREATED));
        stmtUpdate.bind(3, static_cast<int>(OperationSyncing::NO_OP));
        stmtUpdate.bind(4, static_cast<int>(SyncStatus::SYNCING));
        stmtUpdate.bind(5, static_cast<int>(SyncStatus::SYNCING_UPDATED));
        stmtUpdate.step();

        const std::string queryUpdateIsNew = "UPDATE persistent_queue SET create_status = ? WHERE operation = ?;";
        Statement stmtUpdateIsNew(m_connection, queryUpdateIsNew);
        stmtUpdateIsNew.bind(1, static_cast<int>(CreateStatus::NEW_CREATED));
        stmtUpdateIsNew.bind(2, static_cast<int>(Operation::CREATE));
        stmtUpdateIsNew.step();

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
        stmtUpdate.bind(2, static_cast<int>(OperationSyncing::NO_OP));
        stmtUpdate.bind(3, static_cast<int>(SyncStatus::SYNCING));
        stmtUpdate.bind(4, static_cast<int>(SyncStatus::SYNCING_UPDATED));
        stmtUpdate.step();

        const std::string queryDelete = "DELETE FROM persistent_queue WHERE operation = ? AND create_status = ?;";
        Statement stmtDelete(m_connection, queryDelete);
        stmtDelete.bind(1, static_cast<int>(Operation::DELETE));
        stmtDelete.bind(2, static_cast<int>(CreateStatus::DELETED_AFTER_CREATED));
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
