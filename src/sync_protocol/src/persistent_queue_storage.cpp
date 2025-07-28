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
            "module TEXT NOT NULL,"
            "seq INTEGER NOT NULL,"
            "id TEXT NOT NULL,"
            "idx TEXT NOT NULL,"
            "data TEXT NOT NULL,"
            "operation INTEGER NOT NULL,"
            "PRIMARY KEY (module, seq));";

        m_connection.execute(query);
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[PersistentQueueStorage] SQLite error: " << ex.what() << std::endl;
        throw;
    }
}

size_t PersistentQueueStorage::save(const std::string& module, const PersistedData& data)
{
    try
    {
        m_connection.execute("BEGIN IMMEDIATE TRANSACTION;");

        const std::string insertQuery =
            "INSERT INTO persistent_queue (seq, module, id, idx, data, operation)"
            " VALUES (?, ?, ?, ?, ?, ?);";

        Statement insertStmt(m_connection, insertQuery);
        insertStmt.bind(1, data.seq);
        insertStmt.bind(2, module);
        insertStmt.bind(3, data.id);
        insertStmt.bind(4, data.index);
        insertStmt.bind(5, data.data);
        insertStmt.bind(6, static_cast<int>(data.operation));
        insertStmt.step();

        const std::string countQuery = "SELECT COUNT(*) FROM persistent_queue WHERE module = ?;";
        Statement countStmt(m_connection, countQuery);
        countStmt.bind(1, module);

        size_t count = 0;

        if (countStmt.step() == SQLITE_ROW)
        {
            count = countStmt.value<int64_t>(0);
        }

        m_connection.execute("COMMIT;");

        return count;
    }
    catch (const Sqlite3Error& ex)
    {
        std::cerr << "[PersistentQueueStorage] SQLite transaction failed, rolling back. Error: " << ex.what() << std::endl;

        try
        {
            m_connection.execute("ROLLBACK;");
        }
        catch (const Sqlite3Error& rollback_ex)
        {
            std::cerr << "[PersistentQueueStorage] CRITICAL: Failed to rollback transaction: " << rollback_ex.what() << std::endl;
        }

        throw;
    }
}

void PersistentQueueStorage::removeAll(const std::string& module)
{
    try
    {
        const std::string query = "DELETE FROM persistent_queue WHERE module = ?;";
        Statement stmt(m_connection, query);
        stmt.bind(1, module);
        stmt.step();
    }
    catch (const Sqlite3Error& ex)
    {
        std::cerr << "[PersistentQueueStorage] SQLite error: " << ex.what() << std::endl;
        throw;
    }
}

std::vector<PersistedData> PersistentQueueStorage::loadAll(const std::string& module)
{
    std::vector<PersistedData> result;

    try
    {
        const std::string query =
            "SELECT seq, id, idx, data, operation FROM persistent_queue WHERE module = ? ORDER BY seq ASC;";

        Statement stmt(m_connection, query);
        stmt.bind(1, module);

        while (stmt.step() == SQLITE_ROW)
        {
            PersistedData data;
            data.seq = stmt.value<uint64_t>(0);
            data.id = stmt.value<std::string>(1);
            data.index = stmt.value<std::string>(2);
            data.data = stmt.value<std::string>(3);
            data.operation = static_cast<Wazuh::SyncSchema::Operation>(stmt.value<int>(4));
            result.emplace_back(std::move(data));
        }
    }
    catch (const Sqlite3Error& ex)
    {
        std::cerr << "[PersistentQueueStorage] SQLite error: " << ex.what() << std::endl;
        throw;
    }

    return result;
}
