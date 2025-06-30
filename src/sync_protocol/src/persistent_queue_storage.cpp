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

void PersistentQueueStorage::save(const std::string& module, const PersistedData& data)
{
    try
    {
        const std::string query =
            "INSERT INTO persistent_queue (seq, module, id, idx, data, operation)"
            " VALUES (?, ?, ?, ?, ?, ?);";

        Statement stmt(m_connection, query);
        stmt.bind(1, data.seq);
        stmt.bind(2, module);
        stmt.bind(3, data.id);
        stmt.bind(4, data.index);
        stmt.bind(5, data.data);
        stmt.bind(6, static_cast<int>(data.operation));
        stmt.step();
    }
    catch (const Sqlite3Error& ex)
    {
        std::cerr << "[PersistentQueueStorage] SQLite error: " << ex.what() << std::endl;
        throw;
    }
}

void PersistentQueueStorage::remove(const std::string& module, uint64_t sequence)
{
    try
    {
        const std::string query =
            "DELETE FROM persistent_queue WHERE seq = ? AND module = ?;";

        Statement stmt(m_connection, query);
        stmt.bind(1, static_cast<int64_t>(sequence));
        stmt.bind(2, module);
        stmt.step();
    }
    catch (const Sqlite3Error& ex)
    {
        std::cerr << "[PersistentQueueStorage] SQLite error: " << ex.what() << std::endl;
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
