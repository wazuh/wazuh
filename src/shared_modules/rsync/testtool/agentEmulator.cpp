/*
 * Wazuh RSYNC
 * Copyright (C) 2015, Wazuh Inc.
 * August 28, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include <iostream>
#include <iomanip>
#include <ctime>
#include <cstdlib>
#include "agentEmulator.h"
#include "cjsonSmartDeleter.hpp"


constexpr auto CREATE_STATEMENT { "CREATE TABLE data_values(`key` BIGINT, `data1` BIGINT, `data2` BIGINT, `data3` BIGINT, PRIMARY KEY (`key`)) WITHOUT ROWID;"};

static DBSYNC_HANDLE createDbsyncHandle(const std::string& dbName)
{
    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, dbName.c_str(), CREATE_STATEMENT) };

    if (!handle)
    {
        throw std::runtime_error
        {
            "Error creating dbsync handle."
        };
    }

    return handle;
}

static void callback(const ReturnTypeCallback /*type*/,
                     const cJSON* /*json*/,
                     void* /*ctx*/)
{
    // const std::unique_ptr<char, CJsonSmartFree> spJsonBytes{ cJSON_PrintUnformatted(json) };
    // std::cout << spJsonBytes.get() << std::endl;
}

AgentEmulator::AgentEmulator(const std::chrono::milliseconds updatePeriod,
                             const unsigned int maxDbItems,
                             const std::shared_ptr<SyncQueue>& outQueue,
                             const std::string& dbFolder,
                             const size_t maxQueueSize)
    : m_agentId{ std::to_string(reinterpret_cast<unsigned long>(this)) }
    , m_rsyncHandle{ rsync_create(std::thread::hardware_concurrency(), maxQueueSize) }
    , m_dbSyncHandle{ createDbsyncHandle(dbFolder + m_agentId + ".db") }
    , m_config{ nullptr }//TODO: define config based on dbsync handle create statement
    , m_startConfig{ nullptr }//TODO: define config based on first/last sync information statement
    , m_updatePeriod {updatePeriod}
    , m_maxDbItems{ maxDbItems }
    , m_threadsRunning{ true }
    , m_outQueue{ outQueue }
{
    if (!m_rsyncHandle)
    {
        throw std::runtime_error
        {
            "Error creating rsync handle."
        };
    }

    sync_callback_data_t callback{agentEmulatorSyncCallback, this};

    if (rsync_register_sync_id(m_rsyncHandle, m_agentId.c_str(), m_dbSyncHandle, m_config, callback))
    {
        throw std::runtime_error
        {
            "Error registering rsync id."
        };
    }

    if (rsync_start_sync(m_rsyncHandle, m_dbSyncHandle, m_startConfig, callback))
    {
        throw std::runtime_error
        {
            "Error starting rsync handle."
        };
    }

    m_updateThread = std::thread{&AgentEmulator::updateData, this};
}

AgentEmulator::~AgentEmulator()
{
    m_threadsRunning = false;

    if (m_updateThread.joinable())
    {
        m_updateThread.join();
    }

    rsync_close(m_rsyncHandle);
}

void AgentEmulator::updateData()
{
    std::srand(std::time(0));

    while (m_threadsRunning)
    {
        const auto key{std::to_string(std::rand() % m_maxDbItems)};
        const auto data1{std::to_string(std::rand())};
        const auto data2{std::to_string(std::rand())};
        const auto data3{std::to_string(std::rand())};
        const std::string dataToSync
        {
            R"({"table":"data_values","data":[{"key":)" + key + R"(, "data1":)" + data1 + R"(, "data2":)" + data2 + R"(, "data3":)" + data3 + R"(}]})"
        };
        const std::unique_ptr<cJSON, CJsonSmartDeleter> jsSync{ cJSON_Parse(dataToSync.c_str()) };
        callback_data_t callbackData { callback, nullptr };

        dbsync_sync_row(m_dbSyncHandle, jsSync.get(), callbackData);

        std::this_thread::sleep_for(m_updatePeriod);
    }
}

void AgentEmulator::syncData(const void* buffer, size_t bufferSize)
{
    std::cout << "AGENT: sync." << std::endl;
    const auto first{reinterpret_cast<const unsigned char*>(buffer)};
    const auto last{first + bufferSize};
    const auto data
    {
        std::make_pair<SyncId, SyncData>(RSYNC_HANDLE{m_rsyncHandle}, SyncData{first, last})
    };
    m_outQueue->push(data);
}

void AgentEmulator::agentEmulatorSyncCallback(const void* buffer, size_t bufferSize, void* userData)
{
    AgentEmulator* agent{ reinterpret_cast<AgentEmulator*>(userData) };

    if (agent)
    {
        agent->syncData(buffer, bufferSize);
    }
}
