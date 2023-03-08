/*
 * Wazuh RSYNC
 * Copyright (C) 2015, Wazuh Inc.
 * September 18, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "oneTimeSync.h"
#include <fstream>
#include <sstream>
#include "cjsonSmartDeleter.hpp"
#include <thread>

DBSYNC_HANDLE getDbsyncHandle(const nlohmann::json& config)
{
    const std::string dbName{ config.at("db_name").get_ref<const std::string&>() };
    const std::string dbType{ config.at("db_type").get_ref<const std::string&>() };
    const std::string hostType{ config.at("host_type").get_ref<const std::string&>() };
    const std::string sqlStmt{ config.at("sql_statement").get_ref<const std::string&>() };
    auto handle
    {
        dbsync_create((hostType.compare("0") == 0) ? HostType::MANAGER : HostType::AGENT,
                      (dbType.compare("1") == 0) ? DbEngineType::SQLITE3 : DbEngineType::UNDEFINED,
                      dbName.c_str(),
                      sqlStmt.c_str())
    };

    if (!handle)
    {
        throw std::runtime_error
        {
            "Error creating dbsync handle."
        };
    }

    return handle;
}

OneTimeSync::OneTimeSync(const nlohmann::json& config,
                         const nlohmann::json& inputData,
                         const std::string& outputFolder,
                         const size_t maxQueueSize)
    : m_rsyncHandle{ rsync_create(std::thread::hardware_concurrency(), maxQueueSize) }
    , m_dbSyncHandle{ getDbsyncHandle(config.at("dbsync")) }
    , m_inputData{ inputData }
    , m_outputFolder{ outputFolder }
{
    if (!m_rsyncHandle)
    {
        throw std::runtime_error
        {
            "Error creating rsync handle."
        };
    }

    const auto& rsyncRegConfig{ config.at("rsync_register_config") };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsRsyncRegConfig{ cJSON_Parse(rsyncRegConfig.dump().c_str()) };

    sync_callback_data_t callback{ rsyncCallback, this };

    if (rsync_register_sync_id(m_rsyncHandle, "OneTimeSync", m_dbSyncHandle, jsRsyncRegConfig.get(), callback))
    {
        throw std::runtime_error
        {
            "Error registering rsync id."
        };
    }

}
OneTimeSync::~OneTimeSync()
{
    rsync_close(m_rsyncHandle);
}

void OneTimeSync::syncData()
{
    const auto it{ m_inputData.find("dbsync") };

    if (it != m_inputData.end())
    {
        const std::unique_ptr<cJSON, CJsonSmartDeleter> jsSync{ cJSON_Parse(it->dump().c_str()) };
        callback_data_t callback { syncCallback, nullptr };

        if (dbsync_sync_row(m_dbSyncHandle, jsSync.get(), callback))
        {
            throw std::runtime_error
            {
                "Error in dbsync_sync_row."
            };
        }
    }
}

void OneTimeSync::pushData()
{
    const auto it{ m_inputData.find("rsync_push") };

    if (it != m_inputData.end())
    {
        for (const auto& push : *it)
        {
            const auto buffer{push.get<std::string>()};

            if (rsync_push_message(m_rsyncHandle,
                                   buffer.c_str(),
                                   buffer.size()))
            {
                throw std::runtime_error
                {
                    "Error in rsync_push_message."
                };
            }
        }
    }
}

void OneTimeSync::startSync()
{
    const auto it{ m_inputData.find("rsync_start_sync") };

    if (it != m_inputData.end())
    {
        sync_callback_data_t callback{ rsyncCallback, this };
        const std::unique_ptr<cJSON, CJsonSmartDeleter> jsSync{ cJSON_Parse(it->dump().c_str()) };

        if (rsync_start_sync(m_rsyncHandle,
                             m_dbSyncHandle,
                             jsSync.get(),
                             callback))
        {
            throw std::runtime_error
            {
                "Error in rsync_start_sync."
            };
        }
    }
}

void OneTimeSync::rsyncCallback(const void* buffer, size_t bufferSize, void* userData)
{
    static unsigned int index{ 0 };
    const OneTimeSync* object{ reinterpret_cast<OneTimeSync*>(userData) };

    if (object)
    {
        std::stringstream oFileName;
        oFileName << "action_" << index << ".json";
        ++index;
        const auto outputFileName{ object->m_outputFolder + "/" + oFileName.str() };
        std::ofstream outputFile{ outputFileName };
        const auto& jsonResult
        {
            nlohmann::json::parse(std::string{reinterpret_cast<const char*>(buffer), bufferSize})
        };
        outputFile << jsonResult.dump() << std::endl;
    }
}

void OneTimeSync::syncCallback(ReturnTypeCallback /*result_type*/, const cJSON* /*result_json*/, void* /*user_data*/)
{

}
