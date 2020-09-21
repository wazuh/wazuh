/*
 * Wazuh RSYNC
 * Copyright (C) 2015-2020, Wazuh Inc.
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


#include <iostream>

struct SmartDeleterJson final
{
    void operator()(cJSON * data)
    {
        cJSON_Delete(data);
    }
};

DBSYNC_HANDLE getDbsyncHandle(const nlohmann::json& config)
{
    const std::string dbName{ config.at("db_name") };
    const std::string dbType{ config.at("db_type") };
    const std::string hostType{ config.at("host_type") };        
    const std::string sqlStmt{ config.at("sql_statement") };
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
                         const std::string& outputFolder)
: m_rsyncHandle{ rsync_create() }
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
    const auto rsyncConfig{ config.at("rsync") };
    const std::unique_ptr<cJSON, SmartDeleterJson> jsRsyncConfig{ cJSON_Parse(rsyncConfig.dump().c_str()) };

    sync_callback_data_t callback{ rsyncCallback, this };
    if (rsync_register_sync_id(m_rsyncHandle, "OneTimeSync", m_dbSyncHandle, jsRsyncConfig.get(), callback))
    {
        throw std::runtime_error
        {
            "Error registering rsync id."
        };
    }
    if (rsync_start_sync(m_rsyncHandle))
    {
        throw std::runtime_error
        {
            "Error starting rsync handle."
        };
    }
}
OneTimeSync::~OneTimeSync()
{
    rsync_close(m_rsyncHandle);
}

void OneTimeSync::syncData()
{
    const std::unique_ptr<cJSON, SmartDeleterJson> jsSync{ cJSON_Parse(m_inputData[0].dump().c_str()) };
    callback_data_t callback { syncCallback, nullptr };

    dbsync_sync_row(m_dbSyncHandle, jsSync.get(), callback);
}
void OneTimeSync::rsyncCallback(const void* buffer, size_t bufferSize, void* userData)
{
    static unsigned int index{ 0 };
    OneTimeSync* object{ reinterpret_cast<OneTimeSync*>(userData) };
    if (object)
    {
        std::stringstream oFileName;
        oFileName << "action_" << index << ".json";
        const auto outputFileName{ object->m_outputFolder + "/" + oFileName.str() };
        std::ofstream outputFile{ outputFileName };
        const auto jsonResult
        {
            nlohmann::json::parse(std::string{reinterpret_cast<const char*>(buffer), bufferSize})
        };
        outputFile << jsonResult.dump() << std::endl;
        ++index;
    }
}

void OneTimeSync::syncCallback(ReturnTypeCallback /*result_type*/, const cJSON* /*result_json*/, void* /*user_data*/)
{

}
