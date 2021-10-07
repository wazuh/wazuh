/*
 * Wazuh SysCollector
 * Copyright (C) 2015-2021, Wazuh Inc.
 * September 27, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef _FIMDB_CPP
#define _FIMDB_CPP
#include "fimDB.hpp"
#include "dbsync.hpp"
#include "rsync.hpp"
#include "syscheck.h"
#include "db_statements.hpp"
#include "loggingHelper.h"


std::string createStatement()
{
    std::string ret = CREATE_FILE_DB_STATEMENT;
#ifdef WIN32
    ret += CREATE_REGISTRY_KEY_DB_STATEMENT;
    ret += CREATE_REGISTRY_VALUE_DB_STATEMENT;
#endif

    return ret;
}

void setFileLimit()
{
    m_dbsyncHandler->setTableMaxRow("file_entry", syscheck.file_limit);
}

void setRegistryLimit()
{
    m_dbsyncHandler->setTableMaxRow("registry_key", syscheck.value_limit);
}

void setValueLimit()
{
    m_dbsyncHandler->setTableMaxRow("registry_data", syscheck.value_limit);
}

void FIMDB::init(const std::string& dbPath)
{
    m_dbsyncHandler = std::make_unique<DBSync>(HostType::AGENT, DbEngineType::SQLITE3, dbPath, createStatement());
    m_rsyncHandler = std::make_unique<RemoteSync>();

    setFileLimit();
#ifdef WIN32
    setRegistryLimit();
    setValueLimit();
#endif
}

int insertItem(std::unique_ptr<DBItem> const item)
{
    try
    {
        m_dbsyncHandler->insertData(item.toJson());
    }
    catch(const DbSync::max_rows_error &ex)
    {
        logging_function(LOG_INFO, ex.what());
        return 1;
    }
    catch(const std::exception &ex)
    {
        logging_function(LOG_ERROR, ex.what());
        return 2;
    }

    return 0;
}

int removeItem(DBItem* item)
{
    try
    {
        m_dbsyncHandler->deleteRows(item.toJson());
    }
    catch(const DbSync::max_rows_error &ex)
    {
        logging_function(LOG_INFO, ex.what());
        return 1;
    }
    catch(const std::exception &ex)
    {
        logging_function(LOG_ERROR, ex.what());
        return 2;
    }

    return 0;
}

int updateItem(DBItem* item, ResultCallbackData callbackData)
{
    try
    {
        m_dbsyncHandler->syncRow(item.toJson(), callbackData);
    }
    catch(const DbSync::max_rows_error &ex)
    {
        logging_function(LOG_INFO, ex.what());
        return 1;
    }
    catch(const std::exception &ex)
    {
        logging_function(LOG_ERROR, ex.what());
        return 2;
    }

    return 0;
}


void registerRsync()
{
    const auto reportFimWrapper
    {
        // [this](const std::string & dataString)
        // {
        //     auto jsonData(nlohmann::json::parse(dataString));
        //     auto it{jsonData.find("data")};

        //     if (!m_stopping)
        //     {
        //         if (it != jsonData.end())
        //         {
        //             auto& data{*it};
        //             it = data.find("attributes");

        //             if (it != data.end())
        //             {
        //                 auto& fieldData { *it };
        //                 removeKeysWithEmptyValue(fieldData);
        //                 fieldData["scan_time"] = Utils::getCurrentTimestamp();
        //                 const auto msgToSend{jsonData.dump()};
        //                 m_reportSyncFunction(msgToSend);
        //                 m_logFunction(LOG_DEBUG_VERBOSE, "Sync sent: " + msgToSend);
        //             }
        //             else
        //             {
        //                 m_reportSyncFunction(dataString);
        //                 m_logFunction(LOG_DEBUG_VERBOSE, "Sync sent: " + dataString);
        //             }
        //         }
        //         else
        //         {
        //             //LCOV_EXCL_START
        //             m_reportSyncFunction(dataString);
        //             m_logFunction(LOG_DEBUG_VERBOSE, "Sync sent: " + dataString);
        //             //LCOV_EXCL_STOP
        //         }
        //     }
        // }
    };

    try
    {
        m_rsyncHandler->registerSyncID("fim_sync",
                                       m_spDBSync->handle(),
                                       nlohmann::json::parse(OS_SYNC_CONFIG_STATEMENT),
                                       reportSyncWrapper);
    }

}

void loopRsync()
{
//     m_logFunction(LOG_INFO, "Module started.");

//     if (m_scanOnStart)
//     {
//         scan();
//         sync();
//     }

//     while (!m_cv.wait_for(lock, std::chrono::seconds{m_intervalValue}, [&]()
// {
//     return m_stopping;
// }))
//     {
//         scan();
//         sync();
//     }
//     m_spRsync.reset(nullptr);
//     m_spDBSync.reset(nullptr);
}

#endif
