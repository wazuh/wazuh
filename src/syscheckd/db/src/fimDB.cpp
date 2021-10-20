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

#define FIM_COMPONENT_FILE      "fim_file"
#define FIM_COMPONENT_REGISTRY  "fim_registry"

std::string FIMDB::createStatement()
{
    std::string ret = CREATE_FILE_DB_STATEMENT;
#ifdef WIN32
    ret += CREATE_REGISTRY_KEY_DB_STATEMENT;
    ret += CREATE_REGISTRY_VALUE_DB_STATEMENT;
#endif

    return ret;
}

void FIMDB::setFileLimit()
{
    m_dbsyncHandler->setTableMaxRow("file_entry", m_max_rows_file);
}

#ifdef WIN32
void FIMDB::setRegistryLimit()
{
    m_dbsyncHandler->setTableMaxRow("registry_key", m_max_rows_registry);
}

void FIMDB::setValueLimit()
{
    m_dbsyncHandler->setTableMaxRow("registry_data", m_max_rows_registry);
}
#endif

#ifdef WIN32
void FIMDB::init(const std::string& dbPath,
                 const unsigned int interval_synchronization,
                 const unsigned int max_rows_file,
                 const unsigned int max_rows_registry,
                 const std::function<void(const std::string&, const std::string&)>  syncMessageFunction,
                 const std::function<void(const modules_log_level_t, const std::string&)> m_loggingFunction)
#else
void FIMDB::init(const std::string& dbPath,
                 const unsigned int interval_synchronization,
                 const unsigned int max_rows_file,
                 const std::function<void(const std::string&, const std::string&)>  syncMessageFunction,
                 const std::function<void(const modules_log_level_t, const std::string&)> m_loggingFunction)
#endif
{
    m_interval_synchronization = interval_synchronization
    m_max_rows_file = max_rows_file;
#ifdef WIN32
    m_max_rows_registry = max_rows_registry;
#endif
    m_dbsyncHandler = std::make_unique<DBSync>(HostType::AGENT, DbEngineType::SQLITE3, dbPath, createStatement());
    m_rsyncHandler = std::make_unique<RemoteSync>();
    m_syncMessageFunction = syncMessageFunction;
    m_loggingFunction = loggingFunction;

    setFileLimit();
#ifdef WIN32
    setRegistryLimit();
    setValueLimit();
#endif

    std::unique_lock<std::mutex> lock{m_mutex};

    registerRsync();
    loopRsync(lock);
}

int FIMDB::insertItem(DBItem const &item)
{
    try
    {
        m_dbsyncHandler->insertData(item.toJson());
    }
    catch(const DbSync::max_rows_error &ex)
    {
        m_loggingFunction(LOG_INFO, ex.what());
        return 1;
    }
    catch(const std::exception &ex)
    {
        m_loggingFunction(LOG_ERROR, ex.what());
        return 2;
    }

    return 0;
}

int FIMDB::removeItem(DBItem const &item)
{
    try
    {
        m_dbsyncHandler->deleteRows(item.toJson());
    }
    catch(const DbSync::max_rows_error &ex)
    {
        m_loggingFunction(LOG_INFO, ex.what());
        return 1;
    }
    catch(const std::exception &ex)
    {
        m_loggingFunction(LOG_ERROR, ex.what());
        return 2;
    }

    return 0;
}

int FIMDB::updateItem(DBItem const &item, ResultCallbackData callbackData)
{
    try
    {
        m_dbsyncHandler->syncRow(item.toJson(), callbackData);
    }
    catch(const DbSync::max_rows_error &ex)
    {
        m_loggingFunction(LOG_INFO, ex.what());
        return 1;
    }
    catch(const std::exception &ex)
    {
        m_loggingFunction(LOG_ERROR, ex.what());
        return 2;
    }

    return 0;
}

void FIMDB::registerRsync()
{
    const auto reportFileSyncWrapper
    {
        [this](const std::string & dataString)
        {
            m_syncMessageFunction(FIM_COMPONENT_FILE, dataString);
            m_loggingFunction(LOG_DEBUG_VERBOSE, "Sync sent: " + dataString);
        }
    };

    m_rsyncHandler->registerSyncID("fim_file_sync",
                                    m_dbsyncHandler->handle(),
                                    nlohmann::json::parse(FIM_FILE_SYNC_CONFIG_STATEMENT),
                                    reportFileSyncWrapper);

#ifdef WIN32
    const auto reportRegistrySyncWrapper
    {
        [this](const std::string & dataString)
        {
            m_syncMessageFunction(FIM_COMPONENT_REGISTRY, dataString);
            m_loggingFunction(LOG_DEBUG_VERBOSE, "Sync sent: " + dataString);
        }
    };

    m_rsyncHandler->registerSyncID("fim_registry_sync",
                                    m_dbsyncHandler->handle(),
                                    nlohmann::json::parse(FIM_REGISTRY_SYNC_CONFIG_STATEMENT),
                                    reportRegistrySyncWrapper);

    m_rsyncHandler->registerSyncID("fim_value_sync",
                                    m_dbsyncHandler->handle(),
                                    nlohmann::json::parse(FIM_VALUE_SYNC_CONFIG_STATEMENT),
                                    reportRegistrySyncWrapper);
#endif
}

void FIMDB::loopRsync(std::unique_lock<std::mutex>& lock)
{
    m_logFunction(LOG_INFO, "FIM sync module started.");

    m_rsyncHandler->startSync(m_dbsyncHandler->handle(), nlohmann::json::parse(FIM_FILE_START_CONFIG_STATEMENT), m_reportSyncFunction);
#ifdef WIN32
    m_rsyncHandler->startSync(m_dbsyncHandler->handle(), nlohmann::json::parse(FIM_REGISTRY_START_CONFIG_STATEMENT), m_reportSyncFunction);
    m_rsyncHandler->startSync(m_dbsyncHandler->handle(), nlohmann::json::parse(FIM_VALUE_START_CONFIG_STATEMENT), m_reportSyncFunction);
#endif
    while (!m_cv.wait_for(lock, std::chrono::seconds{m_interval_synchronization}, [&]()
{
    return m_stopping;
}))
    {
        m_logFunction(LOG_INFO, "Executing FIM sync.");
        m_rsyncHandler->startSync(m_dbsyncHandler->handle(), nlohmann::json::parse(FIM_FILE_START_CONFIG_STATEMENT), m_reportSyncFunction);
#ifdef WIN32
        m_rsyncHandler->startSync(m_dbsyncHandler->handle(), nlohmann::json::parse(FIM_REGISTRY_START_CONFIG_STATEMENT), m_reportSyncFunction);
        m_rsyncHandler->startSync(m_dbsyncHandler->handle(), nlohmann::json::parse(FIM_VALUE_START_CONFIG_STATEMENT), m_reportSyncFunction);
#endif
        m_logFunction(LOG_INFO, "Finished FIM sync.");
    }
    m_rsyncHandler.reset(nullptr);
}

#endif
