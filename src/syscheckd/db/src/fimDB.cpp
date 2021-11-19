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

#include "fimDB.hpp"

#define FIM_LOCATION      "syscheck"

void FIMDB::setFileLimit()
{
    try
    {
        m_dbsyncHandler->setTableMaxRow("file_entry", m_max_rows_file);
    }
    catch (DbSync::dbsync_error& err)
    {
        m_loggingFunction(LOG_ERROR, err.what());
    }
}

#ifdef WIN32
void FIMDB::setRegistryLimit()
{
    try
    {
        m_dbsyncHandler->setTableMaxRow("registry_key", m_max_rows_registry);
    }
    catch (DbSync::dbsync_error& err)
    {
        m_loggingFunction(LOG_ERROR, err.what());
    }
}

void FIMDB::setValueLimit()
{
    try
    {
        m_dbsyncHandler->setTableMaxRow("registry_data", m_max_rows_registry);
    }
    catch (DbSync::dbsync_error& err)
    {
        m_loggingFunction(LOG_ERROR, err.what());
    }
}
#endif

void FIMDB::registerRSync()
{
    // LCOV_EXCL_START
    const auto reportFimSyncWrapper
    {
        [this](const std::string & dataString)
        {
            m_syncMessageFunction(dataString);
            m_loggingFunction(LOG_DEBUG_VERBOSE, "Sync sent: " + dataString);
        }
    };
    // LCOV_EXCL_STOP

    try
    {
        m_rsyncHandler->registerSyncID("fim_file_sync",
                                       m_dbsyncHandler->handle(),
                                       nlohmann::json::parse(FIM_FILE_SYNC_CONFIG_STATEMENT),
                                       reportFimSyncWrapper);
#ifdef WIN32
        m_rsyncHandler->registerSyncID("fim_registry_sync",
                                       m_dbsyncHandler->handle(),
                                       nlohmann::json::parse(FIM_REGISTRY_SYNC_CONFIG_STATEMENT),
                                       reportFimSyncWrapper);

        m_rsyncHandler->registerSyncID("fim_value_sync",
                                       m_dbsyncHandler->handle(),
                                       nlohmann::json::parse(FIM_VALUE_SYNC_CONFIG_STATEMENT),
                                       reportFimSyncWrapper);

#endif
    }
    catch (std::exception& ex)
    {
        m_loggingFunction(LOG_ERROR, ex.what());
    }
}

void FIMDB::sync()
{
    try
    {
        m_loggingFunction(LOG_INFO, "Executing FIM sync.");
        m_rsyncHandler->startSync(m_dbsyncHandler->handle(), nlohmann::json::parse(FIM_FILE_START_CONFIG_STATEMENT), m_syncMessageFunction);
#ifdef WIN32
        m_rsyncHandler->startSync(m_dbsyncHandler->handle(), nlohmann::json::parse(FIM_REGISTRY_START_CONFIG_STATEMENT), m_syncMessageFunction);
        m_rsyncHandler->startSync(m_dbsyncHandler->handle(), nlohmann::json::parse(FIM_VALUE_START_CONFIG_STATEMENT), m_syncMessageFunction);
#endif
        m_loggingFunction(LOG_INFO, "Finished FIM sync.");
    }
    catch (const std::exception& ex)
    {
        m_loggingFunction(LOG_ERROR, ex.what());
    }
}

void FIMDB::loopRSync(std::unique_lock<std::mutex>& lock)
{
    m_loggingFunction(LOG_INFO, "FIM sync module started.");
    sync();

    while (!m_cv.wait_for(lock, std::chrono::seconds{m_interval_synchronization}, [&]()
{
    return m_stopping;
}))
    {
        sync();
    }
    m_rsyncHandler = nullptr;
}

#ifdef WIN32
void FIMDB::init(unsigned int interval_synchronization,
                 unsigned int max_rows_file,
                 unsigned int max_rows_registry,
                 fim_sync_callback_t callbackSync,
                 logging_callback_t callbackLog,
                 std::shared_ptr<DBSync> dbsyncHandler,
                 std::shared_ptr<RemoteSync> rsyncHanlder)
#else
void FIMDB::init(unsigned int interval_synchronization,
                 unsigned int max_rows_file,
                 fim_sync_callback_t callbackSync,
                 logging_callback_t callbackLog,
                 std::shared_ptr<DBSync> dbsyncHandler,
                 std::shared_ptr<RemoteSync> rsyncHanlder)
#endif
{
    // LCOV_EXCL_START
    std::function<void(const std::string&)> callbackSyncWrapper
    {
        [callbackSync](const std::string & msg)
        {
            callbackSync(FIM_LOCATION, msg.c_str());
        }
    };
    // LCOV_EXCL_STOP

    std::function<void(modules_log_level_t, const std::string&)> callbackLogWrapper
    {
        [callbackLog](modules_log_level_t level, const std::string & log)
        {
            callbackLog(level, log.c_str());
        }
    };

    m_interval_synchronization = interval_synchronization;
    m_max_rows_file = max_rows_file;
#ifdef WIN32
    m_max_rows_registry = max_rows_registry;
#endif
    m_dbsyncHandler = dbsyncHandler;
    m_rsyncHandler = rsyncHanlder;
    m_syncMessageFunction = callbackSyncWrapper;
    m_loggingFunction = callbackLogWrapper;
    m_stopping = false;

    setFileLimit();
#ifdef WIN32
    setRegistryLimit();
    setValueLimit();
#endif

}

dbQueryResult FIMDB::insertItem(const nlohmann::json& item)
{
    try
    {
        m_dbsyncHandler->insertData(item);
    }
    catch (const DbSync::max_rows_error& ex)
    {
        m_loggingFunction(LOG_INFO, ex.what());
        return dbQueryResult::MAX_ROWS_ERROR;
    }
    catch (const std::exception& ex)
    {
        m_loggingFunction(LOG_ERROR, ex.what());
        return dbQueryResult::DBSYNC_ERROR;
    }

    return dbQueryResult::SUCCESS;
}

dbQueryResult FIMDB::removeItem(const nlohmann::json& item)
{
    try
    {
        m_dbsyncHandler->deleteRows(item);
    }
    catch (const std::exception& ex)
    {
        m_loggingFunction(LOG_ERROR, ex.what());
        return dbQueryResult::DBSYNC_ERROR;
    }

    return dbQueryResult::SUCCESS;
}

dbQueryResult FIMDB::updateItem(const nlohmann::json& item, ResultCallbackData callbackData)
{
    try
    {
        m_dbsyncHandler->syncRow(item, callbackData);
    }
    catch (const DbSync::max_rows_error& ex)
    {
        m_loggingFunction(LOG_INFO, ex.what());
        return dbQueryResult::MAX_ROWS_ERROR;
    }
    catch (const std::exception& ex)
    {
        m_loggingFunction(LOG_ERROR, ex.what());
        return dbQueryResult::DBSYNC_ERROR;
    }

    return dbQueryResult::SUCCESS;
}

dbQueryResult FIMDB::executeQuery(const nlohmann::json& item, ResultCallbackData callbackData)
{
    try
    {
        m_dbsyncHandler->selectRows(item, callbackData);
    }
    catch (const DbSync::max_rows_error& ex)
    {
        m_loggingFunction(LOG_INFO, ex.what());
        return dbQueryResult::MAX_ROWS_ERROR;
    }
    catch (const std::exception& ex)
    {
        m_loggingFunction(LOG_ERROR, ex.what());
        return dbQueryResult::DBSYNC_ERROR;
    }

    return dbQueryResult::SUCCESS;
}
