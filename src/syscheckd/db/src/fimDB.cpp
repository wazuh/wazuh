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

void FIMDB::registerRSync()
{
    m_rsyncHandler->registerSyncID("fim_file",
                                    m_dbsyncHandler->handle(),
                                    nlohmann::json::parse(FIM_FILE_SYNC_CONFIG_STATEMENT),
                                    m_syncFileMessageFunction);
#ifdef WIN32
    m_rsyncHandler->registerSyncID("fim_registry",
                                    m_dbsyncHandler->handle(),
                                    nlohmann::json::parse(FIM_REGISTRY_SYNC_CONFIG_STATEMENT),
                                    m_syncRegistryMessageFunction);
#endif
}

void FIMDB::sync()
{
    m_loggingFunction(LOG_INFO, "Executing FIM sync.");
    m_rsyncHandler->startSync(m_dbsyncHandler->handle(), nlohmann::json::parse(FIM_FILE_START_CONFIG_STATEMENT), m_syncFileMessageFunction);
#ifdef WIN32
    m_rsyncHandler->startSync(m_dbsyncHandler->handle(), nlohmann::json::parse(FIM_REGISTRY_START_CONFIG_STATEMENT), m_syncRegistryMessageFunction);
#endif
    m_loggingFunction(LOG_INFO, "Finished FIM sync.");
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
    std::function<void(const std::string&)> callbackSyncFileWrapper
    {
        [callbackSync](const std::string & msg)
        {
            callbackSync(FIM_COMPONENT_FILE, msg.c_str());
        }
    };

    std::function<void(const std::string&)> callbackSyncRegistryWrapper
    {
        [callbackSync](const std::string & msg)
        {
            callbackSync(FIM_COMPONENT_REGISTRY, msg.c_str());
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
    m_syncFileMessageFunction = callbackSyncFileWrapper;
    m_syncRegistryMessageFunction = callbackSyncRegistryWrapper;
    m_loggingFunction = callbackLogWrapper;
    m_stopping = false;

    setFileLimit();
#ifdef WIN32
    setRegistryLimit();
    setValueLimit();
#endif

}

void FIMDB::insertItem(const nlohmann::json& item)
{
    m_dbsyncHandler->insertData(item);
}

void FIMDB::removeItem(const nlohmann::json& item)
{
    m_dbsyncHandler->deleteRows(item);

}

void FIMDB::updateItem(const nlohmann::json& item, ResultCallbackData callbackData)
{
    m_dbsyncHandler->syncRow(item, callbackData);
}

void FIMDB::executeQuery(const nlohmann::json& item, ResultCallbackData callbackData)
{
    m_dbsyncHandler->selectRows(item, callbackData);
}

void FIMDB::fimRunIntegrity()
{
    std::unique_lock<std::mutex> lock{m_fimSyncMutex};

    registerRSync();
    loopRSync(lock);
}

void FIMDB::fimSyncPushMsg(const std::string& data)
{
    std::unique_lock<std::mutex> lock{m_fimSyncMutex};

    if (!m_stopping)
    {
        auto rawData{data};
        const auto buff{reinterpret_cast<const uint8_t*>(rawData.c_str())};

        try
        {
            m_rsyncHandler->pushMessage(std::vector<uint8_t> {buff, buff + rawData.size()});
            m_loggingFunction(LOG_DEBUG_VERBOSE, "Message pushed: " + data);
        }
        // LCOV_EXCL_START
        catch (const std::exception& ex)
        {
            m_loggingFunction(LOG_ERROR, ex.what());
        }
    }
    // LCOV_EXCL_STOP
}
