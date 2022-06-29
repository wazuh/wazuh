/*
 * Wazuh Syscheck
 * Copyright (C) 2015, Wazuh Inc.
 * September 27, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "fimDB.hpp"
#include "fimDBSpecialization.h"
#include "promiseFactory.h"
#include <future>


void FIMDB::registerRSync()
{
    std::shared_lock<std::shared_timed_mutex> lock(m_handlersMutex);

    if (!m_stopping)
    {
        FIMDBCreator<OS_TYPE>::registerRsync(m_rsyncHandler,
                                             m_dbsyncHandler->handle(),
                                             m_syncFileMessageFunction,
                                             m_minSyncIntervalTime,
                                             m_syncRegistryMessageFunction,
                                             m_syncRegistryEnabled);
    }
}

void FIMDB::sync()
{
    std::shared_lock<std::shared_timed_mutex> lock(m_handlersMutex);

    if (!m_stopping)
    {
        m_loggingFunction(LOG_DEBUG, "Executing FIM sync.");
        FIMDBCreator<OS_TYPE>::sync(m_rsyncHandler,
                                    m_dbsyncHandler->handle(),
                                    m_syncFileMessageFunction,
                                    m_syncRegistryMessageFunction,
                                    m_syncRegistryEnabled);
        m_loggingFunction(LOG_DEBUG, "Finished FIM sync.");
    }
}

void FIMDB::init(unsigned int syncInterval,
                 std::function<void(const std::string&)> callbackSyncFileWrapper,
                 std::function<void(const std::string&)> callbackSyncRegistryWrapper,
                 std::function<void(modules_log_level_t, const std::string&)> callbackLogWrapper,
                 std::shared_ptr<DBSync> dbsyncHandler,
                 std::shared_ptr<RemoteSync> rsyncHandler,
                 const int fileLimit,
                 const uint32_t minSyncIntervalTime,
                 const int registryLimit,
                 const bool syncRegistryEnabled,
                 int syncQueueSize)
{
    m_syncInterval = syncInterval;
    m_dbsyncHandler = dbsyncHandler;
    m_rsyncHandler = rsyncHandler;
    m_syncFileMessageFunction = callbackSyncFileWrapper;
    m_syncRegistryMessageFunction = callbackSyncRegistryWrapper;
    m_loggingFunction = callbackLogWrapper;
    m_stopping = false;
    m_runIntegrity = false;
    std::shared_lock<std::shared_timed_mutex> lock(m_handlersMutex);
    FIMDBCreator<OS_TYPE>::setLimits(m_dbsyncHandler, fileLimit, registryLimit);
    m_syncRegistryEnabled = syncRegistryEnabled;
    m_minSyncIntervalTime = minSyncIntervalTime;
}

void FIMDB::removeItem(const nlohmann::json& item)
{
    std::shared_lock<std::shared_timed_mutex> lock(m_handlersMutex);

    if (!m_stopping)
    {
        m_dbsyncHandler->deleteRows(item);
    }
}

void FIMDB::updateItem(const nlohmann::json& item, ResultCallbackData callbackData)
{
    std::shared_lock<std::shared_timed_mutex> lock(m_handlersMutex);

    if (!m_stopping)
    {
        m_dbsyncHandler->syncRow(item, callbackData);
    }
}

void FIMDB::executeQuery(const nlohmann::json& item, ResultCallbackData callbackData)
{
    m_dbsyncHandler->selectRows(item, callbackData);
}

void FIMDB::runIntegrity()
{
    std::lock_guard<std::mutex> lock{m_fimSyncMutex};

    if (!m_runIntegrity)
    {
        m_runIntegrity = true;
        registerRSync();
        auto promise { PromiseFactory<PROMISE_TYPE>::getPromiseObject() };
        m_integrityThread = std::thread([&]()
        {
            m_loggingFunction(LOG_INFO, "FIM sync module started.");
            sync();
            promise->set_value();
            std::unique_lock<std::mutex> lockCv{m_fimSyncMutex};

            while (!m_cv.wait_for(lockCv, std::chrono::seconds{m_syncInterval}, [&]()
        {
            return m_stopping;
        }))
            {
                // LCOV_EXCL_START
                sync();
                // LCOV_EXCL_STOP
            }
        });
        promise->wait();

    }
    else
    {
        throw std::runtime_error("FIM integrity thread already running.");
    }
}

void FIMDB::pushMessage(const std::string& data)
{
    std::shared_lock<std::shared_timed_mutex> lock(m_handlersMutex);

    if (!m_stopping)
    {
        auto rawData{data};
        Utils::replaceFirst(rawData, "dbsync ", "");
        const auto buff{reinterpret_cast<const uint8_t*>(rawData.c_str())};

        try
        {
            m_rsyncHandler->pushMessage(std::vector<uint8_t> {buff, buff + rawData.size()});
        }
        // LCOV_EXCL_START
        catch (const std::exception& ex)
        {
            m_loggingFunction(LOG_ERROR, ex.what());
        }

        // LCOV_EXCL_STOP
    }
}

void FIMDB::teardown()
{
    std::unique_lock<std::shared_timed_mutex> lock(m_handlersMutex);

    try
    {
        stopIntegrity();
        m_rsyncHandler = nullptr;
        m_dbsyncHandler = nullptr;
    }
    // LCOV_EXCL_START
    catch (const std::exception& ex)
    {
        auto errmsg { "There is a problem to close FIMDB " + std::string(ex.what()) };
        m_loggingFunction(LOG_ERROR, errmsg);
    }

    // LCOV_EXCL_STOP
}
