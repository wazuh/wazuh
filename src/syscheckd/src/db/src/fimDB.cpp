/*
 * Wazuh Syscheck
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "fimDB.hpp"
#include "fimDBSpecialization.h"
#include <future>

void FIMDB::init(std::function<void(modules_log_level_t, const std::string&)> callbackLogWrapper,
                 std::shared_ptr<DBSync> dbsyncHandler,
                 const int fileLimit,
                 const int registryLimit)
{
    std::lock_guard<std::shared_timed_mutex> lock(m_handlersMutex);
    m_dbsyncHandler = std::move(dbsyncHandler);
    m_loggingFunction = std::move(callbackLogWrapper);
    m_stopping = false;
    FIMDBCreator<OS_TYPE>::setLimits(m_dbsyncHandler, fileLimit, registryLimit);
}

void FIMDB::removeItem(const nlohmann::json& item)
{
    removeItem(item, []() {});
}

void FIMDB::removeItem(const nlohmann::json& item, const std::function<void()>& afterRemove)
{
    // The lock is kept until the removal is reported, like updateItem() does with its callback, so
    // quiesce() and setTableVersion() never run between the two.
    std::shared_lock<std::shared_timed_mutex> lock(m_handlersMutex);

    if (!m_stopping && m_dbsyncHandler)
    {
        m_dbsyncHandler->deleteRows(item);
        afterRemove();
    }
}

void FIMDB::updateItem(const nlohmann::json& item, ResultCallbackData& callbackData)
{
    std::shared_lock<std::shared_timed_mutex> lock(m_handlersMutex);

    if (!m_stopping && m_dbsyncHandler)
    {
        m_dbsyncHandler->syncRow(item, callbackData);
    }
}

void FIMDB::executeQuery(const nlohmann::json& item, ResultCallbackData& callbackData)
{
    std::shared_ptr<DBSync> dbsyncHandler;

    {
        std::shared_lock<std::shared_timed_mutex> lock(m_handlersMutex);

        if (!m_stopping)
        {
            dbsyncHandler = m_dbsyncHandler;
        }
    }

    // The callbacks may query or update FIMDB again, so the lock is not held while they run
    if (dbsyncHandler)
    {
        dbsyncHandler->selectRows(item, callbackData);
    }
    else if (m_loggingFunction)
    {
        m_loggingFunction(LOG_DEBUG, "Query not executed: FIMDB is not initialized or is shutting down");
    }
}

bool FIMDB::setTableVersion(const std::string& table, const int version, const std::chrono::milliseconds timeout)
{
    // Exclusive: updateItem() and removeItem() hold the lock shared from the row write to the end
    // of its callback, so the version is never set between a row write and the queueing of its event.
    std::unique_lock<std::shared_timed_mutex> lock(m_handlersMutex, timeout);

    if (!lock.owns_lock() || m_stopping || !m_dbsyncHandler)
    {
        return false;
    }

    m_dbsyncHandler->setEachEntryVersion(table, version);
    return true;
}

void FIMDB::quiesce()
{
    m_stopping = true;
    // Taken and released: the row writes in flight finish with their callback, later ones do nothing.
    std::lock_guard<std::shared_timed_mutex> lock(m_handlersMutex);
}

void FIMDB::teardown()
{

    try
    {
        m_stopping = true;
        std::lock_guard<std::shared_timed_mutex> lock(m_handlersMutex);
        m_dbsyncHandler = nullptr;
    }
    // LCOV_EXCL_START
    catch (const std::exception& ex)
    {
        auto errmsg {"There is a problem to close FIMDB " + std::string(ex.what())};
        m_loggingFunction(LOG_ERROR, errmsg);
    }

    // LCOV_EXCL_STOP
}

void FIMDB::closeAndDeleteDatabase()
{
    try
    {
        m_stopping = true;
        std::lock_guard<std::shared_timed_mutex> lock(m_handlersMutex);

        if (m_dbsyncHandler)
        {
            m_dbsyncHandler->closeAndDeleteDatabase();
            m_dbsyncHandler = nullptr;
        }
    }
    // LCOV_EXCL_START
    catch (const std::exception& ex)
    {
        auto errmsg {"There is a problem to close and delete FIMDB " + std::string(ex.what())};
        m_loggingFunction(LOG_ERROR, errmsg);
    }

    // LCOV_EXCL_STOP
}
