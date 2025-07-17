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
#include <future>


void FIMDB::init(std::function<void(modules_log_level_t, const std::string&)> callbackLogWrapper,
                 std::shared_ptr<DBSync> dbsyncHandler,
                 const int fileLimit,
                 const int registryLimit)
{
    m_dbsyncHandler = dbsyncHandler;
    m_loggingFunction = callbackLogWrapper;
    m_stopping = false;
    std::shared_lock<std::shared_timed_mutex> lock(m_handlersMutex);
    FIMDBCreator<OS_TYPE>::setLimits(m_dbsyncHandler, fileLimit, registryLimit);
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
        auto errmsg { "There is a problem to close FIMDB " + std::string(ex.what()) };
        m_loggingFunction(LOG_ERROR, errmsg);
    }

    // LCOV_EXCL_STOP
}
