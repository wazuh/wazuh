/*
 * Wazuh DBSYNC
 * Copyright (C) 2015-2020, Wazuh Inc.
 * June 11, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "dbsync_implementation.h"
#include <iostream>

DBSYNC_HANDLE DBSyncImplementation::initialize(const HostType hostType,
                                               const DbEngineType dbType,
                                               const std::string& path,
                                               const std::string& sqlStatement)
{
    DBSYNC_HANDLE retVal { nullptr };
    try
    {
        auto db{ FactoryDbEngine::Create(dbType, path, sqlStatement) };
        std::lock_guard<std::mutex> lock{m_mutex};
        m_dbSyncContexts.push_back(std::make_shared<DbEngineContext>(
          db,
          hostType,
          dbType
        ));
        retVal = m_dbSyncContexts.back().get();
    }
    catch (const std::exception& ex)
    {
        std::cout << ex.what() << std::endl;
    }
    return retVal;
}

void DBSyncImplementation::release()
{
    std::lock_guard<std::mutex> lock{m_mutex};
    m_dbSyncContexts.clear();
}

int32_t DBSyncImplementation::insertBulkData(const DBSYNC_HANDLE handle,
                                             const char* jsonRaw)
{
    auto retVal { -1 };
    try
    {
        const auto ctx{ getDbEngineContext(handle) };
        const auto json { nlohmann::json::parse(jsonRaw)};
        retVal = ctx->GetDbEngine()->BulkInsert(json[0]["table"], json[0]["data"]) ? 0 : -1;
    }
    catch (const nlohmann::json::exception& ex)
    {
        std::cout << "message: " << ex.what() << std::endl
                  << "exception id: " << ex.id << std::endl;
        retVal = ex.id;
    }
    catch (const SQLite::exception& ex)
    {
        std::cout << "message: " << ex.what() << std::endl;
        retVal = ex.id();
    }
    catch (const std::runtime_error& ex)
    {
        std::cout << "message: " << ex.what() << std::endl;
        // retVal = ex.id;
    }
    return retVal;
}

int32_t DBSyncImplementation::updateSnapshotData(const DBSYNC_HANDLE handle,
                                                 const char* jsonSnapshot,
                                                 std::string& result)
{
    auto retVal { 1 };
    try
    {
        const auto ctx{ getDbEngineContext(handle) };
        const auto json { nlohmann::json::parse(jsonSnapshot)};
        nlohmann::json jsonResult;
        retVal = ctx->GetDbEngine()->RefreshTablaData(json[0], std::make_tuple(std::ref(jsonResult), nullptr)) ? 0 : 1;
        result = std::move(jsonResult.dump());
    }
    catch (const nlohmann::json::exception& ex)
    {
        std::cout << "message: " << ex.what() << std::endl
                  << "exception id: " << ex.id << std::endl;
        retVal = ex.id;
    }
    catch (const SQLite::exception& ex)
    {
        std::cout << "message: " << ex.what() << std::endl;
        retVal = ex.id();
    }
    catch (const std::runtime_error& ex)
    {
        std::cout << "message: " << ex.what() << std::endl;
        // retVal = ex.id;
    }
    return retVal;
}

int32_t DBSyncImplementation::updateSnapshotData(const DBSYNC_HANDLE handle,
                                                 const char* jsonSnapshot,
                                                 void* callback)
{
    auto retVal { 1 };
    try
    {
        const auto ctx{ getDbEngineContext(handle) };
        const auto json { nlohmann::json::parse(jsonSnapshot)};
        nlohmann::json fake;
        retVal = ctx->GetDbEngine()->RefreshTablaData(json[0], std::make_tuple(std::ref(fake), callback)) ? 0 : 1;
    }
    catch (const nlohmann::json::exception& ex)
    {
        std::cout << "message: " << ex.what() << std::endl
                  << "exception id: " << ex.id << std::endl;
        retVal = ex.id;
    }
    //check whether is correct to know about a db implementation detail like SQLite exception (?)
    catch (const SQLite::exception& ex)
    {
        std::cout << "message: " << ex.what() << std::endl;
        retVal = ex.id();
    }
    catch (const std::runtime_error& ex)
    {
        std::cout << "message: " << ex.what() << std::endl;
        // retVal = ex.id;
    }
    return retVal;
}

std::shared_ptr<DbEngineContext> DBSyncImplementation::getDbEngineContext(const DBSYNC_HANDLE handle)
{
    std::lock_guard<std::mutex> lock{m_mutex};
    const auto it
    {
        std::find_if(m_dbSyncContexts.begin(),
                     m_dbSyncContexts.end(),
                     [handle](const std::shared_ptr<DbEngineContext>& context)
                     {
                        return context.get() == handle;
                     })
    };
    if (it == m_dbSyncContexts.end())
    {
        throw std::runtime_error
        {
            "Invalid handle value."
        };
    }
    return *it;
}
