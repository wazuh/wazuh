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
using namespace DbSync;
DBSYNC_HANDLE DBSyncImplementation::initialize(const HostType hostType,
                                               const DbEngineType dbType,
                                               const std::string& path,
                                               const std::string& sqlStatement)
{
    auto db{ FactoryDbEngine::create(dbType, path, sqlStatement) };
    std::lock_guard<std::mutex> lock{m_mutex};
    m_dbSyncContexts.push_back(std::make_shared<DbEngineContext>(
      db,
      hostType,
      dbType
    ));
    return m_dbSyncContexts.back().get();
}

void DBSyncImplementation::release()
{
    std::lock_guard<std::mutex> lock{m_mutex};
    m_dbSyncContexts.clear();
}

void DBSyncImplementation::insertBulkData(const DBSYNC_HANDLE handle,
                                          const char* jsonRaw)
{
    const auto ctx{ dbEngineContext(handle) };
    const auto json { nlohmann::json::parse(jsonRaw)};
    ctx->dbEngine()->bulkInsert(json[0]["table"], json[0]["data"]);
}

void DBSyncImplementation::updateSnapshotData(const DBSYNC_HANDLE handle,
                                              const char* jsonSnapshot,
                                              std::string& result)
{
    const auto ctx{ dbEngineContext(handle) };
    const auto json { nlohmann::json::parse(jsonSnapshot)};
    nlohmann::json jsonResult;
    ctx->dbEngine()->refreshTableData(json[0], std::make_tuple(std::ref(jsonResult), nullptr));
    result = std::move(jsonResult.dump());
}

void DBSyncImplementation::updateSnapshotData(const DBSYNC_HANDLE handle,
                                              const char* jsonSnapshot,
                                              void* callback)
{
    const auto ctx{ dbEngineContext(handle) };
    const auto json { nlohmann::json::parse(jsonSnapshot)};
    nlohmann::json fake;
    ctx->dbEngine()->refreshTableData(json[0], std::make_tuple(std::ref(fake), callback));
}

std::shared_ptr<DbEngineContext> DBSyncImplementation::dbEngineContext(const DBSYNC_HANDLE handle)
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
        throw dbsync_error
        {
            2, "Invalid handle value."
        };
    }
    return *it;
}
