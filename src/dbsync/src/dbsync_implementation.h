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

#pragma once
#include <vector>
#include <memory>
#include <mutex>

#include "dbengine_factory.h"
#include "dbengine_context.h"
#include "typedef.h"
#include "json.hpp"

class DBSyncImplementation
{
public:
    static DBSyncImplementation& getInstance()
    {
        static DBSyncImplementation s_instance;
        return s_instance;
    }
    int32_t insertBulkData(const DBSYNC_HANDLE handle,
                           const char* jsonRaw);
    int32_t updateSnapshotData(const DBSYNC_HANDLE handle,
                               const char* jsonSnapshot,
                               std::string& result);
    int32_t updateSnapshotData(const DBSYNC_HANDLE handle,
                               const char* jsonSnapshot,
                               void* callback);
    DBSYNC_HANDLE initialize(const HostType hostType,
                             const DbEngineType dbType,
                             const std::string& path,
                             const std::string& sqlStatement);
    void release();
private:
    std::shared_ptr<DbEngineContext> getDbEngineContext(const DBSYNC_HANDLE handle);
    DBSyncImplementation() = default;
    ~DBSyncImplementation() = default;
    DBSyncImplementation(const DBSyncImplementation&) = delete;
    DBSyncImplementation& operator=(const DBSyncImplementation&) = delete;
    std::vector<std::shared_ptr<DbEngineContext>> m_dbSyncContexts;
    std::mutex m_mutex;
};