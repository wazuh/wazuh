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

#ifndef _DBSYNC_IMPLEMENTATION_H
#define _DBSYNC_IMPLEMENTATION_H

#include <map>
#include <memory>
#include <mutex>
#include "dbengine_factory.h"
#include "typedef.h"
#include "json.hpp"

namespace DbSync
{
    class DBSyncImplementation
    {
    public:
        static DBSyncImplementation& instance()
        {
            static DBSyncImplementation s_instance;
            return s_instance;
        }

        void insertBulkData(const DBSYNC_HANDLE handle,
                            const char*         jsonRaw);

        void syncRowData(const DBSYNC_HANDLE  handle,
                         const char*          jsonRaw,
                         const ResultCallback callback);

        void updateSnapshotData(const DBSYNC_HANDLE  handle,
                                const char*          jsonSnapshot,
                                const ResultCallback callback);

        DBSYNC_HANDLE initialize(const HostType     hostType,
                                 const DbEngineType dbType,
                                 const std::string& path,
                                 const std::string& sqlStatement);
        void release();
    private:
        struct DbEngineContext
        {
            DbEngineContext(std::unique_ptr<IDbEngine>& dbEngine,
                            const HostType hostType,
                            const DbEngineType dbType)
            : m_dbEngine{std::move(dbEngine)}
            , m_hostType{hostType}
            , m_dbEngineType{dbType}
            {}
            const std::unique_ptr<IDbEngine> m_dbEngine;
            const HostType m_hostType;
            const DbEngineType m_dbEngineType;
        };

        std::shared_ptr<DbEngineContext> dbEngineContext(const DBSYNC_HANDLE handle);
        DBSyncImplementation() = default;
        ~DBSyncImplementation() = default;
        DBSyncImplementation(const DBSyncImplementation&) = delete;
        DBSyncImplementation& operator=(const DBSyncImplementation&) = delete;
        std::map<DBSYNC_HANDLE, std::shared_ptr<DbEngineContext>> m_dbSyncContexts;
        std::mutex m_mutex;
    };
}

#endif // _DBSYNC_IMPLEMENTATION_H