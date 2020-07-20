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
        TXN_HANDLE createTransaction(const DBSYNC_HANDLE handle,
                                     const char** tables,
                                     const int threadNumber,
                                     const int maxQueueSize,
                                     result_callback_t callback);
        void closeTransaction(const DBSYNC_HANDLE handle,
                              TXN_HANDLE txnHandle);
        void release();
    private:

        struct TransactionContext
        {
            explicit TransactionContext(const char** tables)
            {
                auto rawElement { *tables };
                if (nullptr != rawElement)
                {
                    while ('\0' != *rawElement)
                    {
                        m_tables.push_back(std::string(rawElement));
                        rawElement += m_tables.back().size() + 1;
                    }
                } 
                else 
                {
                    throw dbsync_error
                    {
                        INVALID_TRANSACTION
                    };
                }
            }
            std::vector<std::string> m_tables;
        };
        class DbEngineContext
        {
            public:
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
                const std::shared_ptr<DBSyncImplementation::TransactionContext> transactionContext(const TXN_HANDLE handle)
                {
                    std::lock_guard<std::mutex> lock{m_mutex};
                    const auto it{ m_transactionContexts.find(handle) };
                    if (m_transactionContexts.end() == it)
                    {
                        throw dbsync_error
                        {
                            INVALID_TRANSACTION
                        };
                    }
                    return it->second;
                }
                void addTransactionContext(const std::shared_ptr<DbSync::DBSyncImplementation::TransactionContext>& spTransactionContext)
                {
                    std::lock_guard<std::mutex> lock{m_mutex};
                    m_transactionContexts[spTransactionContext.get()] = spTransactionContext;
                }
                void deleteTransactionContext(const TXN_HANDLE txnHandle)
                {
                    std::lock_guard<std::mutex> lock{m_mutex};
                    m_transactionContexts.erase(txnHandle);
                }
            private:
                std::map<TXN_HANDLE, std::shared_ptr<TransactionContext>> m_transactionContexts;
                std::mutex m_mutex;
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