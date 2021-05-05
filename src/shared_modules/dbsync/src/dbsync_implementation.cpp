/*
 * Wazuh DBSYNC
 * Copyright (C) 2015-2021, Wazuh Inc.
 * June 11, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <iostream>
#include "dbsync_implementation.h"

using namespace DbSync;

DBSYNC_HANDLE DBSyncImplementation::initialize(const HostType     hostType,
                                               const DbEngineType dbType,
                                               const std::string& path,
                                               const std::string& sqlStatement)
{
    auto db{ FactoryDbEngine::create(dbType, path, sqlStatement) };
    const auto spDbEngineContext
    {
        std::make_shared<DbEngineContext>(db, hostType, dbType)
    };
    const DBSYNC_HANDLE handle{ spDbEngineContext.get() };
    std::lock_guard<std::mutex> lock{m_mutex};
    m_dbSyncContexts[handle] = spDbEngineContext;
    return handle;
}

void DBSyncImplementation::release()
{
    std::lock_guard<std::mutex> lock{m_mutex};
    m_dbSyncContexts.clear();
}

void DBSyncImplementation::releaseContext(const DBSYNC_HANDLE handle)
{
    std::lock_guard<std::mutex> lock{ m_mutex };
    m_dbSyncContexts.erase(handle);
}

void DBSyncImplementation::insertBulkData(const DBSYNC_HANDLE   handle,
                                          const nlohmann::json& json)
{
    const auto ctx{ dbEngineContext(handle) };
    ctx->m_dbEngine->bulkInsert(json.at("table"), json.at("data"));
}

void DBSyncImplementation::syncRowData(const DBSYNC_HANDLE      handle,
                                       const nlohmann::json&    json,
                                       const ResultCallback     callback)
{
    const auto ctx{ dbEngineContext(handle) };
    ctx->m_dbEngine->syncTableRowData(json.at("table"),
                                      json.at("data"),
                                      callback);
}

void DBSyncImplementation::syncRowData(const DBSYNC_HANDLE      handle,
                                       const TXN_HANDLE         txn,
                                       const nlohmann::json&    json,
                                       const ResultCallback     callback)
{
    const auto& ctx{ dbEngineContext(handle) };
    const auto& tnxCtx { ctx->transactionContext(txn) };
    if (std::find(tnxCtx->m_tables.begin(), tnxCtx->m_tables.end(), json.at("table")) == tnxCtx->m_tables.end())
    {
        throw dbsync_error{INVALID_TABLE};
    }
    ctx->m_dbEngine->syncTableRowData(json.at("table"),
                                      json.at("data"),
                                      callback,
                                      true);
}

void DBSyncImplementation::deleteRowsData(const DBSYNC_HANDLE   handle,
                                          const nlohmann::json& json)
{
    const auto ctx{ dbEngineContext(handle) };
    ctx->m_dbEngine->deleteTableRowsData(json.at("table"),
                                         json.at("query"));
}

void DBSyncImplementation::updateSnapshotData(const DBSYNC_HANDLE   handle,
                                              const nlohmann::json& json,
                                              const ResultCallback  callback)
{
    const auto ctx{ dbEngineContext(handle) };
    ctx->m_dbEngine->refreshTableData(json, callback);
}

std::shared_ptr<DBSyncImplementation::DbEngineContext> DBSyncImplementation::dbEngineContext(const DBSYNC_HANDLE handle)
{
    std::lock_guard<std::mutex> lock{m_mutex};
    const auto it{ m_dbSyncContexts.find(handle) };
    if (it == m_dbSyncContexts.end())
    {
        throw dbsync_error { INVALID_HANDLE };
    }
    return it->second;
}

void DBSyncImplementation::setMaxRows(const DBSYNC_HANDLE handle,
                                      const std::string& table,
                                      const unsigned long long maxRows)
{
    const auto ctx{ dbEngineContext(handle) };
    ctx->m_dbEngine->setMaxRows(table, maxRows);
}

TXN_HANDLE DBSyncImplementation::createTransaction(const DBSYNC_HANDLE      handle,
                                                   const nlohmann::json&    json)
{
    const auto& ctx{ dbEngineContext(handle) };
    const auto& spTransactionContext
    {
        std::make_shared<TransactionContext>(json)
    };
    ctx->addTransactionContext(spTransactionContext);
    ctx->m_dbEngine->initializeStatusField(spTransactionContext->m_tables);
    
    return spTransactionContext.get();
}

void DBSyncImplementation::closeTransaction(const DBSYNC_HANDLE handle,
                                            const TXN_HANDLE txn)
{
    const auto& ctx{ dbEngineContext(handle) };
    const auto& tnxCtx { ctx->transactionContext(txn) };
    
    ctx->m_dbEngine->deleteRowsByStatusField(tnxCtx->m_tables);
    ctx->deleteTransactionContext(txn);
}

void DBSyncImplementation::getDeleted(const DBSYNC_HANDLE   handle, 
                                      const TXN_HANDLE      txnHandle,
                                      const ResultCallback  callback)
{
    const auto& ctx{ dbEngineContext(handle) };
    const auto& tnxCtx { ctx->transactionContext(txnHandle) };

    ctx->m_dbEngine->returnRowsMarkedForDelete(tnxCtx->m_tables, callback);
}

void DBSyncImplementation::selectData(const DBSYNC_HANDLE   handle, 
                                      const nlohmann::json& json,
                                      const ResultCallback& callback)
{
    const auto ctx{ dbEngineContext(handle) };
    ctx->m_dbEngine->selectData(json.at("table"),
                                json.at("query"),
                                callback);
}

void DBSyncImplementation::addTableRelationship(const DBSYNC_HANDLE   handle, 
                                                const nlohmann::json& json)
{
    const auto ctx{ dbEngineContext(handle) };
    ctx->m_dbEngine->addTableRelationship(json);
}