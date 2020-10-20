/*
 * Wazuh DBSYNC
 * Copyright (C) 2015-2020, Wazuh Inc.
 * October 13, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _DBSYNC_HPP_
#define _DBSYNC_HPP_

// Define EXPORTED for any platform
#ifdef _WIN32
#ifdef WIN_EXPORT
#define EXPORTED __declspec(dllexport)
#else
#define EXPORTED __declspec(dllimport)
#endif
#elif __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

#include <functional>
#include "json.hpp"
#include "db_exception.h"

using ResultCallbackData = const std::function<void(ReturnTypeCallback, const nlohmann::json&) >&;

class EXPORTED DBSync 
{
public:
    DBSync(const HostType     hostType,
           const DbEngineType dbType,
           const std::string& path,
           const std::string& sqlStatement);
    
    DBSync(const DBSYNC_HANDLE handle);
    // LCOV_EXCL_START
    virtual ~DBSync();
    // LCOV_EXCL_STOP

    virtual void addTableRelationship(const nlohmann::json& jsInput);

    virtual void insertData(const nlohmann::json& jsInsert);

    virtual void setTableMaxRow(const std::string&       table,
                                const unsigned long long maxRows);

    virtual void syncRow(const nlohmann::json& jsInput,
                         ResultCallbackData&   callbackData);

    virtual void selectRows(const nlohmann::json& jsInput,
                            ResultCallbackData&   callbackData);

    virtual void deleteRows(const nlohmann::json& jsInput);

    virtual void updateWithSnapshot(const nlohmann::json& jsInput,
                                    nlohmann::json&       jsResult);

    virtual void updateWithSnapshot(const nlohmann::json& jsInput,
                                    ResultCallbackData&   callbackData);     

    static void teardown();

    DBSYNC_HANDLE getHandle() { return m_dbsyncHandle; } 
private:
    DBSYNC_HANDLE m_dbsyncHandle;
    bool m_shouldBeRemove;
};

class EXPORTED DBSyncTxn 
{
public:
    explicit DBSyncTxn(const DBSYNC_HANDLE   handle,
                       const nlohmann::json& tables,
                       const unsigned int    threadNumber,
                       const unsigned int    maxQueueSize,
                       ResultCallbackData&   callbackData);
    // LCOV_EXCL_START
    virtual ~DBSyncTxn();
    // LCOV_EXCL_STOP

    virtual void syncTxnRow(const nlohmann::json& jsInput);

    virtual void getDeletedRows(ResultCallbackData& callbackData);

private:
    TXN_HANDLE m_txn;
};


#endif // _DBSYNC_HPP_