/*
 * Wazuh DBSYNC
 * Copyright (C) 2015-2021, Wazuh Inc.
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
#include "commonDefs.h"

using ResultCallbackData = const std::function<void(ReturnTypeCallback, const nlohmann::json&) >;

class EXPORTED DBSync 
{
public:
    /**
    * @brief Initializes the shared library.
    *
    * @param logFunction pointer to log function to be used by the dbsync.
    */
    static void initialize(std::function<void(const std::string&)> logFunction);

    /**
     * @brief Explicit DBSync Constructor.
     *
     * @param hostType     Dynamic library host type to be used.
     * @param dbType       Database type to be used (currently only supported SQLITE3)
     * @param path         Path where the local database will be created.
     * @param sqlStatement SQL sentence to create tables in a SQL engine.
     *
     */
    explicit DBSync(const HostType     hostType,
                    const DbEngineType dbType,
                    const std::string& path,
                    const std::string& sqlStatement);

    /**
     * @brief DBSync Constructor.
     *
     * @param handle     handle to point another dbsync instance.
     *
     */
    DBSync(const DBSYNC_HANDLE handle);
    // LCOV_EXCL_START
    virtual ~DBSync();
    // LCOV_EXCL_STOP

    /**
     * @brief Generates triggers that execute actions to maintain consistency between tables.
     *
     * @param jsInput      JSON information with tables relationship.
     *
     */
    virtual void addTableRelationship(const nlohmann::json& jsInput);

    /**
     * @brief Insert the \p jsInsert data in the database.
     *
     * @param jsInsert JSON information with values to be inserted.
     *
     */
    virtual void insertData(const nlohmann::json& jsInsert);

    /**
     * @brief Sets the max rows in the \p table table.
     *
     * @param table    Table name to apply the max rows configuration.
     * @param maxRows  Max rows number to be applied in the table \p table table.
     *
     *
     * @details The table will work as a queue if the limit is exceeded.
     */
    virtual void setTableMaxRow(const std::string&       table,
                                const unsigned long long maxRows);

    /**
     * @brief Inserts (or modifies) a database record.
     *
     * @param jsInput        JSON information used to add/modified a database record.
     * @param callbackData   Result callback(std::function) will be called for each result.
     *
     */
    virtual void syncRow(const nlohmann::json& jsInput,
                         ResultCallbackData    callbackData);

    /**
     * @brief Select data, based in \p jsInput data, from the database table.
     *
     * @param jsInput         JSON with table name, fields and filters to apply in the query.
     * @param callbackData    Result callback(std::function) will be called for each result.
     *
     */
    virtual void selectRows(const nlohmann::json& jsInput,
                            ResultCallbackData    callbackData);

    /**
     * @brief Deletes a database table record and its relationships based on \p jsInput value.
     *
     * @param jsInput JSON information to be applied/deleted in the database.
     *
     */
    virtual void deleteRows(const nlohmann::json& jsInput);

    /**
     * @brief Updates data table with \p jsInput information. \p jsResult value will
     *  hold/contain the results of this operation (rows insertion, modification and/or deletion).
     *
     * @param jsInput    JSON information with snapshot values.
     * @param jsResult   JSON with deletes, creations and modifications (diffs) in rows.
     *
     */
    virtual void updateWithSnapshot(const nlohmann::json& jsInput,
                                    nlohmann::json&       jsResult);

    /**
     * @brief Update data table, based on json_raw_snapshot bulk data based on json string.
     *
     * @param jsInput       JSON with snapshot values.
     * @param callbackData  Result callback(std::function) will be called for each result.
     *
     */
    virtual void updateWithSnapshot(const nlohmann::json& jsInput,
                                    ResultCallbackData    callbackData);

    /**
     * @brief Turns off the services provided by the shared library.
     */
    static void teardown();

    /**
     * @brief Get current dbsync handle in the instance.
     *
     * @return DBSYNC_HANDLE to be used in all internal calls.
     */
    DBSYNC_HANDLE handle() { return m_dbsyncHandle; }
private:
    DBSYNC_HANDLE m_dbsyncHandle;
    bool m_shouldBeRemoved;
};

class EXPORTED DBSyncTxn 
{
public:
    /**
     * @brief DBSync Transaction constructor
     *
     * @param handle         Handle obtained from the \ref DBSync instance.
     * @param tables         Tables to be created in the transaction.
     * @param threadNumber   Number of worker threads for processing data. If 0 hardware concurrency
     *                       value will be used.
     * @param maxQueueSize   Max data number to hold/queue to be processed.
     * @param callbackData   Result callback(std::function) will be called for each result.
     *
     * @details If the max queue size is reached then this will be processed synchronously.
     */
    explicit DBSyncTxn(const DBSYNC_HANDLE   handle,
                       const nlohmann::json& tables,
                       const unsigned int    threadNumber,
                       const unsigned int    maxQueueSize,
                       ResultCallbackData    callbackData);
    /**
     * @brief DBSync transaction Constructor.
     *
     * @param handle     handle to point another dbsync transaction instance.
     *
     */
    DBSyncTxn(const TXN_HANDLE handle);

    /**
     * @brief Destructor closes the database transaction.
     *
     */
    // LCOV_EXCL_START
    virtual ~DBSyncTxn();
    // LCOV_EXCL_STOP

    /**
     * @brief Synchronizes the \p jsInput data.
     *
     * @param jsInput JSON information to be synchronized.
     *
     */
    virtual void syncTxnRow(const nlohmann::json& jsInput);

    /**
     * @brief Gets the deleted rows (diff) from the database.
     *
     * @param callbackData    Result callback(std::function) will be called for each result.
     *
     */
    virtual void getDeletedRows(ResultCallbackData callbackData);

    /**
     * @brief Get current dbsync transaction handle in the instance.
     *
     * @return TXN_HANDLE to be used in all internal calls.
     */
    TXN_HANDLE handle() { return m_txn; }

private:
    TXN_HANDLE m_txn;
};


#endif // _DBSYNC_HPP_