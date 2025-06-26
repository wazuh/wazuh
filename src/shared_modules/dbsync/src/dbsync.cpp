/*
 * Wazuh DBSYNC
 * Copyright (C) 2015, Wazuh Inc.
 * June 11, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <map>
#include <mutex>
#include "dbsync.h"
#include "dbsync.hpp"
#include "dbsync_implementation.h"
#include "dbsyncPipelineFactory.h"
#include "cjsonSmartDeleter.hpp"

#ifdef __cplusplus
extern "C" {
#endif

using namespace DbSync;

static std::function<void(const std::string&)> gs_logFunction;

static void log_message(const std::string& msg)
{
    if (!msg.empty() && gs_logFunction)
    {
        gs_logFunction(msg);
    }
}

void dbsync_initialize(log_fnc_t log_function)
{
    DBSync::initialize([log_function](const std::string & msg)
    {
        log_function(msg.c_str());
    });
}

DBSYNC_HANDLE dbsync_create_(const HostType     host_type,
                             const DbEngineType db_type,
                             const char*        path,
                             const char*        sql_statement,
                             const DbManagement db_management,
                             const char**       upgrade_statements)
{
    DBSYNC_HANDLE retVal{ nullptr };
    std::string errorMessage;

    if (!path || !sql_statement)
    {
        errorMessage += "Invalid path or sql_statement.";
    }
    else
    {
        try
        {
            auto upgradeStatements = std::vector<std::string>();

            while (upgrade_statements && *upgrade_statements)
            {
                upgradeStatements.emplace_back(*upgrade_statements);
                upgrade_statements++;
            }

            retVal = DBSyncImplementation::instance().initialize(host_type, db_type, path, sql_statement, db_management, upgradeStatements);
        }
        catch (const DbSync::dbsync_error& ex)
        {
            errorMessage += "DB error, id: " + std::to_string(ex.id()) + ". " + ex.what();
        }
        // LCOV_EXCL_START
        catch (...)
        {
            errorMessage += "Unrecognized error.";
        }

        // LCOV_EXCL_STOP
    }

    log_message(errorMessage);
    return retVal;
}

DBSYNC_HANDLE dbsync_create(const HostType     host_type,
                            const DbEngineType db_type,
                            const char*        path,
                            const char*        sql_statement)
{
    return dbsync_create_(host_type, db_type, path, sql_statement, DbManagement::VOLATILE, nullptr);
}

DBSYNC_HANDLE dbsync_create_persistent(const HostType     host_type,
                                       const DbEngineType db_type,
                                       const char*        path,
                                       const char*        sql_statement,
                                       const char**       upgrade_statements)
{
    return dbsync_create_(host_type, db_type, path, sql_statement, DbManagement::PERSISTENT, upgrade_statements);
}

void dbsync_teardown(void)
{
    PipelineFactory::instance().release();
    DBSyncImplementation::instance().release();
}

TXN_HANDLE dbsync_create_txn(const DBSYNC_HANDLE handle,
                             const cJSON*        tables,
                             const unsigned int  thread_number,
                             const unsigned int  max_queue_size,
                             callback_data_t     callback_data)
{
    std::string errorMessage;
    TXN_HANDLE txn{ nullptr };

    if (!handle || !tables || !max_queue_size || !callback_data.callback)
    {
        errorMessage += "Invalid parameters.";
    }
    else
    {
        try
        {
            const auto callbackWrapper
            {
                [callback_data](ReturnTypeCallback result, const nlohmann::json & jsonResult)
                {
                    std::string Message;
                    Message += "jsonResult: " + jsonResult.dump();
                    log_message(Message);
                    const std::unique_ptr<cJSON, CJsonSmartDeleter> spJson{ cJSON_Parse(jsonResult.dump().c_str()) };
                    callback_data.callback(result, spJson.get(), callback_data.user_data);
                }
            };
            const std::unique_ptr<char, CJsonSmartFree> spJsonBytes{cJSON_Print(tables)};
            txn = PipelineFactory::instance().create(handle, nlohmann::json::parse(spJsonBytes.get()), thread_number, max_queue_size, callbackWrapper);
        }
        catch (const DbSync::dbsync_error& ex)
        {
            errorMessage += "DB error, id: " + std::to_string(ex.id()) + ". " + ex.what();
        }
        // LCOV_EXCL_START
        catch (...)
        {
            errorMessage += "Unrecognized error.";
        }

        // LCOV_EXCL_STOP
    }

    log_message(errorMessage);
    return txn;
}

int dbsync_close_txn(const TXN_HANDLE txn)
{
    auto retVal { -1 };
    std::string errorMessage;

    if (!txn)
    {
        errorMessage += "Invalid txn.";
    }
    else
    {
        try
        {
            PipelineFactory::instance().destroy(txn);
            retVal = 0;
        }
        catch (const DbSync::dbsync_error& ex)
        {
            errorMessage += "DB error, id: " + std::to_string(ex.id()) + ". " + ex.what();
            retVal = ex.id();
        }
        // LCOV_EXCL_START
        catch (...)
        {
            errorMessage += "Unrecognized error.";
        }

        // LCOV_EXCL_STOP
    }

    log_message(errorMessage);
    return retVal;
}

int dbsync_sync_txn_row(const TXN_HANDLE txn,
                        const cJSON*     js_input)
{
    auto retVal { -1 };
    std::string error_message;

    if (!txn || !js_input)
    {
        error_message += "Invalid txn or json.";
    }
    else
    {
        try
        {
            const std::unique_ptr<char, CJsonSmartFree> spJsonBytes{cJSON_PrintUnformatted(js_input)};
            PipelineFactory::instance().pipeline(txn)->syncRow(nlohmann::json::parse(spJsonBytes.get()));
            retVal = 0;
        }
        catch (const DbSync::dbsync_error& ex)
        {
            error_message += "DB error, id: " + std::to_string(ex.id()) + ". " + ex.what();
            retVal = ex.id();
        }
        // LCOV_EXCL_START
        catch (...)
        {
            error_message += "Unrecognized error.";
        }

        // LCOV_EXCL_STOP
    }

    log_message(error_message);
    return retVal;
}

int dbsync_add_table_relationship(const DBSYNC_HANDLE handle,
                                  const cJSON*        js_input)
{
    auto retVal { -1 };
    std::string errorMessage;

    if (!handle || !js_input)
    {
        errorMessage += "Invalid parameters.";
    }
    else
    {
        try
        {
            const std::unique_ptr<char, CJsonSmartFree> spJsonBytes{cJSON_Print(js_input)};
            DBSyncImplementation::instance().addTableRelationship(handle, nlohmann::json::parse(spJsonBytes.get()));
            retVal = 0;
        }
        catch (const nlohmann::detail::exception& ex)
        {
            errorMessage += "json error, id: " + std::to_string(ex.id) + ". " + ex.what();
            retVal = ex.id;
        }
        catch (const DbSync::dbsync_error& ex)
        {
            errorMessage += "DB error, id: " + std::to_string(ex.id()) + ". " + ex.what();
            retVal = ex.id();
        }
        catch (...)
        {
            errorMessage += "Unrecognized error.";
        }
    }

    log_message(errorMessage);

    return retVal;
}

int dbsync_insert_data(const DBSYNC_HANDLE handle,
                       const cJSON*        js_insert)
{
    auto retVal { -1 };
    std::string errorMessage;

    if (!handle || !js_insert)
    {
        errorMessage += "Invalid handle or json.";
    }
    else
    {
        try
        {
            const std::unique_ptr<char, CJsonSmartFree> spJsonBytes{cJSON_Print(js_insert)};
            DBSyncImplementation::instance().insertBulkData(handle, nlohmann::json::parse(spJsonBytes.get()));
            retVal = 0;
        }
        catch (const nlohmann::detail::exception& ex)
        {
            errorMessage += "json error, id: " + std::to_string(ex.id) + ". " + ex.what();
            retVal = ex.id;
        }
        catch (const DbSync::dbsync_error& ex)
        {
            errorMessage += "DB error, id: " + std::to_string(ex.id()) + ". " + ex.what();
            retVal = ex.id();
        }
        catch (const DbSync::max_rows_error& ex)
        {
            errorMessage += "DB error, ";
            errorMessage += ex.what();
        }
        // LCOV_EXCL_START
        catch (...)
        {
            errorMessage += "Unrecognized error.";
        }

        // LCOV_EXCL_STOP
    }

    log_message(errorMessage);

    return retVal;
}

int dbsync_set_table_max_rows(const DBSYNC_HANDLE handle,
                              const char*         table,
                              const long long     max_rows)
{
    auto retVal { -1 };
    std::string errorMessage;

    if (!handle || !table)
    {
        errorMessage += "Invalid parameters.";
    }
    else
    {
        try
        {
            DBSyncImplementation::instance().setMaxRows(handle, table, max_rows);
            retVal = 0;
        }
        catch (const DbSync::dbsync_error& ex)
        {
            errorMessage += "DB error, id: " + std::to_string(ex.id()) + ". " + ex.what();
            retVal = ex.id();
        }
        // LCOV_EXCL_START
        catch (...)
        {
            errorMessage += "Unrecognized error.";
        }

        // LCOV_EXCL_STOP
    }

    log_message(errorMessage);

    return retVal;
}

int dbsync_sync_row(const DBSYNC_HANDLE handle,
                    const cJSON*        js_input,
                    callback_data_t     callback_data)
{
    auto retVal { -1 };
    std::string errorMessage;

    if (!handle || !js_input || !callback_data.callback)
    {
        errorMessage += "Invalid input parameters.";
    }
    else
    {
        try
        {
            const auto callbackWrapper
            {
                [callback_data](ReturnTypeCallback result, const nlohmann::json & jsonResult)
                {
                    const std::unique_ptr<cJSON, CJsonSmartDeleter> spJson{ cJSON_Parse(jsonResult.dump().c_str()) };
                    callback_data.callback(result, spJson.get(), callback_data.user_data);
                }
            };
            const std::unique_ptr<char, CJsonSmartFree> spJsonBytes{ cJSON_PrintUnformatted(js_input) };
            DBSyncImplementation::instance().syncRowData(handle, nlohmann::json::parse(spJsonBytes.get()), callbackWrapper);
            retVal = 0;
        }
        catch (const nlohmann::detail::exception& ex)
        {
            errorMessage += "json error, id: " + std::to_string(ex.id) + ". " + ex.what();
            retVal = ex.id;
        }
        catch (const DbSync::dbsync_error& ex)
        {
            errorMessage += "DB error, id: " + std::to_string(ex.id()) + ". " + ex.what();
            retVal = ex.id();
        }
        // LCOV_EXCL_START
        catch (...)
        {
            errorMessage += "Unrecognized error.";
        }

        // LCOV_EXCL_STOP
    }

    log_message(errorMessage);
    return retVal;
}

int dbsync_select_rows(const DBSYNC_HANDLE handle,
                       const cJSON*        js_data_input,
                       callback_data_t     callback_data)
{
    auto retVal { -1 };
    std::string errorMessage;

    if (!handle || !js_data_input || !callback_data.callback)
    {
        errorMessage += "Invalid input parameters.";
    }
    else
    {
        try
        {
            const auto callbackWrapper
            {
                [callback_data](ReturnTypeCallback result, const nlohmann::json & jsonResult)
                {
                    const std::unique_ptr<cJSON, CJsonSmartDeleter> spJson{ cJSON_Parse(jsonResult.dump().c_str()) };
                    callback_data.callback(result, spJson.get(), callback_data.user_data);
                }
            };
            const std::unique_ptr<char, CJsonSmartFree> spJsonBytes{ cJSON_PrintUnformatted(js_data_input) };
            DBSyncImplementation::instance().selectData(handle, nlohmann::json::parse(spJsonBytes.get()), callbackWrapper);
            retVal = 0;
        }
        catch (const nlohmann::detail::exception& ex)
        {
            errorMessage += "json error, id: " + std::to_string(ex.id) + ". " + ex.what();
            retVal = ex.id;
        }
        catch (const DbSync::dbsync_error& ex)
        {
            errorMessage += "DB error, id: " + std::to_string(ex.id()) + ". " + ex.what();
            retVal = ex.id();
        }
        // LCOV_EXCL_START
        catch (...)
        {
            errorMessage += "Unrecognized error.";
        }

        // LCOV_EXCL_STOP
    }

    log_message(errorMessage);
    return retVal;
}

int dbsync_delete_rows(const DBSYNC_HANDLE handle,
                       const cJSON*        js_key_values)
{
    auto retVal { -1 };
    std::string errorMessage;

    if (!handle || !js_key_values)
    {
        errorMessage += "Invalid input parameters.";
    }
    else
    {
        try
        {
            const std::unique_ptr<char, CJsonSmartFree> spJsonBytes{ cJSON_PrintUnformatted(js_key_values) };
            DBSyncImplementation::instance().deleteRowsData(handle, nlohmann::json::parse(spJsonBytes.get()));
            retVal = 0;
        }
        catch (const nlohmann::detail::exception& ex)
        {
            errorMessage += "json error, id: " + std::to_string(ex.id) + ". " + ex.what();
            retVal = ex.id;
        }
        catch (const DbSync::dbsync_error& ex)
        {
            errorMessage += "DB error, id: " + std::to_string(ex.id()) + ". " + ex.what();
            retVal = ex.id();
        }
        // LCOV_EXCL_START
        catch (...)
        {
            errorMessage += "Unrecognized error.";
        }

        // LCOV_EXCL_STOP
    }

    log_message(errorMessage);
    return retVal;
}

int dbsync_get_deleted_rows(const TXN_HANDLE  txn,
                            callback_data_t   callback_data)
{
    auto retVal { -1 };
    std::string error_message;

    if (!txn || !callback_data.callback)
    {
        error_message += "Invalid txn or callback.";
    }
    else
    {
        try
        {
            const auto callbackWrapper
            {
                [callback_data](ReturnTypeCallback result, const nlohmann::json & jsonResult)
                {
                    const std::unique_ptr<cJSON, CJsonSmartDeleter> spJson{ cJSON_Parse(jsonResult.dump().c_str()) };
                    callback_data.callback(result, spJson.get(), callback_data.user_data);
                }
            };
            PipelineFactory::instance().pipeline(txn)->getDeleted(callbackWrapper);
            retVal = 0;
        }
        catch (const DbSync::dbsync_error& ex)
        {
            error_message += "DB error, id: " + std::to_string(ex.id()) + ". " + ex.what();
            retVal = ex.id();
        }
        // LCOV_EXCL_START
        catch (...)
        {
            error_message += "Unrecognized error.";
        }

        // LCOV_EXCL_STOP
    }

    log_message(error_message);

    return retVal;
}

int dbsync_update_with_snapshot(const DBSYNC_HANDLE handle,
                                const cJSON*        js_snapshot,
                                cJSON**             js_result)
{
    auto retVal { -1 };
    std::string errorMessage;

    if (!handle || !js_snapshot || !js_result)
    {
        errorMessage += "Invalid input parameter.";
    }
    else
    {
        try
        {
            nlohmann::json result;
            const auto callbackWrapper
            {
                [&result](ReturnTypeCallback resultType, const nlohmann::json & jsonResult)
                {
                    static std::map<ReturnTypeCallback, std::string> s_opMap
                    {
                        // LCOV_EXCL_START
                        { MODIFIED, "modified" },
                        { DELETED,  "deleted" },
                        { INSERTED, "inserted" }
                        // LCOV_EXCL_STOP
                    };
                    result[s_opMap.at(resultType)].push_back(jsonResult);
                }
            };
            const std::unique_ptr<char, CJsonSmartFree> spJsonBytes{cJSON_PrintUnformatted(js_snapshot)};
            DBSyncImplementation::instance().updateSnapshotData(handle, nlohmann::json::parse(spJsonBytes.get()), callbackWrapper);
            *js_result = cJSON_Parse(result.dump().c_str());
            retVal = 0;
        }
        catch (const nlohmann::detail::exception& ex)
        {
            errorMessage += "json error, id: " + std::to_string(ex.id) + ". " + ex.what();
            retVal = ex.id;
        }
        catch (const DbSync::dbsync_error& ex)
        {
            errorMessage += "DB error, id: " + std::to_string(ex.id()) + ". " + ex.what();
            retVal = ex.id();
        }
        catch (const DbSync::max_rows_error& ex)
        {
            errorMessage += "DB error, ";
            errorMessage += ex.what();
        }
        // LCOV_EXCL_START
        catch (...)
        {
            errorMessage += "Unrecognized error.";
        }

        // LCOV_EXCL_STOP
    }

    log_message(errorMessage);
    return retVal;
}

int dbsync_update_with_snapshot_cb(const DBSYNC_HANDLE handle,
                                   const cJSON*        js_snapshot,
                                   callback_data_t     callback_data)
{
    auto retVal { -1 };
    std::string errorMessage;

    if (!handle || !js_snapshot || !callback_data.callback)
    {
        errorMessage += "Invalid input parameters.";
    }
    else
    {
        try
        {
            const auto callbackWrapper
            {
                [callback_data](ReturnTypeCallback result, const nlohmann::json & jsonResult)
                {
                    const std::unique_ptr<cJSON, CJsonSmartDeleter> spJson{ cJSON_Parse(jsonResult.dump().c_str()) };
                    callback_data.callback(result, spJson.get(), callback_data.user_data);
                }
            };
            const std::unique_ptr<char, CJsonSmartFree> spJsonBytes{cJSON_PrintUnformatted(js_snapshot)};
            DBSyncImplementation::instance().updateSnapshotData(handle, nlohmann::json::parse(spJsonBytes.get()), callbackWrapper);
            retVal = 0;
        }
        catch (const nlohmann::detail::exception& ex)
        {
            errorMessage += "json error, id: " + std::to_string(ex.id) + ". " + ex.what();
            retVal = ex.id;
        }
        catch (const DbSync::dbsync_error& ex)
        {
            errorMessage += "DB error, id: " + std::to_string(ex.id()) + ". " + ex.what();
            retVal = ex.id();
        }
        // LCOV_EXCL_START
        catch (...)
        {
            errorMessage += "Unrecognized error.";
        }

        // LCOV_EXCL_STOP
    }

    log_message(errorMessage);
    return retVal;
}

void dbsync_free_result(cJSON** js_data)
{
    if (*js_data)
    {
        cJSON_Delete(*js_data);
    }
}

#ifdef __cplusplus
}
#endif


void DBSync::initialize(std::function<void(const std::string&)> logFunction)
{
    if (!gs_logFunction)
    {
        gs_logFunction = logFunction;
    }
}

DBSync::DBSync(const HostType                  hostType,
               const DbEngineType              dbType,
               const std::string&              path,
               const std::string&              sqlStatement,
               const DbManagement              dbManagement,
               const std::vector<std::string>& upgradeStatements)
    : m_dbsyncHandle { DBSyncImplementation::instance().initialize(hostType, dbType, path, sqlStatement, dbManagement, upgradeStatements) }
    , m_shouldBeRemoved{ true }
{ }

DBSync::DBSync(const DBSYNC_HANDLE dbsyncHandle)
    : m_dbsyncHandle { dbsyncHandle }
    , m_shouldBeRemoved{ false }
{ }

DBSync::~DBSync()
{
    if (m_shouldBeRemoved)
    {
        DBSyncImplementation::instance().releaseContext(m_dbsyncHandle);
    }
}


void DBSync::teardown()
{
    PipelineFactory::instance().release();
    DBSyncImplementation::instance().release();
}

void DBSync::addTableRelationship(const nlohmann::json& jsInput)
{
    DBSyncImplementation::instance().addTableRelationship(m_dbsyncHandle, jsInput);
}

void DBSync::insertData(const nlohmann::json& jsInsert)
{
    DBSyncImplementation::instance().insertBulkData(m_dbsyncHandle, jsInsert);
}

void DBSync::setTableMaxRow(const std::string& table,
                            const long long    maxRows)
{
    DBSyncImplementation::instance().setMaxRows(m_dbsyncHandle, table, maxRows);
}

void DBSync::syncRow(const nlohmann::json& jsInput,
                     ResultCallbackData    callbackData)
{
    const auto callbackWrapper
    {
        [callbackData](ReturnTypeCallback result, const nlohmann::json & jsonResult)
        {
            callbackData(result, jsonResult);
        }
    };
    DBSyncImplementation::instance().syncRowData(m_dbsyncHandle, jsInput, callbackWrapper);
}

void DBSync::selectRows(const nlohmann::json& jsInput,
                        ResultCallbackData    callbackData)
{
    const auto callbackWrapper
    {
        [callbackData](ReturnTypeCallback result, const nlohmann::json & jsonResult)
        {
            callbackData(result, jsonResult);
        }
    };
    DBSyncImplementation::instance().selectData(m_dbsyncHandle, jsInput, callbackWrapper);
}

void DBSync::deleteRows(const nlohmann::json& jsInput)
{
    DBSyncImplementation::instance().deleteRowsData(m_dbsyncHandle, jsInput);
}

void DBSync::updateWithSnapshot(const nlohmann::json& jsInput,
                                nlohmann::json&       jsResult)
{
    const auto callbackWrapper
    {
        [&jsResult](ReturnTypeCallback resultType, const nlohmann::json & jsonResult)
        {
            static std::map<ReturnTypeCallback, std::string> s_opMap
            {
                // LCOV_EXCL_START
                { MODIFIED, "modified" },
                { DELETED,  "deleted" },
                { INSERTED, "inserted" }
                // LCOV_EXCL_STOP
            };
            jsResult[s_opMap.at(resultType)].push_back(jsonResult);
        }
    };
    DBSyncImplementation::instance().updateSnapshotData(m_dbsyncHandle, jsInput, callbackWrapper);
}

void DBSync::updateWithSnapshot(const nlohmann::json&     jsInput,
                                ResultCallbackData        callbackData)
{
    const auto callbackWrapper
    {
        [callbackData](ReturnTypeCallback result, const nlohmann::json & jsonResult)
        {
            callbackData(result, jsonResult);
        }
    };
    DBSyncImplementation::instance().updateSnapshotData(m_dbsyncHandle, jsInput, callbackWrapper);
}


DBSyncTxn::DBSyncTxn(const DBSYNC_HANDLE   handle,
                     const nlohmann::json& tables,
                     const unsigned int    threadNumber,
                     const unsigned int    maxQueueSize,
                     ResultCallbackData    callbackData)
    : m_shouldBeRemoved {true}
{
    const auto callbackWrapper
    {
        [callbackData](ReturnTypeCallback result, const nlohmann::json & jsonResult)
        {
            callbackData(result, jsonResult);
        }
    };
    m_txn = PipelineFactory::instance().create(handle, tables, threadNumber, maxQueueSize, callbackWrapper);
}

DBSyncTxn::DBSyncTxn(const TXN_HANDLE handle)
    : m_txn { handle }
    , m_shouldBeRemoved {false}
{ }

DBSyncTxn::~DBSyncTxn()
{
    if (m_shouldBeRemoved)
    {
        try
        {
            PipelineFactory::instance().destroy(m_txn);
        }
        catch (const DbSync::dbsync_error& ex)
        {
            log_message(ex.what());
        }
    }
}

void DBSyncTxn::syncTxnRow(const nlohmann::json& jsInput)
{
    PipelineFactory::instance().pipeline(m_txn)->syncRow(jsInput);
}

void DBSyncTxn::getDeletedRows(ResultCallbackData  callbackData)
{
    const auto callbackWrapper
    {
        [&callbackData](ReturnTypeCallback result, const nlohmann::json & jsonResult)
        {
            callbackData(result, jsonResult);
        }
    };
    PipelineFactory::instance().pipeline(m_txn)->getDeleted(callbackWrapper);
}

SelectQuery& SelectQuery::columnList(const std::vector<std::string>& fields)
{
    m_jsQuery["query"]["column_list"] = fields;
    return *this;
}

SelectQuery& SelectQuery::rowFilter(const std::string& filter)
{
    m_jsQuery["query"]["row_filter"] = filter;
    return *this;
}

SelectQuery& SelectQuery::distinctOpt(const bool distinct)
{
    m_jsQuery["query"]["distinct_opt"] = distinct;
    return *this;
}

SelectQuery& SelectQuery::orderByOpt(const std::string& orderBy)
{
    m_jsQuery["query"]["order_by_opt"] = orderBy;
    return *this;
}

SelectQuery& SelectQuery::countOpt(const uint32_t count)
{
    m_jsQuery["query"]["count_opt"] = count;
    return *this;
}

DeleteQuery& DeleteQuery::data(const nlohmann::json& data)
{
    m_jsQuery["query"]["data"].push_back(data);
    return *this;
}

DeleteQuery& DeleteQuery::reset()
{
    m_jsQuery["query"]["data"].clear();
    return *this;
}

DeleteQuery& DeleteQuery::rowFilter(const std::string& filter)
{
    m_jsQuery["query"]["where_filter_opt"] = filter;
    return *this;
}

InsertQuery& InsertQuery::data(const nlohmann::json& data)
{
    m_jsQuery["data"].push_back(data);
    return *this;
}

InsertQuery& InsertQuery::reset()
{
    m_jsQuery["data"].clear();
    return *this;
}

SyncRowQuery& SyncRowQuery::data(const nlohmann::json& data)
{
    m_jsQuery["data"].push_back(data);
    return *this;
}

SyncRowQuery& SyncRowQuery::ignoreColumn(const std::string& column)
{
    m_jsQuery["options"]["ignore"].push_back(column);
    return *this;
}

SyncRowQuery& SyncRowQuery::returnOldData()
{
    m_jsQuery["options"]["return_old_data"] = true;
    return *this;
}

SyncRowQuery& SyncRowQuery::reset()
{
    m_jsQuery["data"].clear();
    return *this;
}
