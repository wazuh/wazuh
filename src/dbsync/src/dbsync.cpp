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

#include <map>
#include <mutex>
#include "dbsync.h"
#include "dbsync_implementation.h"
#include "dbsyncPipelineFactory.h"

#ifdef __cplusplus
extern "C" {
#endif

using namespace DbSync;

struct CJsonDeleter
{
    void operator()(char* json)
    {
        cJSON_free(json);
    }
    void operator()(cJSON* json)
    {
        cJSON_Delete(json);
    }
};

static log_fnc_t gs_logFunction{ nullptr };

static void log_message(const std::string& msg)
{
    if (!msg.empty())
    {
        if (gs_logFunction)
        {
            gs_logFunction(msg.c_str());
        }
    }
}

void dbsync_initialize(log_fnc_t log_function)
{
    if (!gs_logFunction)
    {
        gs_logFunction = log_function;
    }
}

DBSYNC_HANDLE dbsync_create(const HostType     host_type,
                            const DbEngineType db_type,
                            const char*        path,
                            const char*        sql_statement)
{
    DBSYNC_HANDLE ret_val{ nullptr };
    std::string error_message;
    if (!path || !sql_statement)
    {
        error_message += "Invalid path or sql_statement.";
    }
    else
    {
        try
        {
            ret_val = DBSyncImplementation::instance().initialize(host_type, db_type, path, sql_statement);
        }
        catch(const nlohmann::detail::exception& ex)
        {
            error_message += "json error, id: " + std::to_string(ex.id) + ". " + ex.what();
        }
        catch(const DbSync::dbsync_error& ex)
        {
            error_message += "DB error, id: " + std::to_string(ex.id()) + ". " + ex.what();
        }
        catch(...)
        {
            error_message += "Unrecognized error.";
        }
    }
    log_message(error_message);
    return ret_val;
}

void dbsync_teardown(void)
{
    DBSyncImplementation::instance().release();
}

TXN_HANDLE dbsync_create_txn(const DBSYNC_HANDLE handle,
                             const char**        tables,
                             const int           /*thread_number*/,
                             const int           /*max_queue_size*/,
                             result_callback_t   callback)
{
    TXN_HANDLE ret_val{ nullptr };
    std::string error_message;
    if (!tables || !callback)
    {
        error_message += "Invalid tables or callback.";
    }
    else
    {
        try
        {
            const auto txnCtx = DBSyncImplementation::instance().createTransaction(handle, tables);
            const auto callbackWrapper
            {
                [callback](ReturnTypeCallback result, const nlohmann::json& jsonResult)
                {
                    const std::unique_ptr<cJSON, CJsonDeleter> spJson{ cJSON_Parse(jsonResult.dump().c_str()) };
                    callback(result, spJson.get());
                }
            };
            txn = PipelineFactory::instance().create(handle, txnCtx, thread_number, max_queue_size, callbackWrapper);
        }
        catch(const DbSync::dbsync_error& ex)
        {
            error_message += "DB error, id: " + std::to_string(ex.id()) + ". " + ex.what();
        }
        catch(...)
        {
            error_message += "Unrecognized error.";
        }
    }
    log_message(error_message);
    return ret_val;
}

int dbsync_close_txn(const DBSYNC_HANDLE handle,
                     const TXN_HANDLE txn)
{
    auto ret_val{ -1l };
    std::string error_message;
    
    try
    {
        DBSyncImplementation::instance().closeTransaction(handle, txn);
        ret_val = 0;
    }
    catch(const DbSync::dbsync_error& ex)
    {
        error_message += "DB error, id: " + std::to_string(ex.id()) + ". " + ex.what();
        ret_val = ex.id();
    }
    catch(...)
    {
        error_message += "Unrecognized error.";
    }
    return ret_val;
}

int dbsync_sync_txn_row(const DBSYNC_HANDLE /*handle*/,
                        const TXN_HANDLE /*txn*/,
                        const cJSON*     /*js_input*/)
{
    auto ret_val { -1 };
    std::string error_message;
    if (!txn || !js_input)
    {
        error_message += "Invalid txn or json.";
    }
    else
    {
        try
        {
            const std::unique_ptr<char, CJsonDeleter> spJsonBytes{cJSON_Print(js_input)};
            PipelineFactory::instance().pipeline(txn)->syncRow(spJsonBytes.get());
            ret_val = 0;
        }
        catch(const DbSync::dbsync_error& ex)
        {
            error_message += "DB error, id: " + std::to_string(ex.id()) + ". " + ex.what();
            ret_val = ex.id();
        }
        catch(...)
        {
            error_message += "Unrecognized error.";
        }
    }
    log_message(error_message);
    return ret_val;
}

int dbsync_add_table_relationship(const DBSYNC_HANDLE /*handle*/,
                                  const char*         /*table*/,
                                  const char*         /*parent_table*/,
                                  const char*         /*key_base*/,
                                  const char*         /*parent_field*/)
{
    // Dummy function for now.
    return 0;
}

int dbsync_insert_data(const DBSYNC_HANDLE handle,
                       const cJSON*        js_insert)
{
    auto ret_val { -1 };
    std::string error_message;
    if (!handle || !js_insert)
    {
        error_message += "Invalid handle or json.";
    }
    else
    {
        try
        {
            const std::unique_ptr<char, CJsonDeleter> spJsonBytes{cJSON_Print(js_insert)};
            DBSyncImplementation::instance().insertBulkData(handle, spJsonBytes.get());
            ret_val = 0;
        }
        catch(const nlohmann::detail::exception& ex)
        {
            error_message += "json error, id: " + std::to_string(ex.id) + ". " + ex.what();
            ret_val = ex.id;
        }
        catch(const DbSync::dbsync_error& ex)
        {
            error_message += "DB error, id: " + std::to_string(ex.id()) + ". " + ex.what();
            ret_val = ex.id();
        }
        catch(...)
        {
            error_message += "Unrecognized error.";
        }
    }
    log_message(error_message);

    return ret_val;
}

int dbsync_set_table_max_rows(const DBSYNC_HANDLE      /*handle*/,
                              const char*              /*table*/,
                              const unsigned long long /*max_rows*/)
{
    // Dummy function for now.
    return 0;
}

int dbsync_sync_row(const DBSYNC_HANDLE handle,
                    const cJSON*        js_input,
                    result_callback_t   callback)
{
    auto ret_val { -1 };
    std::string errorMessage;
    if (!handle || !js_input || !callback)
    {
        errorMessage += "Invalid input parameters.";
    }
    else
    {
        try
        {
            const auto callbackWrapper
            {
                [callback](ReturnTypeCallback result, const nlohmann::json& jsonResult)
                {
                    const std::unique_ptr<cJSON, CJsonDeleter> spJson{ cJSON_Parse(jsonResult.dump().c_str()) };
                    callback(result, spJson.get());
                }
            };
            const std::unique_ptr<char, CJsonDeleter> spJsonBytes{ cJSON_PrintUnformatted(js_input) };
            DBSyncImplementation::instance().syncRowData(handle, spJsonBytes.get(), callbackWrapper);
            ret_val = 0;
        }
        catch(const nlohmann::detail::exception& ex)
        {
            errorMessage += "json error, id: " + std::to_string(ex.id) + ". " + ex.what();
            ret_val = ex.id;
        }
        catch(const DbSync::dbsync_error& ex)
        {
            errorMessage += "DB error, id: " + std::to_string(ex.id()) + ". " + ex.what();
            ret_val = ex.id();
        }
        catch(...)
        {
            errorMessage += "Unrecognized error.";
        }
    }
    log_message(errorMessage);
    return ret_val;
}

int dbsync_select_rows(const DBSYNC_HANDLE /*handle*/,
                       const cJSON*        /*js_data_input*/,
                       result_callback_t   /*callback*/)
{
    // Dummy function for now.
    return 0;
}

int dbsync_delete_rows(const DBSYNC_HANDLE /*handle*/,
                       const cJSON*        /*js_key_values*/)
{
    // Dummy function for now.
    return 0;
}

int dbsync_get_deleted_rows(const DBSYNC_HANDLE /*handle*/,
                            const TXN_HANDLE  /*txn*/,
                            result_callback_t /*callback*/)
{
    auto ret_val { -1 };
    std::string error_message;
    if (!txn || !callback)
    {
        error_message += "Invalid txn or callback.";
    }
    else
    {
        try
        {
            const auto callbackWrapper
            {
                [callback](ReturnTypeCallback result, const nlohmann::json& jsonResult)
                {
                    const std::unique_ptr<cJSON, CJsonDeleter> spJson{ cJSON_Parse(jsonResult.dump().c_str()) };
                    callback(result, spJson.get());
                }
            };
            PipelineFactory::instance().pipeline(txn)->getDeleted(callbackWrapper);
            ret_val = 0;
        }
        catch(const DbSync::dbsync_error& ex)
        {
            error_message += "DB error, id: " + std::to_string(ex.id()) + ". " + ex.what();
            ret_val = ex.id();
        }
        catch(...)
        {
            error_message += "Unrecognized error.";
        }
    }
    log_message(error_message);

    return ret_val;
}

int dbsync_update_with_snapshot(const DBSYNC_HANDLE handle,
                                const cJSON*        js_snapshot,
                                cJSON**             js_result)
{
    auto ret_val { -1 };
    std::string error_message;
    if (!handle || !js_snapshot || !js_result)
    {
        error_message += "Invalid input parameter.";
    }
    else
    {
        try
        {
            nlohmann::json result;
            const auto callbackWrapper
            {
                [&result](ReturnTypeCallback resultType, const nlohmann::json& jsonResult)
                {
                    static std::map<ReturnTypeCallback, std::string> s_opMap
                    {
                        { MODIFIED , "modified" },
                        { DELETED  ,  "deleted" },
                        { INSERTED , "inserted" }
                    };
                    result[s_opMap.at(resultType)].push_back(jsonResult);
                }
            };
            const std::unique_ptr<char, CJsonDeleter> spJsonBytes{cJSON_PrintUnformatted(js_snapshot)};
            DBSyncImplementation::instance().updateSnapshotData(handle, spJsonBytes.get(), callbackWrapper);
            *js_result = cJSON_Parse(result.dump().c_str());
            ret_val = 0;
        }
        catch(const nlohmann::detail::exception& ex)
        {
            error_message += "json error, id: " + std::to_string(ex.id) + ". " + ex.what();
            ret_val = ex.id;
        }
        catch(const DbSync::dbsync_error& ex)
        {
            error_message += "DB error, id: " + std::to_string(ex.id()) + ". " + ex.what();
            ret_val = ex.id();
        }
        catch(...)
        {
            error_message += "Unrecognized error.";
        }
    }
    log_message(error_message);
    return ret_val;
}

int dbsync_update_with_snapshot_cb(const DBSYNC_HANDLE handle,
                                   const cJSON*        js_snapshot,
                                   result_callback_t   callback)
{
    auto ret_val { -1 };
    std::string error_message;
    if (!handle || !js_snapshot || !callback)
    {
        error_message += "Invalid input parameters.";
    }
    else
    {
        try
        {
            const auto callbackWrapper
            {
                [callback](ReturnTypeCallback result, const nlohmann::json& jsonResult)
                {
                    const std::unique_ptr<cJSON, CJsonDeleter> spJson{ cJSON_Parse(jsonResult.dump().c_str()) };
                    callback(result, spJson.get());
                }
            };
            const std::unique_ptr<char, CJsonDeleter> spJsonBytes{cJSON_PrintUnformatted(js_snapshot)};
            DBSyncImplementation::instance().updateSnapshotData(handle, spJsonBytes.get(), callbackWrapper);
            ret_val = 0;
        }
        catch(const nlohmann::detail::exception& ex)
        {
            error_message += "json error, id: " + std::to_string(ex.id) + ". " + ex.what();
            ret_val = ex.id;
        }
        catch(const DbSync::dbsync_error& ex)
        {
            error_message += "DB error, id: " + std::to_string(ex.id()) + ". " + ex.what();
            ret_val = ex.id();
        }
        catch(...)
        {
            error_message += "Unrecognized error.";
        }
    }
    log_message(error_message);
    return ret_val;
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