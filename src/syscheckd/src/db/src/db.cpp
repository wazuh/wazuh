/*
 * Wazuh Syscheck
 * Copyright (C) 2015, Wazuh Inc.
 * August 28, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "commonDefs.h"
#include "dbsync.hpp"
#include "dbsync.h"
#include "db.h"
#include "db.hpp"
#include "fimCommonDefs.h"
#include "fimDB.hpp"
#include "dbFileItem.hpp"
#include "dbRegistryKey.hpp"
#include "dbRegistryValue.hpp"
#include "fimDBSpecialization.h"
#include "stringHelper.h"
#include "cjsonSmartDeleter.hpp"

void DB::init(const int storage,
              const int syncInterval,
              const uint32_t syncMaxInterval,
              const uint32_t syncResponseTimeout,
              std::function<void(const std::string&)> callbackSyncFileWrapper,
              std::function<void(const std::string&)> callbackSyncRegistryWrapper,
              std::function<void(modules_log_level_t, const std::string&)> callbackLogWrapper,
              const int fileLimit,
              const int valueLimit,
              bool syncRegistryEnabled,
              const int syncThreadPool,
              const int syncQueueSize)
{
    auto path { storage == FIM_DB_MEMORY ? FIM_DB_MEMORY_PATH : FIM_DB_DISK_PATH };
    auto dbsyncHandler
    {
        std::make_shared<DBSync>(HostType::AGENT, DbEngineType::SQLITE3, path,
                                 FIMDBCreator<OS_TYPE>::CreateStatement())
    };

    auto rsyncHandler { std::make_shared<RemoteSync>(syncThreadPool, syncQueueSize) };

    FIMDB::instance().init(syncInterval,
                           syncMaxInterval,
                           syncResponseTimeout,
                           callbackSyncFileWrapper,
                           callbackSyncRegistryWrapper,
                           callbackLogWrapper,
                           dbsyncHandler,
                           rsyncHandler,
                           fileLimit,
                           valueLimit,
                           syncRegistryEnabled);
}

void DB::runIntegrity()
{
    FIMDB::instance().runIntegrity();
}

void DB::pushMessage(const std::string& message)
{
    FIMDB::instance().pushMessage(message);
}

DBSYNC_HANDLE DB::DBSyncHandle()
{
    return FIMDB::instance().DBSyncHandler()->handle();
}

void DB::teardown()
{
    FIMDB::instance().teardown();
}

const std::map<COUNT_SELECT_TYPE, std::vector<std::string>> COUNT_SELECT_TYPE_MAP
{
    { COUNT_SELECT_TYPE::COUNT_ALL, {"count(*) AS count"} },
    { COUNT_SELECT_TYPE::COUNT_INODE, {"count(DISTINCT (inode || ',' || dev)) AS count"} },
};

int DB::countEntries(const std::string& tableName, const COUNT_SELECT_TYPE selectType)
{
    auto count { 0 };
    auto callback
    {
        [&count](ReturnTypeCallback type, const nlohmann::json & jsonResult)
        {
            if (ReturnTypeCallback::SELECTED == type)
            {
                count = jsonResult.at("count");
            }
        }
    };

    auto selectQuery
    {
        SelectQuery::builder()
        .table(tableName)
        .columnList(COUNT_SELECT_TYPE_MAP.at(selectType))
        .rowFilter("")
        .orderByOpt("")
        .distinctOpt(false)
        .build()
    };

    FIMDB::instance().executeQuery(selectQuery.query(), callback);

    return count;
}

#ifdef __cplusplus
extern "C" {
#endif
FIMDBErrorCode fim_db_init(int storage,
                           int sync_interval,
                           uint32_t sync_max_interval,
                           uint32_t sync_response_timeout,
                           fim_sync_callback_t sync_callback,
                           logging_callback_t log_callback,
                           int file_limit,
                           int value_limit,
                           bool sync_registry_enabled,
                           int sync_thread_pool,
                           unsigned int sync_queue_size,
                           log_fnc_t dbsync_log_function,
                           log_fnc_t rsync_log_function)
{
    auto retVal { FIMDBErrorCode::FIMDB_ERR };

    try
    {
        // LCOV_EXCL_START
        std::function<void(const std::string&)> callbackSyncFileWrapper
        {
            [sync_callback](const std::string & msg)
            {
                if (sync_callback)
                {
                    auto json = nlohmann::json::parse(msg);

                    if (json.at("type") == "state")
                    {
                        std::string perm_string = json["data"]["attributes"]["perm"];
                        auto perm_json = nlohmann::json::parse(perm_string, nullptr, false);

                        if (!perm_json.is_discarded())
                        {
                            json["data"]["attributes"].erase("perm");
                            json["data"]["attributes"]["perm"] = perm_json;
                        }

                        json["data"]["attributes"]["type"] = "file";
                        json["data"]["attributes"].erase("dev");
                        json["data"]["attributes"].erase("last_event");
                        json["data"]["attributes"].erase("mode");
                        json["data"]["attributes"].erase("options");
                        json["data"]["attributes"].erase("path");
                        json["data"]["attributes"].erase("scanned");
                        auto& obj = json.at("data").at("attributes");

                        if (obj.contains("inode") && !obj["inode"].is_string())
                        {
                            obj["inode"] = obj["inode"].dump();
                        }

                        FIMDB::instance().setTimeLastSyncMsg();
                    }

                    try
                    {
                        sync_callback(FIM_COMPONENT_FILE, json.dump().c_str());
                    }
                    catch (std::exception& err)
                    {
                        FIMDB::instance().logFunction(LOG_ERROR, err.what());
                    }
                }
            }
        };

        std::function<void(const std::string&)> callbackSyncRegistryWrapper
        {
            [sync_callback](const std::string & msg)
            {
                if (sync_callback)
                {
                    auto json = nlohmann::json::parse(msg);
                    const auto component { json.at("component").get<std::string>() };

                    if (json.at("type") == "state")
                    {

                        if (component == FIM_COMPONENT_REGISTRY_VALUE)
                        {
                            const auto registryType { json.at("data").at("attributes").at("type").get<uint32_t>() };
                            json["data"]["attributes"]["value_type"] = RegistryTypes<OS_TYPE>::typeText(registryType);
                            json["data"]["attributes"]["type"] = "registry_value";
                            json["data"]["value_name"] = json["data"]["attributes"]["name"];
                            json["data"]["attributes"].erase("name");
                        }
                        else
                        {
                            std::string perm_string = json["data"]["attributes"]["perm"];
                            auto perm_json = nlohmann::json::parse(perm_string, nullptr, false);

                            if (!perm_json.is_discarded())
                            {
                                json["data"]["attributes"].erase("perm");
                                json["data"]["attributes"]["perm"] = perm_json;
                            }

                            json["data"]["attributes"]["type"] = "registry_key";
                        }

                        json["data"]["path"] = json["data"]["attributes"]["path"];
                        json["data"]["attributes"].erase("path");
                        json["data"]["arch"] = json["data"]["attributes"]["arch"];
                        json["data"]["attributes"].erase("arch");

                        json["data"]["attributes"].erase("hash_full_path");
                        json["data"]["attributes"].erase("last_event");
                        json["data"]["attributes"].erase("scanned");
                        json["data"]["version"] = 3;

                        FIMDB::instance().setTimeLastSyncMsg();
                    }

                    try
                    {
                        sync_callback(component.c_str(), json.dump().c_str());
                    }
                    catch (std::exception& err)
                    {
                        FIMDB::instance().logFunction(LOG_ERROR, err.what());
                    }
                }
            }
        };
        // LCOV_EXCL_STOP

        std::function<void(modules_log_level_t, const std::string&)> callbackLogWrapper
        {
            [log_callback](modules_log_level_t level, const std::string & log)
            {
                if (log_callback)
                {
                    log_callback(level, log.c_str());
                }
            }
        };

        if (dbsync_log_function)
        {
            dbsync_initialize(dbsync_log_function);
        }

        if (rsync_log_function)
        {
            rsync_initialize(rsync_log_function);
        }

        DB::instance().init(storage,
                            sync_interval,
                            sync_max_interval,
                            sync_response_timeout,
                            callbackSyncFileWrapper,
                            callbackSyncRegistryWrapper,
                            callbackLogWrapper,
                            file_limit,
                            value_limit,
                            sync_registry_enabled,
                            sync_thread_pool,
                            sync_queue_size);
        retVal = FIMDBErrorCode::FIMDB_OK;

    }
    // LCOV_EXCL_START
    catch (const std::exception& ex)
    {
        auto errorMessage { std::string("Error, id: ") + ex.what() };
        log_callback(LOG_ERROR_EXIT, errorMessage.c_str());
    }

    // LCOV_EXCL_STOP
    return retVal;
}

FIMDBErrorCode fim_run_integrity()
{
    auto retval { FIMDB_ERR };

    try
    {
        DB::instance().runIntegrity();
        retval = FIMDB_OK;
    }
    catch (const std::exception& err)
    {
        FIMDB::instance().logFunction(LOG_ERROR, err.what());
    }

    return retval;
}

FIMDBErrorCode fim_sync_push_msg(const char* msg)
{
    auto retval { FIMDB_ERR };

    try
    {
        DB::instance().pushMessage(msg);
        retval = FIMDB_OK;
    }
    // LCOV_EXCL_START
    catch (const std::exception& err)
    {
        FIMDB::instance().logFunction(LOG_ERROR, err.what());
    }

    // LCOV_EXCL_STOP

    return retval;
}

TXN_HANDLE fim_db_transaction_start(const char* table, result_callback_t row_callback, void* user_data)
{
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsInput
    {
        cJSON_Parse(table)
    };

    callback_data_t cb_data = { .callback = row_callback, .user_data = user_data };

    TXN_HANDLE dbsyncTxnHandle = dbsync_create_txn(DB::instance().DBSyncHandle(), jsInput.get(), 0,
                                                   QUEUE_SIZE, cb_data);

    return dbsyncTxnHandle;
}

FIMDBErrorCode fim_db_transaction_sync_row(TXN_HANDLE txn_handler, const fim_entry* entry)
{
    auto retval { FIMDB_ERR };

    if (entry)
    {
        std::unique_ptr<DBItem> syncItem;

        if (entry->type == FIM_TYPE_FILE)
        {
            syncItem = std::make_unique<FileItem>(entry, true);
        }
        else
        {
            if (entry->registry_entry.key == NULL)
            {
                syncItem = std::make_unique<RegistryValue>(entry, true);
            }
            else
            {
                syncItem = std::make_unique<RegistryKey>(entry, true);
            }
        }

        try
        {
            DBSyncTxn txn(txn_handler);
            txn.syncTxnRow(*syncItem->toJSON());
            retval = FIMDB_OK;
        }
        catch (std::exception& err)
        {
            FIMDB::instance().logFunction(LOG_ERROR, err.what());
        }
    }

    return retval;
}

FIMDBErrorCode fim_db_transaction_deleted_rows(TXN_HANDLE txn_handler,
                                               result_callback_t res_callback,
                                               void* txn_ctx)
{
    auto retval {FIMDB_OK};
    callback_data_t cb_data = { .callback = res_callback, .user_data = txn_ctx };

    if (dbsync_get_deleted_rows(txn_handler, cb_data) != 0)
    {
        retval = FIMDB_ERR;
    }

    if (dbsync_close_txn(txn_handler) != 0)
    {
        retval = FIMDB_ERR;
    }

    return retval;
}

void fim_db_teardown()
{
    try
    {
        DB::instance().teardown();
    }
    // LCOV_EXCL_START
    catch (const std::exception& err)
    {
        FIMDB::instance().logFunction(LOG_ERROR, err.what());
    }

    // LCOV_EXCL_STOP
}


#ifdef __cplusplus
}
#endif
