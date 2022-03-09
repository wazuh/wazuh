/*
 * Wazuh Syscheck
 * Copyright (C) 2015-2021, Wazuh Inc.
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

void DB::init(const int storage,
              const int syncInterval,
              std::function<void(const std::string&)> callbackSyncFileWrapper,
              std::function<void(const std::string&)> callbackSyncRegistryWrapper,
              std::function<void(modules_log_level_t, const std::string&)> callbackLogWrapper,
              const int fileLimit,
              const int valueLimit,
              bool syncRegistryEnabled)
{
    auto path { storage == FIM_DB_MEMORY ? FIM_DB_MEMORY_PATH : FIM_DB_DISK_PATH };
    auto dbsyncHandler
    {
        std::make_shared<DBSync>(HostType::AGENT, DbEngineType::SQLITE3, path,
                                 FIMDBCreator<OS_TYPE>::CreateStatement())
    };

    auto rsyncHandler { std::make_shared<RemoteSync>() };

    FIMDB::instance().init(syncInterval,
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
void fim_db_init(int storage,
                 int sync_interval,
                 fim_sync_callback_t sync_callback,
                 logging_callback_t log_callback,
                 int file_limit,
                 int value_limit,
                 bool sync_registry_enabled)
{
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
                        json["data"]["attributes"]["type"] = "file";
                        json["data"]["attributes"].erase("dev");
                        json["data"]["attributes"].erase("last_event");
                        json["data"]["attributes"].erase("mode");
                        json["data"]["attributes"].erase("options");
                        json["data"]["attributes"].erase("path");
                        json["data"]["attributes"].erase("scanned");
                        // Type different from server.
                        json["data"]["attributes"]["gid"] = std::to_string(json.at("data").at("attributes").at("gid")
                                                                           .get<int>());
                        json["data"]["attributes"]["uid"] = std::to_string(json.at("data").at("attributes").at("uid")
                                                                           .get<int>());
                    }

                    sync_callback(FIM_COMPONENT_FILE, json.dump().c_str());
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

                    if (json.at("type") == "state")
                    {
                        enum REG_TYPE { REG_KEY, REG_VALUE };
                        const auto fullPath { json.at("data").at("index").get_ref<const std::string&>() };
                        const std::string arch { Utils::startsWith(fullPath, "[x32]") ? "[x32]" : "[x64]" };
                        const auto rawKeyValue { fullPath.substr(arch.size() + 1) };
                        const auto keyValue { Utils::splitKeyValueNonEscapedDelimiter(rawKeyValue, ':', '\\') };

                        const auto type { json.at("data").at("attributes").at("type").get<uint32_t>() };

                        if (type == REG_VALUE)
                        {
                            const auto registryType { json.at("data").at("attributes").at("value_type").get<uint32_t>() };
                            json["data"]["value_name"] = keyValue.second;
                            json["data"]["attributes"]["value_type"] = RegistryTypes<OS_TYPE>::typeText(registryType);
                            json["data"]["attributes"]["type"] = "registry_value";
                        }
                        else
                        {
                            json["data"]["attributes"]["type"] = "registry_key";
                            json["data"]["attributes"]["gid"] = std::to_string(json.at("data").at("attributes").at("gid")
                                                                               .get<uint32_t>());
                            json["data"]["attributes"]["uid"] = std::to_string(json.at("data").at("attributes").at("uid")
                                                                               .get<uint32_t>());
                        }

                        json["data"]["attributes"].erase("path");
                        json["data"]["attributes"].erase("last_event");
                        json["data"]["arch"] = arch;
                        json["data"]["version"] = 2;
                        auto key = keyValue.first;
                        Utils::replaceAll(key, "\\\\", "\\");
                        json["data"]["index"] = key;
                    }

                    sync_callback(FIM_COMPONENT_REGISTRY, json.dump().c_str());
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
        DB::instance().init(storage,
                            sync_interval,
                            callbackSyncFileWrapper,
                            callbackSyncRegistryWrapper,
                            callbackLogWrapper,
                            file_limit,
                            value_limit,
                            sync_registry_enabled);

    }
    // LCOV_EXCL_START
    catch (const std::exception& ex)
    {
        auto errorMessage { std::string("Error, id: ") + ex.what() };
        log_callback(LOG_ERROR_EXIT, errorMessage.c_str());
    }

    // LCOV_EXCL_STOP
}

void fim_run_integrity()
{
    try
    {
        DB::instance().runIntegrity();
    }
    catch (const std::exception& err)
    {
        FIMDB::instance().logFunction(LOG_ERROR, err.what());
    }
}

void fim_sync_push_msg(const char* msg)
{
    try
    {
        DB::instance().pushMessage(msg);
    }
    // LCOV_EXCL_START
    catch (const std::exception& err)
    {
        FIMDB::instance().logFunction(LOG_ERROR, err.what());
    }

    // LCOV_EXCL_STOP
}

TXN_HANDLE fim_db_transaction_start(const char* table, result_callback_t row_callback, void* user_data)
{
    const std::unique_ptr<cJSON, CJsonDeleter> jsInput
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

        const std::unique_ptr<cJSON, CJsonDeleter> jsInput
        {
            cJSON_Parse((*syncItem->toJSON()).dump().c_str())
        };

        if (dbsync_sync_txn_row(txn_handler, jsInput.get()) == 0)
        {
            retval = FIMDB_OK;
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
    const std::unique_ptr<cJSON, CJsonDeleter> jsOptions
    {
        cJSON_Parse(GetDeletedQuery::builder().allColumns().query().dump().c_str())
    };

    if (dbsync_get_deleted_rows(txn_handler, cb_data, jsOptions.get()) != 0)
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
