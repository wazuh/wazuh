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

#include "db.h"
#include "cjsonSmartDeleter.hpp"
#include "commonDefs.h"
#include "db.hpp"
#include "dbFileItem.hpp"
#include "dbRegistryKey.hpp"
#include "dbRegistryValue.hpp"
#include "dbsync.h"
#include "dbsync.hpp"
#include "fimCommonDefs.h"
#include "fimDB.hpp"
#include "fimDBSpecialization.h"
#include <hashHelper.h>
#include "stringHelper.h"
#include "timeHelper.h"

void DB::init(const int storage,
              std::function<void(modules_log_level_t, const std::string&)> callbackLogWrapper,
              const int fileLimit,
              const int valueLimit)
{
    auto path {storage == FIM_DB_MEMORY ? FIM_DB_MEMORY_PATH : FIM_DB_DISK_PATH};
    auto dbsyncHandler {std::make_shared<DBSync>(HostType::AGENT,
                                                 DbEngineType::SQLITE3,
                                                 path,
                                                 FIMDBCreator<OS_TYPE>::CreateStatement(),
                                                 DbManagement::PERSISTENT)};

    FIMDB::instance().init(callbackLogWrapper, dbsyncHandler, fileLimit, valueLimit);

    initializeTableMetadata();
}

DBSYNC_HANDLE DB::DBSyncHandle()
{
    return FIMDB::instance().DBSyncHandler()->handle();
}

void DB::teardown()
{
    FIMDB::instance().teardown();
}

void DB::closeAndDeleteDatabase()
{
    FIMDB::instance().closeAndDeleteDatabase();
}

const std::map<COUNT_SELECT_TYPE, std::vector<std::string>> COUNT_SELECT_TYPE_MAP
{
    {COUNT_SELECT_TYPE::COUNT_ALL, {"count(*) AS count"}},
    {COUNT_SELECT_TYPE::COUNT_INODE, {"count(DISTINCT (inode || ',' || device)) AS count"}},
};

int DB::countEntries(const std::string& tableName, const COUNT_SELECT_TYPE selectType)
{
    auto count {0};
    auto callback {[&count](ReturnTypeCallback type, const nlohmann::json & jsonResult)
    {
        if (ReturnTypeCallback::SELECTED == type)
        {
            count = jsonResult.at("count");
        }
    }};

    auto selectQuery {SelectQuery::builder()
                      .table(tableName)
                      .columnList(COUNT_SELECT_TYPE_MAP.at(selectType))
                      .rowFilter("")
                      .orderByOpt("")
                      .distinctOpt(false)
                      .build()};

    FIMDB::instance().executeQuery(selectQuery.query(), callback);

    return count;
}

std::string DB::getConcatenatedChecksums(const std::string& tableName)
{
    std::string concatenatedChecksums;

    auto callback {[&concatenatedChecksums](ReturnTypeCallback type, const nlohmann::json & jsonResult)
    {
        if (ReturnTypeCallback::SELECTED == type)
        {
            concatenatedChecksums += jsonResult.at("checksum").get<std::string>();
        }
    }};

    auto selectQuery {SelectQuery::builder()
                      .table(tableName)
                      .columnList({"checksum"})
                      .orderByOpt({"checksum"})
                      .rowFilter("")
                      .distinctOpt(false)
                      .build()};

    FIMDB::instance().executeQuery(selectQuery.query(), callback);

    return concatenatedChecksums;
}

std::string DB::calculateTableChecksum(const char* table_name)
{
    std::string concatenated_checksums = DB::instance().getConcatenatedChecksums(table_name);

    // Build checksum-of-checksums
    Utils::HashData hash(Utils::HashType::Sha1);
    std::string final_checksum;

    try
    {
        hash.update(concatenated_checksums.c_str(), concatenated_checksums.length());
        const std::vector<unsigned char> hashResult = hash.hash();
        final_checksum = Utils::asciiToHex(hashResult);
    }
    // LCOV_EXCL_START
    catch (const std::exception& e)
    {
        throw std::runtime_error{"Error calculating hash: " + std::string(e.what())};
    }

    // LCOV_EXCL_STOP


    return final_checksum;
}

std::vector<nlohmann::json> DB::getEveryElement(const std::string& tableName)
{
    std::vector<nlohmann::json> recoveryItems;
    auto callback {[&recoveryItems](ReturnTypeCallback type, const nlohmann::json & jsonResult)
    {
        if (ReturnTypeCallback::SELECTED == type)
        {
            recoveryItems.push_back(jsonResult);
        }
    }};
    auto selectQuery {SelectQuery::builder()
                      .table(tableName)
                      .columnList({"*"})
                      .build()};

    FIMDB::instance().executeQuery(selectQuery.query(), callback);
    return recoveryItems;
}

void DB::initializeTableMetadata()
{
    auto emptyCallback = [](ReturnTypeCallback, const nlohmann::json&) {};

    // Check if metadata entries already exist by querying the table
    bool fileEntryExists = false;

    auto checkCallback = [&fileEntryExists](ReturnTypeCallback result, const nlohmann::json&)
    {
        if (result == ReturnTypeCallback::SELECTED)
        {
            fileEntryExists = true;
        }
    };

    auto checkQuery = SelectQuery::builder()
                      .table("table_metadata")
                      .columnList({"table_name"})
                      .rowFilter("WHERE table_name = 'file_entry'")
                      .build();

    FIMDB::instance().executeQuery(checkQuery.query(), checkCallback);

    // Only insert if the entry doesn't exist
    if (!fileEntryExists)
    {
        auto fileEntrySyncQuery = SyncRowQuery::builder()
                                  .table("table_metadata")
        .data(nlohmann::json{{"table_name", "file_entry"}, {"last_sync_time", 0}})
        .build();
        FIMDB::instance().updateItem(fileEntrySyncQuery.query(), emptyCallback);
    }

#ifdef WIN32
    bool registryKeyExists = false;
    auto checkRegistryKeyCallback = [&registryKeyExists](ReturnTypeCallback result, const nlohmann::json&)
    {
        if (result == ReturnTypeCallback::SELECTED)
        {
            registryKeyExists = true;
        }
    };

    auto checkRegistryKeyQuery = SelectQuery::builder()
                                 .table("table_metadata")
                                 .columnList({"table_name"})
                                 .rowFilter("WHERE table_name = 'registry_key'")
                                 .build();

    FIMDB::instance().executeQuery(checkRegistryKeyQuery.query(), checkRegistryKeyCallback);

    if (!registryKeyExists)
    {
        auto registryKeySyncQuery = SyncRowQuery::builder()
                                    .table("table_metadata")
        .data(nlohmann::json{{"table_name", "registry_key"}, {"last_sync_time", 0}})
        .build();
        FIMDB::instance().updateItem(registryKeySyncQuery.query(), emptyCallback);
    }

    bool registryDataExists = false;
    auto checkRegistryDataCallback = [&registryDataExists](ReturnTypeCallback result, const nlohmann::json&)
    {
        if (result == ReturnTypeCallback::SELECTED)
        {
            registryDataExists = true;
        }
    };

    auto checkRegistryDataQuery = SelectQuery::builder()
                                  .table("table_metadata")
                                  .columnList({"table_name"})
                                  .rowFilter("WHERE table_name = 'registry_data'")
                                  .build();

    FIMDB::instance().executeQuery(checkRegistryDataQuery.query(), checkRegistryDataCallback);

    if (!registryDataExists)
    {
        auto registryDataSyncQuery = SyncRowQuery::builder()
                                     .table("table_metadata")
        .data(nlohmann::json{{"table_name", "registry_data"}, {"last_sync_time", 0}})
        .build();
        FIMDB::instance().updateItem(registryDataSyncQuery.query(), emptyCallback);
    }

#endif
}

void DB::updateLastSyncTime(const std::string& tableName, int64_t timestamp)
{
    auto emptyCallback = [](ReturnTypeCallback, const nlohmann::json&) {};

    auto syncQuery = SyncRowQuery::builder()
                     .table("table_metadata")
    .data(nlohmann::json{{"table_name", tableName}, {"last_sync_time", timestamp}})
    .build();

    FIMDB::instance().updateItem(syncQuery.query(), emptyCallback);
}

int64_t DB::getLastSyncTime(const std::string& tableName)
{
    int64_t lastSyncTime = 0;

    auto callback = [&lastSyncTime](ReturnTypeCallback result, const nlohmann::json & data)
    {
        if (result == ReturnTypeCallback::SELECTED && data.contains("last_sync_time"))
        {
            lastSyncTime = data.at("last_sync_time").get<int64_t>();
        }
    };

    auto selectQuery = SelectQuery::builder()
                       .table("table_metadata")
                       .columnList({"last_sync_time"})
                       .rowFilter("WHERE table_name = '" + tableName + "'")
                       .build();

    FIMDB::instance().executeQuery(selectQuery.query(), callback);

    return lastSyncTime;
}

#ifdef __cplusplus
extern "C"
{
#endif
FIMDBErrorCode fim_db_init(
    int storage, logging_callback_t log_callback, int file_limit, int value_limit, log_fnc_t dbsync_log_function)
{
    auto retVal {FIMDBErrorCode::FIMDB_ERR};

    try
    {
        std::function<void(modules_log_level_t, const std::string&)> callbackLogWrapper
        {
            [log_callback](modules_log_level_t level, const std::string & log)
            {
                if (log_callback)
                {
                    log_callback(level, log.c_str());
                }
            }};

        if (dbsync_log_function)
        {
            dbsync_initialize(dbsync_log_function);
        }

        DB::instance().init(storage, callbackLogWrapper, file_limit, value_limit);
        retVal = FIMDBErrorCode::FIMDB_OK;
    }
    // LCOV_EXCL_START
    catch (const std::exception& ex)
    {
        auto errorMessage {std::string("Error, id: ") + ex.what()};
        log_callback(LOG_ERROR_EXIT, errorMessage.c_str());
    }

    // LCOV_EXCL_STOP
    return retVal;
}

void fim_db_update_last_sync_time(const char* table_name)
{
    try
    {
        DB::instance().updateLastSyncTime(table_name, Utils::getSecondsFromEpoch());
    }
    catch (const std::exception& ex)
    {
        // Log error but don't exit - this is not critical
        // The worst case is the integrity check runs again sooner than expected
    }
}

TXN_HANDLE fim_db_transaction_start(const char* table, result_callback_t row_callback, void* user_data)
{
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsInput {cJSON_Parse(table)};

    callback_data_t cb_data = {.callback = row_callback, .user_data = user_data};

    TXN_HANDLE dbsyncTxnHandle =
        dbsync_create_txn(DB::instance().DBSyncHandle(), jsInput.get(), 0, QUEUE_SIZE, cb_data);

    return dbsyncTxnHandle;
}

FIMDBErrorCode fim_db_transaction_sync_row(TXN_HANDLE txn_handler, const fim_entry* entry)
{
    auto retval {FIMDB_ERR};

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

FIMDBErrorCode
fim_db_transaction_deleted_rows(TXN_HANDLE txn_handler, result_callback_t res_callback, void* txn_ctx)
{
    auto retval {FIMDB_OK};
    callback_data_t cb_data = {.callback = res_callback, .user_data = txn_ctx};

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

void fim_db_close_and_delete_database()
{
    try
    {
        DB::instance().closeAndDeleteDatabase();
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
