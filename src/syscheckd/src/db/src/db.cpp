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
#include "stringHelper.h"
#include "timeHelper.h"
#include <hashHelper.h>

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

    FIMDB::instance().init(std::move(callbackLogWrapper), dbsyncHandler, fileLimit, valueLimit);
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

void DB::updateLastSyncTime(const std::string& tableName, int64_t timestamp)
{
    auto emptyCallback = [](ReturnTypeCallback, const nlohmann::json&) {};

    auto syncQuery = SyncRowQuery::builder()
                     .table("table_metadata")
    .data(nlohmann::json {{"table_name", tableName}, {"last_sync_time", timestamp}})
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

int DB::maxVersion(const std::string& tableName)
{
    auto maxVer {0};
    auto callback {[&maxVer](ReturnTypeCallback type, const nlohmann::json & jsonResult)
    {
        if (ReturnTypeCallback::SELECTED == type)
        {
            if (jsonResult.contains("max_version") && !jsonResult.at("max_version").is_null())
            {
                maxVer = jsonResult.at("max_version");
            }
        }
    }};

    auto selectQuery {SelectQuery::builder()
                      .table(tableName)
                      .columnList({"MAX(version) AS max_version"})
                      .rowFilter("")
                      .orderByOpt("")
                      .distinctOpt(false)
                      .build()};

    FIMDB::instance().executeQuery(selectQuery.query(), callback);

    return maxVer;
}

int DB::updateVersion(const std::string& tableName, int version)
{
    // Use dbsync to update all rows by setting version field
    // We'll select all primary keys and update each row

    int retval {0};
    std::vector<nlohmann::json> rows;
    auto callback {[&rows](ReturnTypeCallback type, const nlohmann::json & jsonResult)
    {
        if (ReturnTypeCallback::SELECTED == type)
        {
            rows.push_back(jsonResult);
        }
    }};

    try
    {
        // Select all rows (only primary keys and version column)
        auto selectQuery {SelectQuery::builder()
                          .table(tableName)
                          .columnList({"*"}) // Get all columns to properly identify rows
                          .rowFilter("")
                          .orderByOpt("")
                          .distinctOpt(false)
                          .build()};

        FIMDB::instance().executeQuery(selectQuery.query(), callback);
    }
    catch (const std::exception& ex)
    {
        FIMDB::instance().logFunction(LOG_ERROR, std::string("Error selecting rows for version update: ") + ex.what());
        return -1;
    }

    // Update version for each row
    for (auto& row : rows)
    {
        row["version"] = version;

        // Use syncRow to update the entry
        auto updateCallback {[](ReturnTypeCallback, const nlohmann::json&) {}};

        auto syncQuery {SyncRowQuery::builder().table(tableName).data(row).build()};

        try
        {
            FIMDB::instance().updateItem(syncQuery.query(), updateCallback);
        }
        catch (const std::exception& ex)
        {
            FIMDB::instance().logFunction(LOG_ERROR, std::string("Error updating version: ") + ex.what());
            retval = -1;
        }
    }

    return retval;
}

int DB::countSyncedDocs(const std::string& tableName)
{
    int syncedRows = 0;
    auto callback {[&syncedRows](ReturnTypeCallback type, const nlohmann::json & jsonResult)
    {
        if (ReturnTypeCallback::SELECTED == type)
        {
            syncedRows = jsonResult.at("count");
        }
    }};

    const std::string filter = "WHERE sync = 1";
    auto selectQuery {SelectQuery::builder()
                      .table(tableName)
                      .columnList(COUNT_SELECT_TYPE_MAP.at(COUNT_SELECT_TYPE::COUNT_ALL))
                      .rowFilter(filter)
                      .orderByOpt("")
                      .distinctOpt(false)
                      .build()};

    FIMDB::instance().executeQuery(selectQuery.query(), callback);

    return syncedRows;
}

std::vector<nlohmann::json> DB::getDocumentsToPromote(std::string tableName, int numberOfDocumentsToPromote)
{
    std::vector<nlohmann::json> documents;

    // Select all columns so we can build full stateful events for promoted documents
    auto callback {[&documents](ReturnTypeCallback type, const nlohmann::json & jsonResult)
    {
        if (ReturnTypeCallback::SELECTED == type)
        {
            documents.push_back(jsonResult);
        }
    }};

    // Determine ORDER BY based on table primary keys for deterministic results
    std::string orderBy;

    if (tableName == FIMDB_FILE_TABLE_NAME)
    {
        orderBy = "path, version";
    }
    else if (tableName == FIMDB_REGISTRY_KEY_TABLENAME)
    {
        orderBy = "path, architecture, version";
    }
    else if (tableName == FIMDB_REGISTRY_VALUE_TABLENAME)
    {
        orderBy = "path, architecture, value, version";
    }

    const std::string filter = "WHERE sync = 0";
    auto selectQuery {SelectQuery::builder()
                      .table(tableName)
                      .columnList({"*"})
                      .rowFilter(filter)
                      .orderByOpt(orderBy)
                      .countOpt(numberOfDocumentsToPromote)
                      .distinctOpt(false)
                      .build()};

    FIMDB::instance().executeQuery(selectQuery.query(), callback);
    return documents;
}

std::vector<nlohmann::json> DB::getDocumentsToDemote(std::string tableName, int numberOfDocumentsToDemote)
{
    std::vector<nlohmann::json> documents;

    // Note: we include the version in the query since we'll pass it to the sync flag update so that it doesn't get increased with the update. We want the version value to stay the same after a sync flag update.
    std::string primaryKeys;
    std::string orderBy;

    if (tableName == FIMDB_FILE_TABLE_NAME )
    {
        primaryKeys = "path, version";
        orderBy = "path, version";
    }
    else if (tableName == FIMDB_REGISTRY_KEY_TABLENAME )
    {
        primaryKeys = "architecture, path, version";
        orderBy = "path, architecture, version";
    }
    else if (tableName == FIMDB_REGISTRY_VALUE_TABLENAME )
    {
        primaryKeys = "path, architecture, value, version";
        orderBy = "path, architecture, value, version";
    }

    auto callback {[&documents](ReturnTypeCallback type, const nlohmann::json & jsonResult)
    {
        if (ReturnTypeCallback::SELECTED == type)
        {
            documents.push_back(jsonResult);
        }
    }};

    const std::string filter = "WHERE sync = 1";
    auto selectQuery {SelectQuery::builder()
                      .table(tableName)
                      .columnList({primaryKeys})
                      .rowFilter(filter)
                      .orderByOpt(orderBy)
                      .countOpt(numberOfDocumentsToDemote)
                      .distinctOpt(false)
                      .build()};

    FIMDB::instance().executeQuery(selectQuery.query(), callback);
    return documents;
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
        log_callback(LOG_ERROR, errorMessage.c_str());
        retVal = FIMDBErrorCode::FIMDB_ERR;
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
        FIMDB::instance().logFunction(LOG_ERROR, ex.what());
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
            if (entry->registry_entry.key == nullptr)
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

int fim_db_increase_each_entry_version(const char* table_name)
{
    if (!table_name)
    {
        FIMDB::instance().logFunction(LOG_ERROR, "Invalid parameters");
        return -1;
    }

    try
    {
        FIMDB::instance().DBSyncHandler()->increaseEachEntryVersion(table_name);
        return 0;
    }
    // LCOV_EXCL_START
    catch (const std::exception& err)
    {
        FIMDB::instance().logFunction(LOG_ERROR, err.what());
        return -1;
    }

    // LCOV_EXCL_STOP
}
cJSON* fim_db_get_every_element(const char* table_name, const char* row_filter)
{
    if (!table_name)
    {
        FIMDB::instance().logFunction(LOG_ERROR, "Invalid parameters");
        return nullptr;
    }

    cJSON* result_array = nullptr;

    try
    {
        std::string filter = (row_filter && row_filter[0] != '\0') ? row_filter : "";
        std::vector<nlohmann::json> items;

        // Use SelectQuery to get elements with optional filter
        auto callback = [&items](ReturnTypeCallback result, const nlohmann::json & data)
        {
            if (ReturnTypeCallback::SELECTED == result)
            {
                items.push_back(data);
            }
        };

        auto selectQuery = SelectQuery::builder()
                           .table(table_name)
                           .columnList({"*"})
                           .rowFilter(filter)
                           .orderByOpt("")
                           .distinctOpt(false)
                           .build();

        FIMDB::instance().executeQuery(selectQuery.query(), callback);

        result_array = cJSON_CreateArray();

        if (!result_array)
        {
            FIMDB::instance().logFunction(LOG_ERROR, "Failed to create cJSON array");
            return nullptr;
        }

        size_t processed = 0;

        for (const auto& item : items)
        {
            // Convert nlohmann::json to cJSON for C compatibility
            std::string json_str = item.dump();
            cJSON* c_json = cJSON_Parse(json_str.c_str());

            if (c_json)
            {
                cJSON_AddItemToArray(result_array, c_json);
                processed++;
            }
            else
            {
                // Critical: If ANY item fails to parse, the entire result is invalid
                // Returning partial data could cause incomplete sync/recovery operations
                FIMDB::instance().logFunction(LOG_ERROR,
                                              std::string("Failed to parse JSON item ") +
                                              std::to_string(processed) + "/" + std::to_string(items.size()) +
                                              " from table " + table_name + ". Aborting to prevent data loss.");
                cJSON_Delete(result_array);
                return nullptr;
            }
        }
    }
    catch (const std::exception& err)
    {
        FIMDB::instance().logFunction(LOG_ERROR, err.what());

        if (result_array)
        {
            cJSON_Delete(result_array);
        }

        return nullptr;
    }

    return result_array;
}

char* fim_db_calculate_table_checksum(const char* table_name)
{
    char* result = nullptr;

    if (!table_name)
    {
        FIMDB::instance().logFunction(LOG_ERROR, "Invalid parameters");
        return nullptr;
    }

    try
    {
        DBSync dbSync(DB::instance().DBSyncHandle());
        std::string checksum = dbSync.calculateTableChecksum(table_name, "WHERE sync = 1");
        result = strdup(checksum.c_str());
    }
    catch (const std::exception& err)
    {
        FIMDB::instance().logFunction(LOG_ERROR, err.what());
    }

    return result;
}

int64_t fim_db_get_last_sync_time(const char* table_name)
{
    int64_t result = 0;

    if (!table_name)
    {
        FIMDB::instance().logFunction(LOG_ERROR, "Invalid parameters");
        return 0;
    }

    try
    {
        result = DB::instance().getLastSyncTime(table_name);
    }
    catch (const std::exception& err)
    {
        FIMDB::instance().logFunction(LOG_ERROR, err.what());
    }

    return result;
}

void fim_db_update_last_sync_time_value(const char* table_name, int64_t timestamp)
{
    if (!table_name)
    {
        FIMDB::instance().logFunction(LOG_ERROR, "Invalid parameters");
        return;
    }

    try
    {
        DB::instance().updateLastSyncTime(table_name, timestamp);
    }
    catch (const std::exception& err)
    {
        FIMDB::instance().logFunction(LOG_ERROR, err.what());
    }
}

int fim_db_count_synced_docs(const char* table_name)
{
    if (!table_name)
    {
        FIMDB::instance().logFunction(LOG_ERROR, "Invalid parameters");
        return 0;
    }

    try
    {
        return DB::instance().countSyncedDocs(table_name);
    }
    catch (const std::exception& err)
    {
        FIMDB::instance().logFunction(LOG_ERROR, err.what());
        return 0;
    }
}

cJSON* fim_db_get_documents_to_promote(char* table_name, int documents)
{
    cJSON* result_array = NULL;

    try
    {
        std::vector<nlohmann::json> items = DB::instance().getDocumentsToPromote(table_name, documents);

        result_array = cJSON_CreateArray();

        if (!result_array)
        {
            FIMDB::instance().logFunction(LOG_ERROR, "Failed to create cJSON array");
            return NULL;
        }

        // Convert each nlohmann::json to cJSON and add to array
        for (const auto& item : items)
        {
            // Convert nlohmann::json to string, then parse as cJSON
            std::string json_str = item.dump();
            cJSON* c_json = cJSON_Parse(json_str.c_str());

            if (c_json)
            {
                cJSON_AddItemToArray(result_array, c_json);
            }
            else
            {
                FIMDB::instance().logFunction(LOG_ERROR, "Failed to parse JSON item");
                cJSON_Delete(result_array);
                return NULL;
            }
        }

        return result_array;
    }
    catch (const std::exception& err)
    {
        FIMDB::instance().logFunction(LOG_ERROR, err.what());

        if (result_array)
        {
            cJSON_Delete(result_array);
        }

        return NULL;
    }
}

cJSON* fim_db_get_documents_to_demote(char* table_name, int documents)
{
    cJSON* result_array = NULL;

    try
    {
        std::vector<nlohmann::json> items = DB::instance().getDocumentsToDemote(table_name, documents);

        result_array = cJSON_CreateArray();

        if (!result_array)
        {
            FIMDB::instance().logFunction(LOG_ERROR, "Failed to create cJSON array");
            return NULL;
        }

        // Convert each nlohmann::json to cJSON and add to array
        for (const auto& item : items)
        {
            // Convert nlohmann::json to string, then parse as cJSON
            std::string json_str = item.dump();
            cJSON* c_json = cJSON_Parse(json_str.c_str());

            if (c_json)
            {
                cJSON_AddItemToArray(result_array, c_json);
            }
            else
            {
                FIMDB::instance().logFunction(LOG_ERROR, "Failed to parse JSON item");
                cJSON_Delete(result_array);
                return NULL;
            }
        }

        return result_array;
    }
    catch (const std::exception& err)
    {
        FIMDB::instance().logFunction(LOG_ERROR, err.what());

        if (result_array)
        {
            cJSON_Delete(result_array);
        }

        return NULL;
    }
}
#ifdef __cplusplus
}
#endif
