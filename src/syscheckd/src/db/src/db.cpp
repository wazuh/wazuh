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
#include "cJSON.h"
#include "cjsonSmartDeleter.hpp"
#include "commonDefs.h"
#include "db.hpp"
#include "dbFileItem.hpp"
#include "dbItem.hpp"
#include "dbRegistryKey.hpp"
#include "dbRegistryValue.hpp"
#include "dbsync.h"
#include "dbsync.hpp"
#include "fimCommonDefs.h"
#include "fimDB.hpp"
#include "fimDBSpecialization.h"
#include "json.hpp"
#include "logging_helper.h"
#include "syscheck-config.h"
#include "timeHelper.h"
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <functional>
#include <hashHelper.h>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <utility>
#include <vector>

void DB::init(const int storage,
              std::function<void(modules_log_level_t, const std::string&)> callbackLogWrapper,
              const int fileLimit,
              const int valueLimit)
{
    const auto* path {storage == FIM_DB_MEMORY ? FIM_DB_MEMORY_PATH : FIM_DB_DISK_PATH};

    // Schema changes for a database that already exists, in order. DBSync
    // reads PRAGMA user_version and applies everything from there on, one
    // prepared statement per entry -- so each entry holds exactly one
    // statement, and the list is append-only: an agent may skip releases and
    // replays it from wherever its own database stopped.
    //
    // Without this, CreateStatement() is only ever reached by a database being
    // created from nothing, and every upgraded agent silently keeps the schema
    // it already had.
    const std::vector<std::string> upgradeStatements
    {
        // v1 -> v2: store a container's context once, rather than stamping a
        // copy of it onto every file row that container owns.
        CREATE_CONTAINER_CONTEXT_DB_STATEMENT,
    };

    auto dbsyncHandler {std::make_shared<DBSync>(HostType::AGENT,
                                                 DbEngineType::SQLITE3,
                                                 path,
                                                 FIMDBCreator<OS_TYPE>::CreateStatement(),
                                                 DbManagement::PERSISTENT,
                                                 upgradeStatements)};

    FIMDB::instance().init(std::move(callbackLogWrapper), std::move(dbsyncHandler), fileLimit, valueLimit);
}

DBSYNC_HANDLE DB::DBSyncHandle()
{
    return FIMDB::instance().DBSyncHandler()->handle();
}

void DB::teardown()
{
    // The cached contexts describe the contents of THIS database. Keeping them
    // across a teardown would let a re-init against a different database serve
    // a container block the new one never stored.
    fim_db_clear_container_contexts();
    FIMDB::instance().teardown();
}

void DB::closeAndDeleteDatabase()
{
    fim_db_clear_container_contexts();
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

std::vector<nlohmann::json> DB::getDocumentsToPromote(const std::string& tableName, int numberOfDocumentsToPromote)
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
    std::string filter = "WHERE sync = 0";

    if (tableName == FIMDB_FILE_TABLE_NAME)
    {
        orderBy = "container_id, path, version";
        // Container-baselined rows are persisted directly by the baseline flow;
        // the promote machinery builds host-config stateful events, so keep it
        // host-only.
        filter += " AND container_id = ''";
    }
    else if (tableName == FIMDB_REGISTRY_KEY_TABLENAME)
    {
        orderBy = "path, architecture, version";
    }
    else if (tableName == FIMDB_REGISTRY_VALUE_TABLENAME)
    {
        orderBy = "path, architecture, value, version";
    }

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

std::vector<nlohmann::json> DB::getDocumentsToDemote(const std::string& tableName, int numberOfDocumentsToDemote)
{
    std::vector<nlohmann::json> documents;

    // Note: we include the version in the query since we'll pass it to the sync flag update so that it doesn't get
    // increased with the update. We want the version value to stay the same after a sync flag update.
    std::string primaryKeys;
    std::string orderBy;
    std::string filter = "WHERE sync = 1";

    if (tableName == FIMDB_FILE_TABLE_NAME)
    {
        primaryKeys = "container_id, path, version";
        orderBy = "container_id, path, version";
        filter += " AND container_id = ''";
    }
    else if (tableName == FIMDB_REGISTRY_KEY_TABLENAME)
    {
        primaryKeys = "architecture, path, version";
        orderBy = "path, architecture, version";
    }
    else if (tableName == FIMDB_REGISTRY_VALUE_TABLENAME)
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

        DB::init(storage, callbackLogWrapper, file_limit, value_limit);
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
        DB::updateLastSyncTime(table_name, Utils::getSecondsFromEpoch());
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
    try
    {
        const std::unique_ptr<cJSON, CJsonSmartDeleter> jsInput {cJSON_Parse(table)};

        callback_data_t cb_data = {.callback = row_callback, .user_data = user_data};

        TXN_HANDLE dbsyncTxnHandle = dbsync_create_txn(DB::DBSyncHandle(), jsInput.get(), 0, QUEUE_SIZE, cb_data);

        return dbsyncTxnHandle;
    }
    // LCOV_EXCL_START
    catch (const std::exception& ex)
    {
        // DBSyncHandle() throws once the handler has been torn down; this is the only
        // extern "C" entry in this file that let the exception escape into C callers
        // (std::terminate). Callers already handle a NULL transaction handle.
        FIMDB::instance().logFunction(LOG_ERROR, ex.what());
        return nullptr;
    }

    // LCOV_EXCL_STOP
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
fim_db_transaction_sync_row_json(TXN_HANDLE txn_handler, const char* table, const char* row_json)
{
    auto retval {FIMDB_ERR};

    if (table == nullptr || row_json == nullptr)
    {
        return retval;
    }

    const auto row = nlohmann::json::parse(row_json, nullptr, false);

    if (row.is_discarded() || !row.is_object())
    {
        FIMDB::instance().logFunction(LOG_ERROR, "fim_db_transaction_sync_row_json: invalid row JSON");
        return retval;
    }

    try
    {
        nlohmann::json input;
        input["table"] = table;
        input["data"] = nlohmann::json::array({row});

        // MODIFIED must arrive as {"old":..., "new":...}: the container txn
        // callback reads the changed columns out of DBSync's "old" object to
        // build the alert's changed_fields, and without this option DBSync
        // hands it the bare updated row instead. The callback then finds no
        // "new" member and returns, so EVERY modification to an
        // already-known container file is dropped -- and dropped invisibly,
        // because the row itself still converges in file_entry. Host FIM sets
        // the same option for the same reason (dbFileItem.cpp).
        input["options"]["return_old_data"] = true;

        DBSyncTxn txn(txn_handler);
        txn.syncTxnRow(input);
        retval = FIMDB_OK;
    }
    catch (const std::exception& err)
    {
        FIMDB::instance().logFunction(LOG_ERROR, err.what());
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

FIMDBErrorCode fim_db_transaction_close(TXN_HANDLE txn_handler)
{
    return dbsync_close_txn(txn_handler) == 0 ? FIMDB_OK : FIMDB_ERR;
}

static std::atomic<bool (*)()> g_teardown_hook {nullptr};

void fim_db_set_teardown_hook(bool (*hook)())
{
    g_teardown_hook.store(hook);
}

void fim_db_teardown()
{
    // The hook owns the decision: it knows whether a scan transaction is in flight, and
    // DB::teardown() would release the context that transaction is running against.
    if (const auto hook {g_teardown_hook.load()}; hook != nullptr && !hook())
    {
        return;
    }

    try
    {
        DB::teardown();
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
        DB::closeAndDeleteDatabase();
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

/* --- container context -------------------------------------------------- *
 *
 * A container's context is stored once, in container_context, instead of being
 * copied onto every file row that container owns. The rows reference it by
 * container_id.
 *
 * The parsed form is cached because the alternative is worse than what it
 * replaced: the context is needed once per emitted row, and querying the
 * database per row would be far more expensive than the per-row parse this
 * exists to remove. The cache holds the "container" block already parsed and
 * hands out duplicates, so a caller that attaches it to a message owns what it
 * attaches.
 *
 * Cleared on teardown and on database recreation, because the entries describe
 * the contents of a particular database and must not outlive it.
 */
namespace
{
    class ContainerContextCache final
    {
        public:
            static ContainerContextCache& instance()
            {
                static ContainerContextCache s_instance;
                return s_instance;
            }

            /// An owned duplicate of the container's block, or nullptr on a miss.
            cJSON* duplicate(const std::string& containerId) const
            {
                std::lock_guard<std::mutex> lock {m_mutex};
                const auto it = m_blocks.find(containerId);
                return it == m_blocks.end() ? nullptr : cJSON_Duplicate(it->second, 1);
            }

            /// Takes ownership of @p block, freeing whatever it replaces.
            void store(const std::string& containerId, cJSON* block)
            {
                std::lock_guard<std::mutex> lock {m_mutex};
                cJSON*& slot = m_blocks[containerId];
                cJSON_Delete(slot);
                slot = block;
            }

            void erase(const std::string& containerId)
            {
                std::lock_guard<std::mutex> lock {m_mutex};
                const auto it = m_blocks.find(containerId);

                if (it != m_blocks.end())
                {
                    cJSON_Delete(it->second);
                    m_blocks.erase(it);
                }
            }

            void clear()
            {
                std::lock_guard<std::mutex> lock {m_mutex};

                for (auto& entry : m_blocks)
                {
                    cJSON_Delete(entry.second);
                }

                m_blocks.clear();
            }

        private:
            ContainerContextCache() = default;
            ~ContainerContextCache()
            {
                clear();
            }

            mutable std::mutex m_mutex;
            std::map<std::string, cJSON*> m_blocks;
    };

    /// Lifts the "container" block out of a stored context document. Returns an
    /// owned object, or nullptr if the document is not one.
    cJSON* ExtractContainerBlock(const char* contextJson)
    {
        if (contextJson == nullptr || *contextJson == '\0')
        {
            return nullptr;
        }

        cJSON* parsed = cJSON_Parse(contextJson);

        if (parsed == nullptr)
        {
            return nullptr;
        }

        cJSON* block = cJSON_DetachItemFromObject(parsed, "container");
        cJSON_Delete(parsed);
        return block;
    }
}

void fim_db_clear_container_contexts()
{
    ContainerContextCache::instance().clear();
}

int fim_db_set_container_context(const char* container_id, const char* context_json)
{
    if (container_id == nullptr || *container_id == '\0' || context_json == nullptr)
    {
        FIMDB::instance().logFunction(LOG_ERROR, "Invalid parameters");
        return FIMDB_ERR;
    }

    try
    {
        nlohmann::json row;
        row["container_id"] = container_id;
        row["context"] = context_json;

        nlohmann::json input;
        input["table"] = FIMDB_CONTAINER_CONTEXT_TABLE_NAME;
        input["data"] = nlohmann::json::array({row});

        // A no-op callback: writes to this table are not events. Nothing
        // downstream should be told that a container's labels moved, which is
        // the point of keeping the context out of the file rows.
        ResultCallbackData callback {[](ReturnTypeCallback, const nlohmann::json&) {}};
        FIMDB::instance().updateItem(input, callback);

        // Only cached once the write succeeded, so a cache hit always describes
        // something the database holds.
        ContainerContextCache::instance().store(container_id, ExtractContainerBlock(context_json));
    }
    catch (const std::exception& e)
    {
        FIMDB::instance().logFunction(LOG_ERROR, std::string("Could not store container context: ") + e.what());
        ContainerContextCache::instance().erase(container_id);
        return FIMDB_ERR;
    }

    return FIMDB_OK;
}

cJSON* fim_db_get_container_context(const char* container_id)
{
    if (container_id == nullptr || *container_id == '\0')
    {
        return nullptr;
    }

    if (cJSON* cached = ContainerContextCache::instance().duplicate(container_id))
    {
        return cached;
    }

    // A miss is expected once per container per process -- after a restart the
    // cache is cold while the database is not.
    try
    {
        std::string context;

        auto callback = [&context](ReturnTypeCallback result, const nlohmann::json & data)
        {
            if (ReturnTypeCallback::SELECTED != result)
            {
                return;
            }

            const auto it = data.find("context");

            if (it != data.end() && it->is_string())
            {
                context = it->get<std::string>();
            }
        };

        auto selectQuery = SelectQuery::builder()
                           .table(FIMDB_CONTAINER_CONTEXT_TABLE_NAME)
                           .columnList({"context"})
                           .rowFilter("WHERE container_id=?")
                           .rowFilterBindText(container_id)
                           .orderByOpt("")
                           .build();

        FIMDB::instance().executeQuery(selectQuery.query(), callback);

        if (context.empty())
        {
            return nullptr;
        }

        cJSON* block = ExtractContainerBlock(context.c_str());

        if (block == nullptr)
        {
            return nullptr;
        }

        ContainerContextCache::instance().store(container_id, block);
        return cJSON_Duplicate(block, 1);
    }
    catch (const std::exception& e)
    {
        FIMDB::instance().logFunction(LOG_ERROR, std::string("Could not read container context: ") + e.what());
        return nullptr;
    }
}

int fim_db_delete_container_context(const char* container_id)
{
    if (container_id == nullptr || *container_id == '\0')
    {
        return FIMDB_ERR;
    }

    try
    {
        // Bound through the query's data rather than spliced into a filter
        // string: container ids come from a runtime that this code does not
        // own, and a primary key is exactly what this builder binds.
        auto deleteQuery
        {
            DeleteQuery::builder()
            .table(FIMDB_CONTAINER_CONTEXT_TABLE_NAME)
            .data({{"container_id", container_id}})
            .rowFilter("")
            .build()
        };

        FIMDB::instance().removeItem(deleteQuery.query());
        ContainerContextCache::instance().erase(container_id);
    }
    catch (const std::exception& e)
    {
        FIMDB::instance().logFunction(LOG_ERROR, std::string("Could not delete container context: ") + e.what());
        return FIMDB_ERR;
    }

    return FIMDB_OK;
}

int fim_db_prune_container_contexts(const char* const* keep, int keep_count)
{
    // A null list with a positive count is a caller bug, and the damage it
    // would do is deleting every context. Refuse rather than interpret.
    if (keep == nullptr && keep_count > 0)
    {
        FIMDB::instance().logFunction(LOG_ERROR, "Invalid parameters");
        return FIMDB_ERR;
    }

    try
    {
        std::set<std::string> live;

        for (int i = 0; i < keep_count; ++i)
        {
            if (keep[i] != nullptr && *keep[i] != '\0')
            {
                live.insert(keep[i]);
            }
        }

        std::vector<std::string> stored;

        auto callback = [&stored](ReturnTypeCallback result, const nlohmann::json & data)
        {
            if (ReturnTypeCallback::SELECTED != result)
            {
                return;
            }

            const auto it = data.find("container_id");

            if (it != data.end() && it->is_string())
            {
                auto id = it->get<std::string>();

                if (!id.empty())
                {
                    stored.push_back(std::move(id));
                }
            }
        };

        auto selectQuery = SelectQuery::builder()
                           .table(FIMDB_CONTAINER_CONTEXT_TABLE_NAME)
                           .columnList({"container_id"})
                           .rowFilter("")
                           .orderByOpt("")
                           .build();

        FIMDB::instance().executeQuery(selectQuery.query(), callback);

        for (const auto& id : stored)
        {
            if (live.find(id) == live.end())
            {
                fim_db_delete_container_context(id.c_str());
            }
        }
    }
    catch (const std::exception& e)
    {
        FIMDB::instance().logFunction(LOG_ERROR, std::string("Could not prune container contexts: ") + e.what());
        return FIMDB_ERR;
    }

    return FIMDB_OK;
}

cJSON* fim_db_get_distinct_container_ids(const char* table_name)
{
    if (!table_name)
    {
        FIMDB::instance().logFunction(LOG_ERROR, "Invalid parameters");
        return nullptr;
    }

    cJSON* result_array = nullptr;

    try
    {
        std::vector<std::string> ids;

        auto callback = [&ids](ReturnTypeCallback result, const nlohmann::json & data)
        {
            if (ReturnTypeCallback::SELECTED != result)
            {
                return;
            }

            const auto it = data.find(FIMDB_FILE_CONTAINER_ID_COLUMN);

            if (it != data.end() && it->is_string())
            {
                auto id = it->get<std::string>();

                if (!id.empty())
                {
                    ids.push_back(std::move(id));
                }
            }
        };

        // One projected column with DISTINCT, so the engine returns at most one
        // row per container instead of one row per file.
        auto selectQuery = SelectQuery::builder()
                           .table(table_name)
                           .columnList({FIMDB_FILE_CONTAINER_ID_COLUMN})
                           .rowFilter(std::string("WHERE ") + FIMDB_FILE_CONTAINER_ID_COLUMN + " != ''")
                           .orderByOpt("")
                           .distinctOpt(true)
                           .build();

        FIMDB::instance().executeQuery(selectQuery.query(), callback);

        result_array = cJSON_CreateArray();

        if (!result_array)
        {
            FIMDB::instance().logFunction(LOG_ERROR, "Failed to create cJSON array");
            return nullptr;
        }

        for (const auto& id : ids)
        {
            cJSON* item = cJSON_CreateString(id.c_str());

            if (!item)
            {
                FIMDB::instance().logFunction(LOG_ERROR, "Failed to create cJSON string");
                cJSON_Delete(result_array);
                return nullptr;
            }

            cJSON_AddItemToArray(result_array, item);
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
        DBSync dbSync(DB::DBSyncHandle());
        std::string checksum = dbSync.calculateTableChecksum(table_name, "WHERE sync = 1");
        result = strdup(checksum.c_str());
    }
    catch (const std::exception& err)
    {
        FIMDB::instance().logFunction(LOG_ERROR, err.what());
    }

    return result;
}

bool fim_db_try_get_last_sync_time(const char* table_name, int64_t* out_value)
{
    if (!table_name || !out_value)
    {
        FIMDB::instance().logFunction(LOG_ERROR, "Invalid parameters");
        return false;
    }

    try
    {
        *out_value = DB::getLastSyncTime(table_name);
        return true;
    }
    catch (const std::exception& err)
    {
        // Reported rather than folded into a zero: a caller that adopts an id on "absent" must
        // not do so because the database was momentarily unreadable.
        FIMDB::instance().logFunction(LOG_ERROR, err.what());
        return false;
    }
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
        result = DB::getLastSyncTime(table_name);
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
        DB::updateLastSyncTime(table_name, timestamp);
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
        return DB::countSyncedDocs(table_name);
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
        std::vector<nlohmann::json> items = DB::getDocumentsToPromote(table_name, documents);

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
        std::vector<nlohmann::json> items = DB::getDocumentsToDemote(table_name, documents);

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
