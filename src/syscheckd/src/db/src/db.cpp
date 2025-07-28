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
}

DBSYNC_HANDLE DB::DBSyncHandle()
{
    return FIMDB::instance().DBSyncHandler()->handle();
}

void DB::teardown()
{
    FIMDB::instance().teardown();
}

const std::map<COUNT_SELECT_TYPE, std::vector<std::string>> COUNT_SELECT_TYPE_MAP {
    {COUNT_SELECT_TYPE::COUNT_ALL, {"count(*) AS count"}},
    {COUNT_SELECT_TYPE::COUNT_INODE, {"count(DISTINCT (inode || ',' || device)) AS count"}},
};

int DB::countEntries(const std::string& tableName, const COUNT_SELECT_TYPE selectType)
{
    auto count {0};
    auto callback {[&count](ReturnTypeCallback type, const nlohmann::json& jsonResult)
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
            std::function<void(modules_log_level_t, const std::string&)> callbackLogWrapper {
                [log_callback](modules_log_level_t level, const std::string& log)
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

#ifdef __cplusplus
}
#endif
