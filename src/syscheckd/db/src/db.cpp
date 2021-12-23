/**
 * @file db.cpp
 * @brief Definition of FIM database library.
 * @date 2019-08-28
 *
 * @copyright Copyright (C) 2015-2021 Wazuh, Inc.
 */

#include "dbsync.hpp"
#include "dbsync.h"
#include "db.h"
#include "fimCommonDefs.h"
#include "fimDB.hpp"
#include "fimDBHelper.hpp"
#include <thread>
#include "dbFileItem.hpp"

#ifdef WIN32
#include "dbRegistryKey.hpp"
#include "dbRegistryValue.hpp"
#endif

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


#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Create the statement string to create the dbsync schema.
 *
 * @return char* Contains the dbsync's schema for FIM db.
 */
static char* CreateStatement()
{
    std::string ret = CREATE_FILE_DB_STATEMENT;
#ifdef WIN32
    ret += CREATE_REGISTRY_KEY_DB_STATEMENT;
    ret += CREATE_REGISTRY_VALUE_DB_STATEMENT;
#endif
    char* statement_cstr = new char[ret.length() + 1];

    std::strcpy(statement_cstr, ret.c_str());
    return statement_cstr;
}

#ifndef WIN32
void fim_db_init(int storage,
                 int sync_interval,
                 int file_limit,
                 fim_sync_callback_t sync_callback,
                 logging_callback_t log_callback)
#else
void fim_db_init(int storage,
                 int sync_interval,
                 int file_limit,
                 int value_limit,
                 fim_sync_callback_t sync_callback,
                 logging_callback_t log_callback)
#endif
{
    try
    {
        const std::unique_ptr<char[]> createQuery
        {
            CreateStatement()
        };

        auto path = (storage == FIM_DB_MEMORY) ? FIM_DB_MEMORY_PATH : FIM_DB_DISK_PATH;
        auto dbsyncHandler = std::make_shared<DBSync>(HostType::AGENT, DbEngineType::SQLITE3, path, createQuery.get());
        auto rsyncHandler = std::make_shared<RemoteSync>();

#ifndef WIN32
        FIMDBHelper::initDB<FIMDB>(sync_interval, file_limit, sync_callback, log_callback, dbsyncHandler, rsyncHandler);
#else
        FIMDBHelper::initDB<FIMDB>(sync_interval, file_limit, value_limit, sync_callback, log_callback, dbsyncHandler,
                                   rsyncHandler);
#endif
    }
    catch (const DbSync::dbsync_error& ex)
    {
        auto errorMessage = "DB error, id: " + std::to_string(ex.id()) + ". " + ex.what();
        log_callback(LOG_ERROR_EXIT, errorMessage.c_str());
    }
}

void fim_run_integrity()
{
    try
    {
        std::thread syncThread(&FIMDB::fimRunIntegrity, &FIMDB::getInstance());
        syncThread.detach();
    }
    catch (const DbSync::dbsync_error& err)
    {
        FIMDB::getInstance().logFunction(LOG_ERROR, err.what());
    }
}

void fim_sync_push_msg(const char* msg)
{
    try
    {
        FIMDB::getInstance().fimSyncPushMsg(msg);
    }
    catch (const DbSync::dbsync_error& err)
    {
        FIMDB::getInstance().logFunction(LOG_ERROR, err.what());
    }
}

TXN_HANDLE fim_db_transaction_start(const char* table, result_callback_t row_callback, void *user_data)
{
    const auto jsonTable { R"({"table": "file_entry"})" };
    const std::unique_ptr<cJSON, CJsonDeleter> jsInput
    {
        cJSON_Parse(jsonTable)
    };

    callback_data_t cb_data = { .callback = row_callback, .user_data = user_data };

    TXN_HANDLE dbsyncTxnHandle = dbsync_create_txn(FIMDB::getInstance().DBSyncHandle(), jsInput.get(), 0,
                                                   QUEUE_SIZE, cb_data);

    return dbsyncTxnHandle;
}

FIMDBErrorCodes fim_db_transaction_sync_row(TXN_HANDLE txn_handler, const fim_entry* entry) {

    nlohmann::json json_insert;
    auto retVal = FIMDB_OK;

    if (entry->type == FIM_TYPE_FILE)
    {
        auto syncItem = std::make_unique<FileItem>(entry);
        json_insert["table"] = FIMBD_FILE_TABLE_NAME;
        json_insert["data"] = {*(syncItem->toJSON())};
    }
    else
    {
        // auto syncItem = FileItem(entry);
        // json_insert["table"] = FIMBD_FILE_TABLE_NAME
        // json_insert["data"] = syncItem.toJSON();
    }

    const std::unique_ptr<cJSON, CJsonDeleter> jsInput
    {
        cJSON_Parse(json_insert.dump().c_str())
    };


    int res = dbsync_sync_txn_row(txn_handler, jsInput.get());
    if (res != 0)
    {
        retVal = FIMDB_ERR;
    }

    return retVal;
}

FIMDBErrorCodes fim_db_transaction_deleted_rows(TXN_HANDLE txn_handler,
                                                result_callback_t res_callback,
                                                void* txn_ctx) {
    auto retVal = FIMDB_OK;
    callback_data_t cb_data = { .callback = res_callback, .user_data = txn_ctx };

    dbsync_get_deleted_rows(txn_handler, cb_data);
    dbsync_close_txn(txn_handler);
    return retVal;
}



#ifdef __cplusplus
}
#endif
