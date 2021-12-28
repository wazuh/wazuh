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
 * @param isWindows True if the system is windows.
 *
 * @return std::string Contains the dbsync's schema for FIM db.
 */
std::string CreateStatement(bool isWindows)
{

    std::string ret = CREATE_FILE_DB_STATEMENT;

    if(isWindows)
    {
        ret += CREATE_REGISTRY_KEY_DB_STATEMENT;
        ret += CREATE_REGISTRY_VALUE_DB_STATEMENT;
    }
    return ret;
}


void fim_db_init(int storage,
                 int sync_interval,
                 fim_sync_callback_t sync_callback,
                 logging_callback_t log_callback,
                 int file_limit,
                 int value_limit,
                 bool is_windows)
{
    try
    {
        auto path = (storage == FIM_DB_MEMORY) ? FIM_DB_MEMORY_PATH : FIM_DB_DISK_PATH;
        auto dbsyncHandler = std::make_shared<DBSync>(HostType::AGENT,
                                                      DbEngineType::SQLITE3,
                                                      path,
                                                      CreateStatement(is_windows));

        auto rsyncHandler = std::make_shared<RemoteSync>();

        FIMDBHelper::initDB<FIMDB>(sync_interval,
                                   sync_callback,
                                   log_callback,
                                   dbsyncHandler,
                                   rsyncHandler,
                                   file_limit,
                                   value_limit,
                                   is_windows);
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

TXN_HANDLE fim_db_transaction_start(const char* table, result_callback_t row_callback, void* user_data)
{
    const std::unique_ptr<cJSON, CJsonDeleter> jsInput
    {
        cJSON_Parse(table)
    };

    callback_data_t cb_data = { .callback = row_callback, .user_data = user_data };

    TXN_HANDLE dbsyncTxnHandle = dbsync_create_txn(FIMDB::getInstance().DBSyncHandle(), jsInput.get(), 0,
                                                   QUEUE_SIZE, cb_data);

    return dbsyncTxnHandle;
}

FIMDBErrorCode fim_db_transaction_sync_row(TXN_HANDLE txn_handler, const fim_entry* entry)
{
    std::unique_ptr<DBItem> syncItem;
    auto retval {FIMDB_OK};

    if (entry->type == FIM_TYPE_FILE)
    {
        syncItem = std::make_unique<FileItem>(entry);
    }

#ifdef WIN32
    else
    {
        if (entry->registry_entry.key == NULL)
        {
            syncItem = std::make_unique<RegistryValue>(entry);
        }
        else
        {
            syncItem = std::make_unique<RegistryKey>(entry);
        }
    }

#endif
    const std::unique_ptr<cJSON, CJsonDeleter> jsInput
    {
        cJSON_Parse((*syncItem->toJSON()).dump().c_str())
    };

    if (dbsync_sync_txn_row(txn_handler, jsInput.get()) != 0)
    {
        retval = FIMDB_ERR;
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



#ifdef __cplusplus
}
#endif
