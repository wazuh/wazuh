/**
 * @file db.cpp
 * @brief Definition of FIM database library.
 * @date 2019-08-28
 *
 * @copyright Copyright (C) 2015-2021 Wazuh, Inc.
 */

#include "dbsync.hpp"
#include "db.hpp"
#include "fimCommonDefs.h"
#include "fimDB.hpp"
#include "fimDBHelper.hpp"

#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Create the statement string to create the dbsync schema.
 *
 * @return std::string Contains the dbsync's schema for FIM db.
 */
const char * CreateStatement()
{
    std::string ret = CREATE_FILE_DB_STATEMENT;
#ifdef WIN32
    ret += CREATE_REGISTRY_KEY_DB_STATEMENT;
    ret += CREATE_REGISTRY_VALUE_DB_STATEMENT;
#endif

    return ret.c_str();
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
        auto path = (storage == FIM_DB_MEMORY) ? FIM_DB_MEMORY_PATH : FIM_DB_DISK_PATH;

        auto dbsyncHandler = std::make_shared<DBSync>(HostType::AGENT, DbEngineType::SQLITE3, path, CreateStatement());
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

void fim_run_integrity() {
    fim_sync_queue = queue_init(syscheck.sync_queue_size);

    FIMDBHelper::fimSyncStart<FIMDB>();
}

void fim_sync_push_msg(const char * msg) {

    if (fim_sync_queue == NULL) {
        mwarn("A data synchronization response was received before sending the first message.");
        return;
    }

    char * copy;
    os_strdup(msg, copy);

    if (queue_push_ex(fim_sync_queue, copy) == -1) {
        mdebug2("Cannot push a data synchronization message: queue is full.");
        free(copy);
    }
}

#ifdef __cplusplus
}
#endif
