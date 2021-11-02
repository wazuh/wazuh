/*
 * Wazuh Syscheckd
 * Copyright (C) 2015-2021, Wazuh Inc.
 * September 23, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _FIMDB_HPP
#define _FIMDB_HPP
#include "dbsync.hpp"
#include "rsync.hpp"
#include "db_statements.hpp"
#include <condition_variable>
#include <mutex>

#ifdef __cplusplus
extern "C"
{
#include "logging_helper.h"
}
#endif

typedef void((*send_data_callback_t)(const char* log, const char* tag));
typedef void((*logging_callback_t)(modules_log_level_t level, const char* tag));

enum class dbResult
{
    DB_SUCCESS,
    DB_ERROR
};

class FIMDB
{
    public:
        static FIMDB& getInstance()
        {
            static FIMDB s_instance;
            return s_instance;
        };

#ifdef WIN32
    void init(const std::string& dbPath,
              unsigned int interval_synchronization,
              unsigned int max_rows_file,
              unsigned int max_rows_registry,
              send_data_callback_t callbackSync,
              logging_callback_t callbackLog,
              std::unique_ptr<DBSync> dbsyncHandler,
              std::unique_ptr<RemoteSync> rsyncHandler);
#else
    void init(const std::string& dbPath,
              unsigned int interval_synchronization,
              unsigned int max_rows_file,
              send_data_callback_t callbackSync,
              logging_callback_t callbackLog,
              std::unique_ptr<DBSync> dbsyncHandler,
              std::unique_ptr<RemoteSync> rsyncHandler);
#endif
    int insertItem(const nlohmann::json& item);
    int removeItem(const nlohmann::json& item);
    int updateItem(const nlohmann::json& item, ResultCallbackData callbackData);
    int executeQuery(const nlohmann::json& item, ResultCallbackData callbackData);
    void loopRSync(std::unique_lock<std::mutex>& lock);
    void registerRSync();
    inline void stopSync(){m_stopping = true;};

private:

    unsigned int                                                            m_max_rows_file;
    unsigned int                                                            m_max_rows_registry;
    unsigned int                                                            m_interval_synchronization;
    bool                                                                    m_stopping;
    std::condition_variable                                                 m_cv;
    std::unique_ptr<DBSync>                                                 m_dbsyncHandler;
    std::unique_ptr<RemoteSync>                                             m_rsyncHandler;
    std::function<void(const std::string&)>                                 m_syncMessageFunction;
    std::function<void(modules_log_level_t, const std::string&)>            m_loggingFunction;

    void sync();
    std::string createStatement();

protected:
    FIMDB() = default;
    ~FIMDB() = default;
    FIMDB(const FIMDB&) = delete;
    void setFileLimit();
    void setRegistryLimit();
    void setValueLimit();
    std::mutex                                                              m_mutex;
};
#endif //_FIMDB_HPP
