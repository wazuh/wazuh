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

class FIMDB final
{
    public:
        static FIMDB& getInstance()
        {
            static FIMDB s_instance;
            return s_instance;
        };

/**
 * @brief Initialize the FIMDB singleton class, setting the attributes needed.
 *
 * @param dbPath Path of the database will be created
 * @param interval_synchronization Interval in second, to determine frequency of the synchronization
 * @param max_rows_file Maximun number of file entries in database
 * @param max_rows_registry Maximun number of registry values entries in database (only for Windows)
 * @param callbackSync Pointer to the callback used to send sync messages
 * @param callbackLog Pointer to the callback used to send log messages
 */
#ifdef WIN32
    void init(const std::string& dbPath,
              unsigned int interval_synchronization,
              unsigned int max_rows_file,
              unsigned int max_rows_registry,
              send_data_callback_t callbackSync,
              logging_callback_t callbackLog);
#else
    void init(const std::string& dbPath,
              unsigned int interval_synchronization,
              unsigned int max_rows_file,
              send_data_callback_t callbackSync,
              logging_callback_t callbackLog);
#endif
/**
 * @brief Insert a given item into the database
 *
 * @param item json item that represent the fim_entry data
 * @return 0 if the execution was ok, 1 for max_rows_error, 2 for another errors
 */
    int insertItem(const nlohmann::json& item);

/**
 * @brief Remove a given item from the database
 *
 * @param item json item that represent the fim_entry data
 * @return 0 if the execution was ok, 1 for max_rows_error, 2 for another errors
 */
    int removeItem(const nlohmann::json& item);

/**
 * @brief Update a given item in the database, or insert a new one if not exists,
 *        then uses the callbackData for that row
 *
 * @param item json item that represent the fim_entry data
 * @param callbackData Pointer to the callback used after update rows
 * @return 0 if the execution was ok, 1 for max_rows_error, 2 for another errors
 */
    int updateItem(const nlohmann::json& item, ResultCallbackData callbackData);

/**
 * @brief Execute a query given and uses the callbackData in these rows
 *
 * @param item json item that represent the query to execute
 * @param callbackData Pointer to the callback used after execute query
 * @return 0 if the execution was ok, 1 for max_rows_error, 2 for another errors
 */
    int executeQuery(const nlohmann::json& item, ResultCallbackData callbackData);

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

    std::string createStatement();

protected:
    FIMDB() = default;
    ~FIMDB() = default;
    FIMDB(const FIMDB&) = delete;

/**
 * @brief Set the entry limits for the table file_entry
 */
    void setFileLimit();

/**
 * @brief Set the entry limits for the table registry_key
 */
    void setRegistryLimit();

/**
 * @brief Set the entry limits for the table registry_data
 */
    void setValueLimit();

/**
 * @brief Its the function in charge of starting the flow of synchronization
 */
    void registerRsync();

/**
 * @brief Function that executes the synchronization of the databases with the manager
 */
    void sync();

/**
 * @brief Create the loop with the configured interval to do the periodical synchronization
 */
    void loopRsync(std::unique_lock<std::mutex>& lock);

    std::mutex                                                              m_mutex;
};
#endif //_FIMDB_HPP
