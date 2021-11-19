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
#include "commonDefs.h"
#include <condition_variable>
#include <mutex>

#ifdef __cplusplus
extern "C"
{
#include "logging_helper.h"
}
#endif

constexpr auto CREATE_FILE_DB_STATEMENT
{
    R"(CREATE TABLE IF NOT EXISTS file_entry (
    path TEXT NOT NULL,
    mode INTEGER,
    last_event INTEGER,
    scanned INTEGER,
    options INTEGER,
    checksum TEXT NOT NULL,
    dev INTEGER,
    inode INTEGER,
    size INTEGER,
    perm TEXT,
    attributes TEXT,
    uid INTEGER,
    gid INTEGER,
    user_name TEXT,
    group_name TEXT,
    hash_md5 TEXT,
    hash_sha1 TEXT,
    hash_sha256 TEXT,
    mtime INTEGER,
    PRIMARY KEY(path)) WITHOUT ROWID;)"
};

constexpr auto CREATE_REGISTRY_KEY_DB_STATEMENT
{
    R"(CREATE TABLE IF NOT EXISTS registry_key (
    path TEXT NOT NULL,
    perm TEXT,
    uid INTEGER,
    gid INTEGER,
    user_name TEXT,
    group_name TEXT,
    mtime INTEGER,
    arch TEXT CHECK (arch IN ('[x32]', '[x64]')),
    scanned INTEGER,
    last_event INTEGER,
    checksum TEXT NOT NULL,
    item_id TEXT,
    PRIMARY KEY(arch, path)) WITHOUT ROWID;)"
};
static const std::vector<std::string> REGISTRY_KEY_ITEM_ID_FIELDS{"arch", "path"};

constexpr auto CREATE_REGISTRY_VALUE_DB_STATEMENT
{
    R"(CREATE TABLE IF NOT EXISTS registry_data (
    key_id INTEGER,
    name TEXT,
    type INTEGER,
    size INTEGER,
    hash_md5 TEXT,
    hash_sha1 TEXT,
    hash_sha256 TEXT,
    scanned INTEGER,
    last_event INTEGER,
    checksum TEXT NOT NULL,
    item_id TEXT,
    PRIMARY KEY(key_id, name)
    FOREIGN KEY (key_id) REFERENCES registry_key(item_id)) WITHOUT ROWID;)"
};
static const std::vector<std::string> REGISTRY_VALUE_ITEM_ID_FIELDS{"key_id", "name"};

constexpr auto FIM_FILE_SYNC_CONFIG_STATEMENT
{
    R"(
    {
        "decoder_type":"JSON_RANGE",
        "table":"file_entry",
        "component":"fim_file_sync",
        "index":"path",
        "checksum_field":"checksum",
        "no_data_query_json": {
                "row_filter":"WHERE path BETWEEN '?' and '?' ORDER BY path",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "count_range_query_json": {
                "row_filter":"WHERE path BETWEEN '?' and '?' ORDER BY path",
                "count_field_name":"count",
                "column_list":["count(*) AS count "],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "row_data_query_json": {
                "row_filter":"WHERE path ='?'",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "range_checksum_query_json": {
                "row_filter":"WHERE path BETWEEN '?' and '?' ORDER BY path",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        }
    }
    )"
};

constexpr auto FIM_REGISTRY_SYNC_CONFIG_STATEMENT
{
    R"(
    {
        "decoder_type":"JSON_RANGE",
        "table":"registry_key",
        "component":"fim_registry_sync",
        "index":"item_id",
        "checksum_field":"checksum",
        "no_data_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "count_range_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "count_field_name":"count",
                "column_list":["count(*) AS count "],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "row_data_query_json": {
                "row_filter":"WHERE item_id ='?'",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "range_checksum_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        }
    }
    )"
};

constexpr auto FIM_VALUE_SYNC_CONFIG_STATEMENT
{
    R"(
    {
        "decoder_type":"JSON_RANGE",
        "table":"registry_data",
        "component":"fim_value_sync",
        "index":"item_id",
        "checksum_field":"checksum",
        "no_data_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "count_range_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "count_field_name":"count",
                "column_list":["count(*) AS count "],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "row_data_query_json": {
                "row_filter":"WHERE item_id ='?'",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "range_checksum_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        }
    }
    )"
};

/* Statement related to files items. Defines everything necessary to perform the synchronization loop */
constexpr auto FIM_FILE_START_CONFIG_STATEMENT
{
    R"({"table":"file_entry"})"
    //TO DO
};

/* Statement related to registries items. Defines everything necessary to perform the synchronization loop */
constexpr auto FIM_REGISTRY_START_CONFIG_STATEMENT
{
    R"({"table":"registry_key"})"
    //TO DO
};

/* Statement related to values items. Defines everything necessary to perform the synchronization loop */
constexpr auto FIM_VALUE_START_CONFIG_STATEMENT
{
    R"({"table":"registry_data"})"
    //TO DO
};


class FIMDB
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
         * @param dbsyncHandler Pointer to a dbsync handler.
         * @param rsyncHandler Pointer to a rsync handler
         */
#ifdef WIN32
        void init(unsigned int interval_synchronization,
                  unsigned int max_rows_file,
                  unsigned int max_rows_registry,
                  fim_sync_callback_t callbackSync,
                  logging_callback_t callbackLog,
                  std::shared_ptr<DBSync> dbsyncHandler,
                  std::shared_ptr<RemoteSync> rsyncHandler);
#else
        void init(unsigned int interval_synchronization,
                  unsigned int max_rows_file,
                  fim_sync_callback_t callbackSync,
                  logging_callback_t callbackLog,
                  std::shared_ptr<DBSync> dbsyncHandler,
                  std::shared_ptr<RemoteSync> rsyncHandler);
#endif
        /**
         * @brief Insert a given item into the database
         *
         * @param item json item that represent the fim_entry data
         * @return 0 if the execution was ok, 1 for max_rows_error, 2 for another errors
         */
        dbQueryResult insertItem(const nlohmann::json& item);

        /**
         * @brief Remove a given item from the database
         *
         * @param item json item that represent the fim_entry data
         * @return 0 if the execution was ok, 1 for max_rows_error, 2 for another errors
         */
        dbQueryResult removeItem(const nlohmann::json& item);

        /**
         * @brief Update a given item in the database, or insert a new one if not exists,
         *        then uses the callbackData for that row
         *
         * @param item json item that represent the fim_entry data
         * @param callbackData Pointer to the callback used after update rows
         * @return 0 if the execution was ok, 1 for max_rows_error, 2 for another errors
         */
        dbQueryResult updateItem(const nlohmann::json& item, ResultCallbackData callbackData);

        /**
         * @brief Execute a query given and uses the callbackData in these rows
         *
         * @param item json item that represent the query to execute
         * @param callbackData Pointer to the callback used after execute query
         * @return 0 if the execution was ok, 1 for max_rows_error, 2 for another errors
         */
        dbQueryResult executeQuery(const nlohmann::json& item, ResultCallbackData callbackData);

        /**
        * @brief Create the loop with the configured interval to do the periodical synchronization
        */
        void loopRSync(std::unique_lock<std::mutex>& lock);

        /**
         * @brief Its the function in charge of starting the flow of synchronization
         */
        void registerRSync();

        inline void stopSync()
        {
            m_stopping = true;
        };


    private:

        unsigned int                                                            m_max_rows_file;
        unsigned int                                                            m_max_rows_registry;
        unsigned int                                                            m_interval_synchronization;
        bool                                                                    m_stopping;
        std::condition_variable                                                 m_cv;
        std::shared_ptr<DBSync>                                                 m_dbsyncHandler;
        std::shared_ptr<RemoteSync>                                             m_rsyncHandler;
        std::function<void(const std::string&)>                                 m_syncMessageFunction;
        std::function<void(modules_log_level_t, const std::string&)>            m_loggingFunction;

        /**
        * @brief Function that executes the synchronization of the databases with the manager
        */
        void sync();

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
};
#endif //_FIMDB_HPP
