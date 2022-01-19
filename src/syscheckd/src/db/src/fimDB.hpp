/*
 * Wazuh Syscheck
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
#include <condition_variable>
#include <mutex>

#ifdef __cplusplus
extern "C"
{
#include "fimCommonDefs.h"
}
#endif

#define FIM_COMPONENT_FILE "fim_file"
#define FIM_COMPONENT_REGISTRY "fim_registry"

constexpr auto QUEUE_SIZE
{
    4096
};

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
    PRIMARY KEY (arch, path)) WITHOUT ROWID;)"
};

constexpr auto CREATE_REGISTRY_VALUE_DB_STATEMENT
{
    R"(CREATE TABLE IF NOT EXISTS registry_data (
    path TEXT,
    arch TEXT CHECK (arch IN ('[x32]', '[x64]')),
    name TEXT NOT NULL,
    type INTEGER,
    size INTEGER,
    hash_md5 TEXT,
    hash_sha1 TEXT,
    hash_sha256 TEXT,
    scanned INTEGER,
    last_event INTEGER,
    checksum TEXT NOT NULL,
    PRIMARY KEY(path, arch, name)
    FOREIGN KEY (path) REFERENCES registry_key(path)
    FOREIGN KEY (arch) REFERENCES registry_key(arch)) WITHOUT ROWID;)"
};

constexpr auto CREATE_REGISTRY_VIEW_STATEMENT
{
    R"(CREATE VIEW IF NOT EXISTS registry_view (path, checksum) AS
       SELECT registry_key.arch || ' ' || replace(replace(registry_key.path, '\', '\\'), ':', '\:'), checksum FROM registry_key
       UNION ALL
       SELECT registry_key.arch || ' ' || replace(replace(registry_key.path, '\', '\\'), ':', '\:') || ':' || replace(replace(name, '\', '\\'), ':', '\:'),
       registry_data.checksum FROM registry_key INNER JOIN registry_data ON registry_key.path=registry_data.path AND registry_key.arch=registry_data.arch;)"
};

constexpr auto FIM_FILE_SYNC_CONFIG_STATEMENT
{
    R"(
    {
        "decoder_type":"JSON_RANGE",
        "table":"file_entry",
        "component":"fim_file",
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
        "table":"registry_view",
        "component":"fim_registry",
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

/* Statement related to files items. Defines everything necessary to perform the synchronization loop */
constexpr auto FIM_FILE_START_CONFIG_STATEMENT
{
    R"({"table":"file_entry",
        "first_query":
            {
                "column_list":["path"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"path DESC",
                "count_opt":1
            },
        "last_query":
            {
                "column_list":["path"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"path ASC",
                "count_opt":1
            },
        "component":"fim_file",
        "index":"path",
        "last_event":"last_event",
        "checksum_field":"checksum",
        "range_checksum_query_json":
            {
                "row_filter":"WHERE path BETWEEN '?' and '?' ORDER BY path",
                "column_list":["path, checksum"],
                "distinct_opt":false,
                "order_by_opt":"",
                "count_opt":100
            }
        })"
};

/* Statement related to registries items. Defines everything necessary to perform the synchronization loop */
constexpr auto FIM_REGISTRY_START_CONFIG_STATEMENT
{
    R"({"table":"registry_view",
        "first_query":
            {
                "column_list":["path"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"path DESC",
                "count_opt":1
            },
        "last_query":
            {
                "column_list":["path"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"path ASC",
                "count_opt":1
            },
        "component":"syscheck",
        "index":"path",
        "last_event":"last_event",
        "checksum_field":"checksum",
        "range_checksum_query_json":
            {
                "row_filter":"WHERE path BETWEEN '?' and '?' ORDER BY path",
                "column_list":["path, checksum"],
                "distinct_opt":false,
                "order_by_opt":"",
                "count_opt":100
            }
        })"
};

class FIMDB
{
    public:
        static FIMDB& instance()
        {
            static FIMDB s_instance;
            return s_instance;
        };

        /**
         * @brief Initialize the FIMDB singleton class, setting the attributes needed.
         *
         * @param syncInterval Interval in second, to determine frequency of the synchronization
         * @param callbackSyncFileWrapper callback used to send sync messages
         * @param callbackSyncRegistryWrapper callback used to send sync messages
         * @param callbackLogWrapper callback used to send log messages
         * @param dbsyncHandler Pointer to a dbsync handler.
         * @param rsyncHandler Pointer to a rsync handler.
         * @param fileLimit Maximun number of file entries in database.
         * @param registryLimit Maximun number of registry values entries in database (only for Windows).
         * @param isWindows True if the OS is Windows.
         */
        void init(unsigned int syncInterval,
                  std::function<void(const std::string&)> callbackSyncFileWrapper,
                  std::function<void(const std::string&)> callbackSyncRegistryWrapper,
                  std::function<void(modules_log_level_t, const std::string&)> callbackLogWrapper,
                  std::shared_ptr<DBSync> dbsyncHandler,
                  std::shared_ptr<RemoteSync> rsyncHandler,
                  unsigned int fileLimit,
                  unsigned int registryLimit = 0,
                  bool isWindows = false);

        /**
         * @brief Remove a given item from the database
         *
         * @param item json item that represent the fim_entry data
         */
        void removeItem(const nlohmann::json& item);

        /**
         * @brief Update a given item in the database, or insert a new one if not exists,
         *        then uses the callbackData for that row
         *
         * @param item json item that represent the fim_entry data
         * @param callbackData Pointer to the callback used after update rows
         */
        void updateItem(const nlohmann::json& item, ResultCallbackData callbackData);

        /**
         * @brief Execute a query given and uses the callbackData in these rows
         *
         * @param item json item that represent the query to execute
         * @param callbackData Pointer to the callback used after execute query
         */
        void executeQuery(const nlohmann::json& item, ResultCallbackData callbackData);

        /**
         * @brief Create the loop with the configured interval to do the periodical synchronization
         */
        void loopRSync(std::unique_lock<std::mutex>& lock);

        /**
         * @brief Its the function in charge of starting the flow of synchronization
         */
        void registerRSync();

        /**
         * @brief Push a syscheck synchronization message to the rsync queue
         *
         * @param data Message to push
         */
        void pushMessage(const std::string& data);

        /**
         * @brief Function in chage of run synchronization integrity
         */
        void runIntegrity();

        /**
         * @brief Its the function in charge of stopping the sync flow
         */
        inline void stopSync()
        {
            m_stopping = true;
        };

        /**
         * @brief Its the function to log an error
         */
        inline void logFunction(const modules_log_level_t logLevel, const std::string& msg)
        {
            if (m_loggingFunction)
            {
                m_loggingFunction(logLevel, msg);
            }
        }

        /**
         * @brief Function to return the DBSync handle.
         *
         * @return DBSYNC_HANDLE Handle to DBSync.
         */
        DBSYNC_HANDLE DBSyncHandle()
        {
            if (!m_dbsyncHandler)
            {
                throw std::runtime_error("DBSyncHandler is not initialized");
            }

            return m_dbsyncHandler->handle();
        }

    private:

        unsigned int                                                            m_fileLimit;
        unsigned int                                                            m_registryLimit;
        unsigned int                                                            m_syncInterval;
        bool                                                                    m_stopping;
        bool                                                                    m_isWindows;
        std::mutex                                                              m_fimSyncMutex;
        std::condition_variable                                                 m_cv;
        std::shared_ptr<DBSync>                                                 m_dbsyncHandler;
        std::shared_ptr<RemoteSync>                                             m_rsyncHandler;
        std::function<void(const std::string&)>                                 m_syncFileMessageFunction;
        std::function<void(const std::string&)>                                 m_syncRegistryMessageFunction;
        std::function<void(modules_log_level_t, const std::string&)>            m_loggingFunction;

        /**
        * @brief Function that executes the synchronization of the databases with the manager
        */
        void sync();

    protected:
        FIMDB() = default;
        // LCOV_EXCL_START
        ~FIMDB() = default;
        // LCOV_EXCL_STOP
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
