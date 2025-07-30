/*
 * Wazuh Syscheck
 * Copyright (C) 2021, Wazuh Inc.
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
#include "stringHelper.h"
#include <condition_variable>
#include <mutex>
#include <shared_mutex>
#include <thread>

#ifdef __cplusplus
extern "C"
{
#include "fimCommonDefs.h"
}
#endif

constexpr auto QUEUE_SIZE
{
    4096
};

constexpr auto CREATE_FILE_DB_STATEMENT
{
    R"(CREATE TABLE IF NOT EXISTS file_entry (
    path TEXT NOT NULL,
    checksum TEXT NOT NULL,
    device INTEGER,
    inode INTEGER,
    size INTEGER,
    permissions TEXT,
    attributes TEXT,
    uid TEXT,
    gid TEXT,
    owner TEXT,
    group_ TEXT,
    hash_md5 TEXT,
    hash_sha1 TEXT,
    hash_sha256 TEXT,
    mtime INTEGER,
    PRIMARY KEY(path)) WITHOUT ROWID;
    CREATE INDEX IF NOT EXISTS path_index ON file_entry (path);
    CREATE INDEX IF NOT EXISTS inode_index ON file_entry (device, inode);)"
};

constexpr auto CREATE_REGISTRY_KEY_DB_STATEMENT
{
    R"(CREATE TABLE IF NOT EXISTS registry_key (
    path TEXT NOT NULL,
    permissions TEXT,
    uid TEXT,
    gid TEXT,
    owner TEXT,
    group_ TEXT,
    mtime INTEGER,
    architecture TEXT CHECK (architecture IN ('[x32]', '[x64]')),
    checksum TEXT NOT NULL,
    PRIMARY KEY (architecture, path)) WITHOUT ROWID;
    CREATE INDEX IF NOT EXISTS path_index ON registry_key (path);)"
};

constexpr auto CREATE_REGISTRY_VALUE_DB_STATEMENT
{
    R"(CREATE TABLE IF NOT EXISTS registry_data (
    path TEXT,
    architecture TEXT CHECK (architecture IN ('[x32]', '[x64]')),
    value TEXT NOT NULL,
    type INTEGER,
    size INTEGER,
    hash_md5 TEXT,
    hash_sha1 TEXT,
    hash_sha256 TEXT,
    checksum TEXT NOT NULL,
    PRIMARY KEY(path, architecture, value)
    FOREIGN KEY (path) REFERENCES registry_key(path)
    FOREIGN KEY (architecture) REFERENCES registry_key(architecture)) WITHOUT ROWID;
    CREATE INDEX IF NOT EXISTS key_name_index ON registry_data (path, value);)"
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
         * @param callbackLogWrapper callback used to send log messages
         * @param dbsyncHandler Pointer to a dbsync handler.
         * @param fileLimit Maximum number of file entries in database.
         * @param registryLimit Maximum number of registry values entries in database (only for Windows).
         */
        void init(std::function<void(modules_log_level_t, const std::string&)> callbackLogWrapper,
                  std::shared_ptr<DBSync> dbsyncHandler,
                  const int fileLimit,
                  const int registryLimit = 0);

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
         * @brief Function to return the DBSync handler.
         *
         * @return std::shared_ptr<DBSync> this a shared_ptr for DBSync.
         */
        std::shared_ptr<DBSync> DBSyncHandler()
        {
            if (!m_dbsyncHandler)
            {
                throw std::runtime_error("DBSyncHandler is not initialized");
            }

            return m_dbsyncHandler;
        }

        /**
         * @brief Turns off the services provided.
         */
        void teardown();

    private:
        bool m_stopping;
        std::shared_ptr<DBSync> m_dbsyncHandler;
        std::function<void(modules_log_level_t, const std::string&)> m_loggingFunction;
        std::shared_timed_mutex m_handlersMutex;

    protected:
        FIMDB() = default;
        // LCOV_EXCL_START
        virtual ~FIMDB() = default;
        // LCOV_EXCL_STOP
        FIMDB(const FIMDB&) = delete;
};
#endif //_FIMDB_HPP
