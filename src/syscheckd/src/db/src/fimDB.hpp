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
#include <thread>
#include <shared_mutex>

#ifdef __cplusplus
extern "C"
{
#include "fimCommonDefs.h"
}
#endif

#define FIM_COMPONENT_FILE              "fim_file"
#define FIM_COMPONENT_REGISTRY_KEY      "fim_registry_key"
#define FIM_COMPONENT_REGISTRY_VALUE    "fim_registry_value"

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
    size BIGINT,
    perm TEXT,
    attributes TEXT,
    uid TEXT,
    gid TEXT,
    user_name TEXT,
    group_name TEXT,
    hash_md5 TEXT,
    hash_sha1 TEXT,
    hash_sha256 TEXT,
    mtime INTEGER,
    PRIMARY KEY(path)) WITHOUT ROWID;
    CREATE INDEX IF NOT EXISTS path_index ON file_entry (path);
    CREATE INDEX IF NOT EXISTS inode_index ON file_entry (dev, inode);)"
};

constexpr auto CREATE_REGISTRY_KEY_DB_STATEMENT
{
    R"(CREATE TABLE IF NOT EXISTS registry_key (
    path TEXT NOT NULL,
    perm TEXT,
    uid TEXT,
    gid TEXT,
    user_name TEXT,
    group_name TEXT,
    mtime INTEGER,
    arch TEXT CHECK (arch IN ('[x32]', '[x64]')),
    scanned INTEGER,
    last_event INTEGER,
    checksum TEXT NOT NULL,
    hash_full_path TEXT NOT NULL,
    PRIMARY KEY (arch, path)) WITHOUT ROWID;
    CREATE INDEX IF NOT EXISTS path_index ON registry_key (path);)"
};

constexpr auto CREATE_REGISTRY_VALUE_DB_STATEMENT
{
    R"(CREATE TABLE IF NOT EXISTS registry_data (
    path TEXT,
    arch TEXT CHECK (arch IN ('[x32]', '[x64]')),
    name TEXT NOT NULL,
    type INTEGER,
    size BIGINT,
    hash_md5 TEXT,
    hash_sha1 TEXT,
    hash_sha256 TEXT,
    scanned INTEGER,
    last_event INTEGER,
    checksum TEXT NOT NULL,
    hash_full_path TEXT NOT NULL,
    PRIMARY KEY(path, arch, name)
    FOREIGN KEY (path) REFERENCES registry_key(path)
    FOREIGN KEY (arch) REFERENCES registry_key(arch)) WITHOUT ROWID;
    CREATE INDEX IF NOT EXISTS key_name_index ON registry_data (path, name);)"
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
         * @param syncMaxInterval Maximum interval allowed for the synchronization process.
         * @param syncResponseTimeout Minimum interval for the synchronization process.
         * @param callbackSyncFileWrapper callback used to send sync messages
         * @param callbackSyncRegistryWrapper callback used to send sync messages
         * @param callbackLogWrapper callback used to send log messages
         * @param dbsyncHandler Pointer to a dbsync handler.
         * @param rsyncHandler Pointer to a rsync handler.
         * @param fileLimit Maximum number of file entries in database.
         * @param registryLimit Maximum number of registry values entries in database (only for Windows).
         * @param syncRegistryEnabled Flag to specify if the synchronization for registries is enabled (only for Windows).
         */
        void init(unsigned int syncInterval,
                  const uint32_t syncMaxInterval,
                  const uint32_t syncResponseTimeout,
                  std::function<void(const std::string&)> callbackSyncFileWrapper,
                  std::function<void(const std::string&)> callbackSyncRegistryWrapper,
                  std::function<void(modules_log_level_t, const std::string&)> callbackLogWrapper,
                  std::shared_ptr<DBSync> dbsyncHandler,
                  std::shared_ptr<RemoteSync> rsyncHandler,
                  int fileLimit,
                  int registryLimit = 0,
                  bool syncRegistryEnabled = true);

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
        void updateItem(const nlohmann::json& item,
                        ResultCallbackData callbackData);

        /**
         * @brief Execute a query given and uses the callbackData in these rows
         *
         * @param item json item that represent the query to execute
         * @param callbackData Pointer to the callback used after execute query
         */
        void executeQuery(const nlohmann::json& item,
                          ResultCallbackData callbackData);

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
        inline void stopIntegrity()
        {
            std::unique_lock<std::mutex> lock(m_fimSyncMutex);
            m_stopping = true;

            if (m_runIntegrity)
            {
                m_cv.notify_all();
                lock.unlock();

                if (m_integrityThread.joinable())
                {
                    m_integrityThread.join();
                }
            }
        };

        /**
         * @brief Its the function to log an error
         */
        inline void logFunction(const modules_log_level_t logLevel,
                                const std::string& msg)
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
         * @brief Function to return the RSync handler.
         *
         * @return std::shared_ptr<RemoteSync> this a shared_ptr for RSync.
         */
        std::shared_ptr<RemoteSync> RSyncHandler()
        {
            if (!m_rsyncHandler)
            {
                throw std::runtime_error("RSyncHandler is not initialized");
            }

            return m_rsyncHandler;
        }

        /**
        * @brief Turns off the services provided.
        */
        void teardown();

        /**
        * @brief Set m_timeLastSyncMsg variable to actual timestamp.
        */
        void setTimeLastSyncMsg()
        {
            m_timeLastSyncMsg = getCurrentTime();
        }

        /**
        * @brief Execute the sync algorithm to avoid overlaping differents syncs.
        */
        void syncAlgorithm();

        /**
        * @brief Get the current timestamp using std::time() function.
        *
        * @return time_t timestamp in seconds.
        */
        virtual time_t getCurrentTime() const;

    private:

        unsigned int                                                            m_syncInterval;
        bool                                                                    m_stopping;
        std::mutex                                                              m_fimSyncMutex;
        std::condition_variable                                                 m_cv;
        std::shared_ptr<DBSync>                                                 m_dbsyncHandler;
        std::shared_ptr<RemoteSync>                                             m_rsyncHandler;
        std::function<void(const std::string&)>                                 m_syncFileMessageFunction;
        std::function<void(const std::string&)>                                 m_syncRegistryMessageFunction;
        std::function<void(modules_log_level_t, const std::string&)>            m_loggingFunction;
        bool                                                                    m_runIntegrity;
        std::thread                                                             m_integrityThread;
        std::shared_timed_mutex                                                 m_handlersMutex;
        bool                                                                    m_syncRegistryEnabled;
        uint32_t                                                                m_syncResponseTimeout;
        uint32_t                                                                m_syncMaxInterval;
        uint32_t                                                                m_currentSyncInterval;
        bool                                                                    m_syncSuccessful;
        std::time_t                                                             m_timeLastSyncMsg;

        /**
        * @brief Function that executes the synchronization of the databases with the manager
        */
        void sync();

    protected:
        FIMDB() = default;
        // LCOV_EXCL_START
        virtual ~FIMDB() = default;
        // LCOV_EXCL_STOP
        FIMDB(const FIMDB&) = delete;
};
#endif //_FIMDB_HPP
