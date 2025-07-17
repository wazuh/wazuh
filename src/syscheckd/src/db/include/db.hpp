/*
 * Wazuh DB
 * Copyright (C) 2015, Wazuh Inc.
 * January 12, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _DB_HPP
#define _DB_HPP
#include "db.h"
#include <string.h>
#include <functional>
#include <json.hpp>

// Define EXPORTED for any platform
#ifdef _WIN32
#ifdef WIN_EXPORT
#define EXPORTED __declspec(dllexport)
#else
#define EXPORTED __declspec(dllimport)
#endif
#elif __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

typedef enum COUNT_SELECT_TYPE
{
    COUNT_ALL,
    COUNT_INODE,
} COUNT_SELECT_TYPE;

typedef enum FILE_SEARCH_TYPE
{
    SEARCH_TYPE_PATH,
    SEARCH_TYPE_INODE
} FILE_SEARCH_TYPE;

using SearchData = std::tuple<FILE_SEARCH_TYPE, std::string, std::string, std::string>;

class no_entry_found : public std::exception
{
    public:
        __attribute__((__returns_nonnull__))
        const char* what() const noexcept override
        {
            return m_error.what();
        }

        explicit no_entry_found(const std::string& whatArg)
            : m_error{ whatArg }
        {}

    private:
        /// an exception object as storage for error messages
        std::runtime_error m_error;
};

class EXPORTED DB final
{
    public:
        static DB& instance()
        {
            static DB s_instance;
            return s_instance;
        }

        /**
        * @brief Init facade with database connection
        *
        * @param storage Storage type.
        * @param syncInterval Sync sync interval.
        * @param sync_max_interval Maximum interval allowed for the synchronization process.
        * @param sync_response_timeout Minimum interval for the synchronization process.
        * @param callbackSyncFileWrapper Callback sync file values.
        * @param callbackSyncRegistryWrapper Callback sync registry values.
        * @param callbackLogWrapper Callback to log lines.
        * @param fileLimit File limit.
        * @param valueLimit Registry value limit.
        * @param syncRegistryEnabled Flag to enable/disable the registry sync mechanism.
        * @param syncThreadPool Number of threads used by RSync.
        * @param syncQueueSize Number to define the size of the queue to be synchronized.
        */
        void init(const int storage,
                  const int syncInterval,
                  const uint32_t syncMaxInterval,
                  const uint32_t syncResponseTimeout,
                  std::function<void(const std::string&)> callbackSyncFileWrapper,
                  std::function<void(const std::string&)> callbackSyncRegistryWrapper,
                  std::function<void(modules_log_level_t, const std::string&)> callbackLogWrapper,
                  int fileLimit,
                  int valueLimit,
                  bool syncRegistryEnabled,
                  const int syncThreadPool,
                  const int syncQueueSize);

        /**
        * @brief runIntegrity Execute the integrity mechanism.
        */
        void runIntegrity();

        /**
        * @brief pushMessage Push a message to the queue of the integrity mechanism.
        *
        * @param message Message payload comming from the manager.
        */
        void pushMessage(const std::string& message);

        /**
        * @brief DBSyncHandle return the dbsync handle, for operations with the database.
        *
        * @return dbsync handle.
        */
        DBSYNC_HANDLE DBSyncHandle();

        /**
        * @brief createJsonEvent Create and fill the json with event data.
        *
        * @param fileJson The json structure with fim file data.
        * @param resultJson The json structure with the result of the dbsync querie.
        * @param type Represents the result type of the database operation events.
        * @param ctx Context struct with data related to the fim_entry.
        *
        * @return jsonEvent The json structure with the event information.
        */
        nlohmann::json createJsonEvent(const nlohmann::json& fileJson,
                                       const nlohmann::json& resultJson,
                                       ReturnTypeCallback type,
                                       callback_ctx* ctx);

        /**
        * @brief removeFile Remove a file from the database.
        *
        * @param path File to remove.
        */
        void removeFile(const std::string& path);

        /**
        * @brief getFile Get a file from the database.
        *
        * @param path File to get.
        * @param callback Callback return the file data.
        */
        void getFile(const std::string& path,
                     std::function<void(const nlohmann::json&)> callback);

        /**
        * @brief countEntries Count files in the database.
        *
        * @param tableName Table name.
        * @param selectType Type of count.
        * @return Number of files.
        */
        int countEntries(const std::string& tableName,
                         const COUNT_SELECT_TYPE selectType);

        /**
        * @brief updateFile Update/insert a file in the database.
        *
        * @param file File entry/data to update/insert.
        * @param ctx Context struct with data related to the fim_entry.
        * @param callback Callback to send the fim message.
        */
        void updateFile(const nlohmann::json& file,
                        callback_ctx* ctx,
                        std::function<void(nlohmann::json)> callbackPrimitive);

        /**
        * @brief searchFiles Search files in the database.
        *
        * @param searchData parameter to search information.
        * @param callback Callback return the file data.
        */
        void searchFile(const SearchData& data,
                        std::function<void(const std::string&)> callback);

        /**
        * @brief teardown Close the fimdb instances.
        */
        void teardown();

    private:
        DB() = default;
        ~DB() = default;
        DB(const DB&) = delete;
        DB& operator=(const DB&) = delete;
};


#endif //_IFIMDB_HPP
