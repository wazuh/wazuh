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
#include <functional>
#include <json.hpp>
#include <string.h>

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
        __attribute__((__returns_nonnull__)) const char* what() const noexcept override
        {
            return m_error.what();
        }

        explicit no_entry_found(const std::string& whatArg)
            : m_error {whatArg}
        {
        }

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
         * @param callbackLogWrapper Callback to log lines.
         * @param fileLimit File limit.
         * @param valueLimit Registry value limit.
         */
        void init(int storage,
                  std::function<void(modules_log_level_t, const std::string&)> callbackLogWrapper,
                  int fileLimit,
                  int valueLimit);

        /**
         * @brief DBSyncHandle return the dbsync handle, for operations with the database.
         *
         * @return dbsync handle.
         */
        DBSYNC_HANDLE DBSyncHandle();

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
        void getFile(const std::string& path, std::function<void(const nlohmann::json&)> callback);

        /**
         * @brief countEntries Count files in the database.
         *
         * @param tableName Table name.
         * @param selectType Type of count.
         * @return Number of files.
         */
        int countEntries(const std::string& tableName, COUNT_SELECT_TYPE selectType);

        /**
         * @brief maxVersion Get the maximum version from a table.
         *
         * @param tableName Table name.
         * @return Maximum version value, 0 if no entries exist.
         */
        int maxVersion(const std::string& tableName);

        /**
         * @brief updateVersion Update the version column for all entries in a table.
         *
         * @param tableName Table name.
         * @param version New version value to set.
         * @return 0 on success, -1 on error.
         */
        int updateVersion(const std::string& tableName, int version);

        /**
         * @brief updateFile Update/insert a file in the database.
         *
         * @param file File entry/data to update/insert.
         * @param callback Callback to send the fim message.
         */
        void updateFile(const nlohmann::json& file, std::function<void(int, const nlohmann::json&)> callback);

        /**
         * @brief searchFiles Search files in the database.
         *
         * @param searchData parameter to search information.
         * @param callback Callback return the file data.
         */
        void searchFile(const SearchData& data, std::function<void(const std::string&)> callback);

        /**
         * @brief teardown Close the fimdb instances.
         */
        void teardown();

        /**
         * @brief closeAndDeleteDatabase Closes the database connection and deletes the database file.
         */
        void closeAndDeleteDatabase();

        /**
         * @brief Update the last_sync_time for a given table.
         *
         * @param tableName Name of the table to update.
         * @param timestamp The sync timestamp to set (UNIX format).
         */
        void updateLastSyncTime(const std::string& tableName, int64_t timestamp);

        /**
         * @brief Get the last_sync_time for a given table.
         *
         * @param tableName Name of the table to query.
         * @return int64_t The last sync timestamp (UNIX format), or 0 if not found.
         */
        int64_t getLastSyncTime(const std::string& tableName);

    private:
        DB() = default;
        ~DB() = default;
        DB(const DB&) = delete;
        DB& operator=(const DB&) = delete;
};

#endif //_IFIMDB_HPP
