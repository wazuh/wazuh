/**
 * @file file.cpp
 * @brief Definition of FIM database for files library.
 * @date 2021-09-9
 *
 * @copyright Copyright (C) 2015-2021 Wazuh, Inc.
 */
#include "fimCommonDefs.h"
#include "json.hpp"
#include "db.h"
#include "fimDBHelper.hpp"
#include "fimDBUtils.hpp"
#include "dbFileItem.hpp"

#ifdef __cplusplus
extern "C" {
#endif

FIMDBErrorCode fim_db_file_pattern_search(const char* pattern, callback_context_t callback)
{
    auto retVal { FIMDB_ERR };
    const auto paths { FimDBUtils::getPathsFromPattern<FIMDB>(pattern) };

    if (paths.empty())
    {
        FIMDB::getInstance().logFunction(LOG_ERROR, "No entry found with that pattern");
    }
    else
    {
        for (const auto& path : paths)
        {
            char* entry = const_cast<char*>(path.c_str());
            callback.callback(entry, callback.context);
        }

        retVal = FIMDB_OK;
    }

    return retVal;
}

FIMDBErrorCode fim_db_get_path(const char* file_path, callback_context_t callback)
{
    auto retVal { FIMDB_ERR };

    if (!file_path || !callback.callback)
    {
        FIMDB::getInstance().logFunction(LOG_ERROR, "Invalid parameters");
    }
    else
    {
        try
        {
            const auto fileColumnList = R"({"column_list":["path",
                                                           "mode",
                                                           "last_event",
                                                           "scanned",
                                                           "options",
                                                           "checksum",
                                                           "dev",
                                                           "inode",
                                                           "size",
                                                           "perm",
                                                           "attributes",
                                                           "uid",
                                                           "gid",
                                                           "user_name",
                                                           "group_name",
                                                           "hash_md5",
                                                           "hash_sha1",
                                                           "hash_sha256",
                                                           "mtime"]})"_json;

            const auto filter { std::string("WHERE path=\"") + std::string(file_path) + "\""};
            const auto query = FimDBUtils::dbQuery(FIMBD_FILE_TABLE_NAME, fileColumnList, filter, FILE_PRIMARY_KEY);

            nlohmann::json entry_from_path;
            FIMDBHelper::getDBItem<FIMDB>(entry_from_path, query);

            if (entry_from_path.size() == 1)
            {
                const auto file { std::make_unique<FileItem>(entry_from_path.front()) };
                callback.callback(file->toFimEntry(), callback.context);
                retVal = FIMDB_OK;
            }
            else
            {
                throw std::runtime_error("There are more or 0 rows");
            }
        }
        catch (const DbSync::dbsync_error& err)
        {
            FIMDB::getInstance().logFunction(LOG_ERROR, err.what());
        }
        catch (const std::exception& ex)
        {
            FIMDB::getInstance().logFunction(LOG_ERROR, ex.what());
        }
    }

    return retVal;
}


FIMDBErrorCode fim_db_remove_path(const char* path)
{
    auto retVal { FIMDB_ERR };

    if (!path)
    {
        FIMDB::getInstance().logFunction(LOG_ERROR, "Invalid parameters");
    }
    else
    {
        try
        {
            nlohmann::json removeFileCondition;
            removeFileCondition["path"] = path;
            FIMDBHelper::removeFromDB<FIMDB>(FIMBD_FILE_TABLE_NAME, removeFileCondition);
            retVal = FIMDB_OK;
        }
        catch (const DbSync::dbsync_error& err)
        {
            FIMDB::getInstance().logFunction(LOG_ERROR, err.what());
        }
    }

    return retVal;
}

int fim_db_get_count_file_inode()
{
    auto count { 0 };

    try
    {
        nlohmann::json inodeQuery;
        inodeQuery["column_list"] = "count(DISTINCT (inode || ',' || dev)) AS count";
        const auto countQuery = FimDBUtils::dbQuery(FIMBD_FILE_TABLE_NAME, inodeQuery, "", "");
        count = FIMDBHelper::getCount<FIMDB>(FIMBD_FILE_TABLE_NAME, countQuery);
    }
    catch (const DbSync::dbsync_error& err)
    {
        FIMDB::getInstance().logFunction(LOG_ERROR, err.what());
    }

    return count;
}

int fim_db_get_count_file_entry()
{
    auto count { 0 };

    try
    {
        count = FIMDBHelper::getCount<FIMDB>(FIMBD_FILE_TABLE_NAME);
    }
    catch (const DbSync::dbsync_error& err)
    {
        FIMDB::getInstance().logFunction(LOG_ERROR, err.what());
    }

    return count;
}

FIMDBErrorCode fim_db_file_update(const fim_entry* data, bool* updated)
{
    auto retVal { FIMDB_ERR };

    if (!data || !updated)
    {
        FIMDB::getInstance().logFunction(LOG_ERROR, "Invalid parameters");
    }
    else
    {
        try
        {
            const auto file { std::make_unique<FileItem>(data) };
            *updated = FIMDBHelper::updateItem<FIMDB>(*file->toJSON());
            retVal = FIMDB_OK;
        }
        catch (DbSync::dbsync_error& err)
        {
            FIMDB::getInstance().logFunction(LOG_ERROR, err.what());
        }
    }

    return retVal;
}

void fim_db_file_inode_search(const unsigned long inode, const unsigned long dev, callback_context_t callback)
{
    const auto paths { FimDBUtils::getPathsFromINode<FIMDB>(inode, dev) };

    if (paths.empty())
    {
        FIMDB::getInstance().logFunction(LOG_ERROR, "No paths found with these inode and dev");
    }
    else
    {
        for (const auto& path : paths)
        {
            char* entry = const_cast<char*>(path.c_str());
            callback.callback(entry, callback.context);
        }
    }
}

#ifdef __cplusplus
}
#endif
