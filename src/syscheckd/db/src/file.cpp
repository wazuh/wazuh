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

int fim_db_file_pattern_search(const char* pattern, callback_context_t callback)
{
    auto retVal { FIMDB_ERR };
    const auto paths { FimDBUtils::getPathsFromPattern(pattern) };

    if (paths.empty())
    {
        FIMDB::getInstance().logErr(LOG_ERROR, "No entry found with that pattern");
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

void fim_db_get_path(const char* file_path, callback_context_t callback)
{
    if (!file_path || !callback.callback)
    {
        FIMDB::getInstance().logErr(LOG_ERROR, "Invalid parameters");
    }
    else
    {
        const auto fileColumnList { R"({"column_list":"[path, mode, last_event, scanned, options, checksum, dev, inode, size,
                                                perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1,
                                                hash_sha256, mtime]"})"_json };

        const auto filter { std::string("WHERE path=") + std::string(file_path) };
        const auto query { FIMDBHelper::dbQuery(FIMBD_FILE_TABLE_NAME, fileColumnList, filter, FILE_PRIMARY_KEY) };

        try
        {
            nlohmann::json entry_from_path;
            FIMDBHelper::getDBItem<FIMDB>(entry_from_path, query);
            const auto file { std::make_unique<FileItem>(entry_from_path) };
            callback.callback(file->toFimEntry(), callback.context);
        }
        catch (const DbSync::dbsync_error& err)
        {
            FIMDB::getInstance().logErr(LOG_ERROR, err.what());
        }
    }
}


int fim_db_remove_path(const char* path)
{
    auto retVal { FIMDB_ERR };

    if (!path)
    {
        FIMDB::getInstance().logErr(LOG_ERROR, "Invalid parameters");
    }
    else
    {
        try
        {
            const auto removeFileCondition { std::string("WHERE path=") + std::string(path) };
            FIMDBHelper::removeFromDB<FIMDB>(FIMBD_FILE_TABLE_NAME, removeFileCondition);
            retVal = FIMDB_OK;
        }
        catch (const DbSync::dbsync_error& err)
        {
            FIMDB::getInstance().logErr(LOG_ERROR, err.what());
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
        const auto countQuery { FIMDBHelper::dbQuery(FIMBD_FILE_TABLE_NAME, inodeQuery, "", "") };
        count = FIMDBHelper::getCount<FIMDB>(FIMBD_FILE_TABLE_NAME, countQuery);
    }
    catch (const DbSync::dbsync_error& err)
    {
        FIMDB::getInstance().logErr(LOG_ERROR, err.what());
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
        FIMDB::getInstance().logErr(LOG_ERROR, err.what());
    }

    return count;
}

int fim_db_file_update(const fim_entry* data, bool* updated)
{
    auto retVal { FIMDB_ERR };

    if (!data || !updated)
    {
        FIMDB::getInstance().logErr(LOG_ERROR, "Invalid parameters");
    }
    else
    {
        try
        {
            const auto file { std::make_unique<FileItem>(data) };
            *updated = FIMDBHelper::updateItem<FIMDB>(*file->toJSON());
        }
        catch (DbSync::dbsync_error& err)
        {
            FIMDB::getInstance().logErr(LOG_ERROR, err.what());
            retVal = FIMDB_OK;
        }
    }
    return retVal;
}

void fim_db_file_inode_search(const unsigned long inode, const unsigned long dev, callback_context_t callback)
{
    const auto paths { FimDBUtils::getPathsFromINode(inode, dev) };
    if (paths.empty())
    {
        FIMDB::getInstance().logErr(LOG_ERROR, "No paths found with these inode and dev");
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
