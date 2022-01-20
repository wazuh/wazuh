/*
 * Wazuh Syscheck
 * Copyright (C) 2015-2021, Wazuh Inc.
 * September 9, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "fimCommonDefs.h"
#include "json.hpp"
#include "db.h"
#include "db.hpp"
#include "fimDB.hpp"
#include "fimDBUtils.hpp"
#include "dbFileItem.hpp"

enum SEARCH_FIELDS
{
    SEARCH_FIELD_TYPE,
    SEARCH_FIELD_PATH,
    SEARCH_FIELD_INODE,
    SEARCH_FIELD_DEV
};

void DB::removeFile(const std::string& path)
{
    auto deleteQuery
    {
        DeleteQuery::builder()
        .table(FIMDB_FILE_TABLE_NAME)
        .data({{"path", path}})
        .rowFilter("")
        .build()
    };

    FIMDB::getInstance().removeItem(deleteQuery.query());
}

void DB::getFile(const std::string& path, std::function<void(const nlohmann::json&)> callback)
{
    auto selectQuery
    {
        SelectQuery::builder()
        .table(FIMDB_FILE_TABLE_NAME)
        .columnList({"path",
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
            "mtime"})
        .rowFilter(std::string("WHERE path=\"") + std::string(path) + "\"")
        .orderByOpt(FILE_PRIMARY_KEY)
        .distinctOpt(false)
        .countOpt(100)
        .build()
    };

    std::vector<nlohmann::json> entryFromPath;
    const auto internalCallback
    {
        [&entryFromPath](ReturnTypeCallback type, const nlohmann::json & jsonResult)
        {
            if (ReturnTypeCallback::SELECTED == type)
            {
                entryFromPath.push_back(jsonResult);
            }
        }
    };

    FIMDB::getInstance().executeQuery(selectQuery.query(), internalCallback);

    if (entryFromPath.size() == 1)
    {
        callback(entryFromPath.front());
    }
    else
    {
        throw std::runtime_error{ "There are more or 0 rows" };
    }
}


const std::unordered_map<COUNT_SELECT_TYPE, std::vector<std::string>> COUNT_SELECT_TYPE_MAP
{
    { COUNT_SELECT_TYPE::COUNT_ALL, {"count(*) AS count"} },
    { COUNT_SELECT_TYPE::COUNT_INODE, {"count(DISTINCT (inode || ',' || dev)) AS count"} },
};



int DB::countFiles(const COUNT_SELECT_TYPE selectType)
{
    auto count { 0 };
    auto callback
    {
        [&count](ReturnTypeCallback type, const nlohmann::json & jsonResult)
        {
            if (ReturnTypeCallback::SELECTED == type)
            {
                count = jsonResult.at("count");
            }
        }
    };

    auto selectQuery
    {
        SelectQuery::builder()
        .table(FIMDB_FILE_TABLE_NAME)
        .columnList(COUNT_SELECT_TYPE_MAP.at(selectType))
        .rowFilter("")
        .orderByOpt("")
        .distinctOpt(false)
        .build()
    };

    FIMDB::getInstance().executeQuery(selectQuery.query(), callback);
    return count;
}

bool DB::updateFile(const nlohmann::json& file)
{
    auto updated { false };
    const auto callback
    {
        [&updated](ReturnTypeCallback type, const nlohmann::json&)
        {
            if (ReturnTypeCallback::MODIFIED == type)
            {
                updated = true;
            }
        }
    };

    FIMDB::getInstance().updateItem(file, callback);
    return updated;
}

void DB::searchFile(const SearchData& data, std::function<void(const std::string&)> callback)
{
    const auto searchType { std::get<SEARCH_FIELD_TYPE>(data) };
    std::string filter;

    if (SEARCH_TYPE_INODE == searchType)
    {
        filter = "WHERE inode=" + std::get<SEARCH_FIELD_INODE>(data) + " AND dev=" + std::get<SEARCH_FIELD_DEV>(data);
    }
    else if (SEARCH_TYPE_PATH == searchType)
    {
        filter = "WHERE path LIKE \"" + std::get<SEARCH_FIELD_PATH>(data) + "\"";
    }
    else
    {
        throw std::runtime_error{ "Invalid search type" };
    }

    auto selectQuery
    {
        SelectQuery::builder()
        .table(FIMDB_FILE_TABLE_NAME)
        .columnList({"path"})
        .rowFilter(filter)
        .orderByOpt(FILE_PRIMARY_KEY)
        .distinctOpt(false)
        .build()
    };


    const auto localCallback
    {
        [callback](ReturnTypeCallback type, const nlohmann::json & jsonResult)
        {
            if (ReturnTypeCallback::SELECTED == type)
            {
                callback(jsonResult.at("path"));
            }
        }
    };

    FIMDB::getInstance().executeQuery(selectQuery.query(), localCallback);
}


#ifdef __cplusplus
extern "C" {
#endif

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
            DB::instance().getFile(file_path, [&callback](const nlohmann::json & jsonResult)
            {
                const auto file { std::make_unique<FileItem>(jsonResult) };
                callback.callback(file->toFimEntry(), callback.context);
            });
            retVal = FIMDB_OK;
        }
        catch (const std::exception& err)
        {
            FIMDB::getInstance().logFunction(LOG_ERROR, err.what());
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
            DB::instance().removeFile(path);
            retVal = FIMDB_OK;
        }
        // LCOV_EXCL_START
        catch (const std::exception& err)
        {
            FIMDB::getInstance().logFunction(LOG_ERROR, err.what());
        }

        // LCOV_EXCL_STOP
    }

    return retVal;
}

int fim_db_get_count_file_inode()
{
    auto count { 0 };

    try
    {
        count = DB::instance().countFiles(COUNT_SELECT_TYPE::COUNT_INODE);
    }
    // LCOV_EXCL_START
    catch (const std::exception& err)
    {
        FIMDB::getInstance().logFunction(LOG_ERROR, err.what());
    }

    // LCOV_EXCL_STOP

    return count;
}

int fim_db_get_count_file_entry()
{
    auto count { 0 };

    try
    {
        count = DB::instance().countFiles(COUNT_SELECT_TYPE::COUNT_ALL);
    }
    // LCOV_EXCL_START
    catch (const std::exception& err)
    {
        FIMDB::getInstance().logFunction(LOG_ERROR, err.what());
    }

    // LCOV_EXCL_STOP

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
            *updated = DB::instance().updateFile(*file->toJSON());
            retVal = FIMDB_OK;
        }
        // LCOV_EXCL_START
        catch (const std::exception& err)
        {
            FIMDB::getInstance().logFunction(LOG_ERROR, err.what());
        }

        // LCOV_EXCL_STOP
    }

    return retVal;
}

FIMDBErrorCode fim_db_file_inode_search(const unsigned long inode, const unsigned long dev, callback_context_t callback)
{
    auto retVal { FIMDB_ERR };

    if (!callback.callback)
    {
        FIMDB::getInstance().logFunction(LOG_ERROR, "Invalid parameters");
    }
    else
    {
        try
        {
            DB::instance().searchFile(std::make_tuple(SEARCH_TYPE_INODE, "", std::to_string(inode), std::to_string(dev)),
                                      [callback] (const std::string & path)
            {
                char* entry = const_cast<char*>(path.c_str());
                callback.callback(entry, callback.context);
            });
            retVal = FIMDB_OK;
        }
        // LCOV_EXCL_START
        catch (const std::exception& err)
        {
            FIMDB::getInstance().logFunction(LOG_ERROR, err.what());
        }

        // LCOV_EXCL_STOP
    }

    return retVal;
}

FIMDBErrorCode fim_db_file_pattern_search(const char* pattern, callback_context_t callback)
{
    auto retVal { FIMDB_ERR };

    if (!pattern || !callback.callback)
    {
        FIMDB::getInstance().logFunction(LOG_ERROR, "Invalid parameters");
    }
    else
    {
        try
        {
            DB::instance().searchFile(std::make_tuple(SEARCH_TYPE_PATH, pattern, "", ""),
                                      [callback] (const std::string & path)
            {
                char* entry = const_cast<char*>(path.c_str());
                callback.callback(entry, callback.context);
            });
            retVal = FIMDB_OK;
        }
        // LCOV_EXCL_START
        catch (const std::exception& err)
        {
            FIMDB::getInstance().logFunction(LOG_ERROR, err.what());
        }

        // LCOV_EXCL_STOP
    }

    return retVal;
}


#ifdef __cplusplus
}
#endif
