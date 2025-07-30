/*
 * Wazuh Syscheck
 * Copyright (C) 2015, Wazuh Inc.
 * September 9, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "cjsonSmartDeleter.hpp"
#include "db.h"
#include "db.hpp"
#include "dbFileItem.hpp"
#include "fimCommonDefs.h"
#include "fimDB.hpp"
#include "json.hpp"

enum SEARCH_FIELDS
{
    SEARCH_FIELD_TYPE,
    SEARCH_FIELD_PATH,
    SEARCH_FIELD_INODE,
    SEARCH_FIELD_DEV
};

void DB::removeFile(const std::string& path)
{
    std::string encodedPath = path;
    FIMDBCreator<OS_TYPE>::encodeString(encodedPath);

    auto deleteQuery
    {
        DeleteQuery::builder().table(FIMDB_FILE_TABLE_NAME).data({{"path", encodedPath}}).rowFilter("").build()};

    FIMDB::instance().removeItem(deleteQuery.query());
}

void DB::getFile(const std::string& path, std::function<void(const nlohmann::json&)> callback)
{
    std::string encodedPath = path;
    FIMDBCreator<OS_TYPE>::encodeString(encodedPath);

    auto selectQuery {SelectQuery::builder()
                      .table(FIMDB_FILE_TABLE_NAME)
                      .columnList({"path",
                                   "checksum",
                                   "device",
                                   "inode",
                                   "size",
                                   "permissions",
                                   "attributes",
                                   "uid",
                                   "gid",
                                   "owner",
                                   "group_",
                                   "hash_md5",
                                   "hash_sha1",
                                   "hash_sha256",
                                   "mtime"})
                      .rowFilter(std::string("WHERE path=\"") + encodedPath + "\"")
                      .orderByOpt(FILE_PRIMARY_KEY)
                      .distinctOpt(false)
                      .countOpt(100)
                      .build()};

    std::vector<nlohmann::json> entryFromPath;
    const auto internalCallback {[&entryFromPath](ReturnTypeCallback type, const nlohmann::json & jsonResult)
    {
        if (ReturnTypeCallback::SELECTED == type)
        {
            entryFromPath.push_back(jsonResult);
        }
    }};

    FIMDB::instance().executeQuery(selectQuery.query(), internalCallback);

    if (entryFromPath.size() == 1)
    {
        callback(entryFromPath.front());
    }
    else
    {
        throw no_entry_found {"No entry found for " + path};
    }
}

void DB::updateFile(const nlohmann::json& file, std::function<void(int, const nlohmann::json&)> callback)
{
    const auto internalCallback {[file, callback, this](ReturnTypeCallback type, const nlohmann::json resultJson)
    {
        callback(type, resultJson);
    }};

    FIMDB::instance().updateItem(file, internalCallback);

    return;
}

void DB::searchFile(const SearchData& data, std::function<void(const std::string&)> callback)
{
    const auto searchType {std::get<SEARCH_FIELD_TYPE>(data)};
    std::string filter;

    if (SEARCH_TYPE_INODE == searchType)
    {
        filter =
            "WHERE inode=" + std::get<SEARCH_FIELD_INODE>(data) + " AND device=" + std::get<SEARCH_FIELD_DEV>(data);
    }
    else if (SEARCH_TYPE_PATH == searchType)
    {
        std::string encodedPath = std::get<SEARCH_FIELD_PATH>(data);
        FIMDBCreator<OS_TYPE>::encodeString(encodedPath);

        filter = "WHERE path LIKE \"" + encodedPath + "\"";
    }
    else
    {
        throw std::runtime_error {"Invalid search type"};
    }

    auto selectQuery {SelectQuery::builder()
                      .table(FIMDB_FILE_TABLE_NAME)
                      .columnList({"path"})
                      .rowFilter(filter)
                      .orderByOpt(FILE_PRIMARY_KEY)
                      .distinctOpt(false)
                      .build()};

    const auto localCallback {[callback](ReturnTypeCallback type, const nlohmann::json & jsonResult)
    {
        if (ReturnTypeCallback::SELECTED == type)
        {
            callback(jsonResult.at("path"));
        }
    }};

    FIMDB::instance().executeQuery(selectQuery.query(), localCallback);
}

#ifdef __cplusplus
extern "C"
{
#endif

FIMDBErrorCode fim_db_get_path(const char* file_path, callback_context_t callback, bool to_delete)
{
    auto retVal {FIMDB_ERR};

    if (!file_path || !callback.callback)
    {
        FIMDB::instance().logFunction(LOG_ERROR, "Invalid parameters");
    }
    else
    {
        try
        {
            DB::instance().getFile(
                file_path,
                [callback, to_delete](const nlohmann::json & resultJson)
            {
                if (to_delete)
                {
                    DB::instance().removeFile(resultJson.at("path").get<std::string>());

                    nlohmann::json patchedJson = resultJson;

                    if (patchedJson.contains("inode") && patchedJson["inode"].is_number())
                    {
                        patchedJson["inode"] = std::to_string(patchedJson["inode"].get<uint64_t>());
                    }

                    const std::unique_ptr<cJSON, CJsonSmartDeleter> spJson
                    {
                        cJSON_Parse(patchedJson.dump().c_str())};
                    callback.callback_txn(ReturnTypeCallback::DELETED, spJson.get(), callback.context);
                }
                else
                {
                    const auto file {std::make_unique<FileItem>(resultJson)};
                    callback.callback(file->toFimEntry(), callback.context);
                }
            });
            retVal = FIMDB_OK;
        }
        catch (const no_entry_found& err)
        {
            FIMDB::instance().logFunction(LOG_DEBUG_VERBOSE, err.what());
        }
        // LCOV_EXCL_START
        catch (const std::exception& err)
        {
            FIMDB::instance().logFunction(LOG_ERROR, err.what());
        }

        // LCOV_EXCL_STOP
    }

    return retVal;
}

int fim_db_get_count_file_inode()
{
    auto count {0};

    try
    {
        count = DB::instance().countEntries(FIMDB_FILE_TABLE_NAME, COUNT_SELECT_TYPE::COUNT_INODE);
    }
    // LCOV_EXCL_START
    catch (const std::exception& err)
    {
        FIMDB::instance().logFunction(LOG_ERROR, err.what());
    }

    // LCOV_EXCL_STOP

    return count;
}

int fim_db_get_count_file_entry()
{
    auto count {0};

    try
    {
        count = DB::instance().countEntries(FIMDB_FILE_TABLE_NAME, COUNT_SELECT_TYPE::COUNT_ALL);
    }
    // LCOV_EXCL_START
    catch (const std::exception& err)
    {
        FIMDB::instance().logFunction(LOG_ERROR, err.what());
    }

    // LCOV_EXCL_STOP

    return count;
}

FIMDBErrorCode fim_db_file_update(fim_entry* data, callback_context_t callback)
{
    auto retVal {FIMDB_ERR};

    if (!data || !callback.callback_txn)
    {
        FIMDB::instance().logFunction(LOG_ERROR, "Invalid parameters");
    }
    else
    {
        try
        {
            const auto file {std::make_unique<FileItem>(data, true)};
            DB::instance().updateFile(*file->toJSON(),
                                      [callback](int resultType, const nlohmann::json & resultJson)
            {
                nlohmann::json patchedJson = resultJson;
                auto convert_inode = [](nlohmann::json & obj)
                {
                    if (obj.contains("inode") && obj["inode"].is_number())
                    {
                        obj["inode"] = std::to_string(obj["inode"].get<uint64_t>());
                    }
                };

                if (patchedJson.contains("data"))
                {
                    if (patchedJson["data"].contains("attributes"))
                    {
                        convert_inode(patchedJson["data"]["attributes"]);
                    }

                    if (patchedJson["data"].contains("old_attributes"))
                    {
                        convert_inode(patchedJson["data"]["old_attributes"]);
                    }
                }

                const std::unique_ptr<cJSON, CJsonSmartDeleter> spJson
                {
                    cJSON_Parse(patchedJson.dump().c_str())};
                callback.callback_txn(static_cast<ReturnTypeCallback>(resultType),
                                      spJson.get(),
                                      callback.context);
            });
            retVal = FIMDB_OK;
        }
        // LCOV_EXCL_START
        catch (DbSync::max_rows_error& max_row)
        {
            FIMDB::instance().logFunction(
                LOG_WARNING,
                "Reached maximum files limit monitored, due to db_entry_limit configuration for files.");
        }
        catch (std::exception& err)
        {
            FIMDB::instance().logFunction(LOG_ERROR, err.what());
        }

        // LCOV_EXCL_STOP
    }

    return retVal;
}

FIMDBErrorCode fim_db_file_inode_search(const unsigned long long int inode,
                                        const unsigned long device,
                                        callback_context_t callback)
{
    auto retVal {FIMDB_ERR};

    if (!callback.callback)
    {
        FIMDB::instance().logFunction(LOG_ERROR, "Invalid parameters");
    }
    else
    {
        try
        {
            DB::instance().searchFile(
                std::make_tuple(SEARCH_TYPE_INODE, "", std::to_string(inode), std::to_string(device)),
                [callback](const std::string & path)
            {
                char* entry = const_cast<char*>(path.c_str());
                callback.callback(entry, callback.context);
            });
            retVal = FIMDB_OK;
        }
        // LCOV_EXCL_START
        catch (const std::exception& err)
        {
            FIMDB::instance().logFunction(LOG_ERROR, err.what());
        }

        // LCOV_EXCL_STOP
    }

    return retVal;
}

FIMDBErrorCode fim_db_file_pattern_search(const char* pattern, callback_context_t callback)
{
    auto retVal {FIMDB_ERR};

    if (!pattern || !callback.callback)
    {
        FIMDB::instance().logFunction(LOG_ERROR, "Invalid parameters");
    }
    else
    {
        try
        {
            DB::instance().searchFile(std::make_tuple(SEARCH_TYPE_PATH, pattern, "", ""),
                                      [callback](const std::string & path)
            {
                char* entry = const_cast<char*>(path.c_str());
                callback.callback(entry, callback.context);
            });
            retVal = FIMDB_OK;
        }
        // LCOV_EXCL_START
        catch (const std::exception& err)
        {
            FIMDB::instance().logFunction(LOG_ERROR, err.what());
        }

        // LCOV_EXCL_STOP
    }

    return retVal;
}

#ifdef __cplusplus
}
#endif
