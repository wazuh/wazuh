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

#include "fimCommonDefs.h"
#include "json.hpp"
#include "db.h"
#include "db.hpp"
#include "fimDB.hpp"
#include "dbFileItem.hpp"
#include "cjsonSmartDeleter.hpp"

static const char* FIM_EVENT_TYPE_ARRAY[] =
{
    "added",
    "deleted",
    "modified"
};

static const char* FIM_EVENT_MODE[] =
{
    "scheduled",
    "realtime",
    "whodata"
};

enum SEARCH_FIELDS
{
    SEARCH_FIELD_TYPE,
    SEARCH_FIELD_PATH,
    SEARCH_FIELD_INODE,
    SEARCH_FIELD_DEV
};

nlohmann::json DB::createJsonEvent(const nlohmann::json& fileJson, const nlohmann::json& resultJson, ReturnTypeCallback type, create_json_event_ctx* ctx)
{
    nlohmann::json jsonEvent;
    nlohmann::json data;

    data = fileJson.at("data")[0];

    jsonEvent["type"] = "event";
    jsonEvent["data"]["path"] = data.at("path");
    jsonEvent["data"]["version"] = "2.0";
    jsonEvent["data"]["mode"] = FIM_EVENT_MODE[ctx->event->mode];

    if (ReturnTypeCallback::MODIFIED == type)
    {
        ctx->event->type = FIM_MODIFICATION;
    }
    else
    {
        ctx->event->type = FIM_ADD;
    }

    jsonEvent["data"]["type"] = FIM_EVENT_TYPE_ARRAY[ctx->event->type];

    // Attributes
    jsonEvent["data"]["attributes"]["type"] = "file";

    if (ctx->config->options & CHECK_SIZE)
    {
        jsonEvent["data"]["attributes"]["size"] = data.at("size");
    }

    if (ctx->config->options & CHECK_PERM)
    {
        jsonEvent["data"]["attributes"]["perm"] = data.at("perm");
    }

    if (data.contains("uid") && data.at("uid") != "" && ctx->config->options & CHECK_OWNER)
    {
        jsonEvent["data"]["attributes"]["uid"] = data.at("uid");
    }

    if (data.contains("gid") && data.at("gid") != "" && ctx->config->options & CHECK_GROUP)
    {
        jsonEvent["data"]["attributes"]["gid"] = data.at("gid");
    }

    if (data.at("user_name") != "")
    {
        jsonEvent["data"]["attributes"]["user_name"] = data.at("user_name");
    }

    if (data.at("group_name") != "")
    {
        jsonEvent["data"]["attributes"]["group_name"] = data.at("group_name");
    }

    if (ctx->config->options & CHECK_INODE)
    {
        jsonEvent["data"]["attributes"]["inode"] = data.at("inode");
    }

    if (ctx->config->options & CHECK_MTIME)
    {
        jsonEvent["data"]["attributes"]["mtime"] = data.at("mtime");
    }

    if (ctx->config->options & CHECK_MD5SUM)
    {
        jsonEvent["data"]["attributes"]["hash_md5"] = data.at("hash_md5");
    }

    if (ctx->config->options & CHECK_SHA1SUM)
    {
        jsonEvent["data"]["attributes"]["hash_sha1"] = data.at("hash_sha1");
    }

    if (ctx->config->options & CHECK_SHA256SUM)
    {
        jsonEvent["data"]["attributes"]["hash_sha256"] = data.at("hash_sha256");
    }

    if (data.at("checksum") != "")
    {
        jsonEvent["data"]["attributes"]["checksum"] = data.at("checksum");
    }

    if (data.at("attributes") != "" && ctx->config->options & CHECK_ATTRS)
    {
        jsonEvent["data"]["attributes"]["attributes"] = data.at("attributes");
    }

    // Last event
    if (resultJson.contains("last_event"))
    {
        jsonEvent["data"]["timestamp"] = resultJson.at("last_event");
    }
    else
    {
        jsonEvent["data"]["timestamp"] = data.at("last_event");
    }

    // Old data attributes
    if (resultJson.contains("old"))
    {

        nlohmann::json old_data = resultJson.at("old");
        nlohmann::json changed_attributes = nlohmann::json::array();

        jsonEvent["data"]["old_attributes"]["type"] = "file";

        if (ctx->config->options & CHECK_SIZE)
        {
            if (old_data.contains("size"))
            {
                jsonEvent["data"]["old_attributes"]["size"] = old_data["size"];
                changed_attributes.push_back("size");
            }
            else
            {
                jsonEvent["data"]["old_attributes"]["size"] = data.at("size");
            }
        }

        if (ctx->config->options & CHECK_PERM)
        {
            if (old_data.contains("perm"))
            {
                jsonEvent["data"]["old_attributes"]["perm"] = old_data["perm"];
                changed_attributes.push_back("permission");
            }
            else
            {
                jsonEvent["data"]["old_attributes"]["perm"] = data.at("perm");
            }
        }

        if (data.contains("uid") && data.at("uid") != "" && ctx->config->options & CHECK_OWNER)
        {
            if (old_data.contains("uid"))
            {
                jsonEvent["data"]["old_attributes"]["uid"] = old_data["uid"];
                changed_attributes.push_back("uid");
            }
            else
            {
                jsonEvent["data"]["old_attributes"]["uid"] = data.at("uid");
            }
        }

        if (data.contains("gid") && data.at("gid") != "" && ctx->config->options & CHECK_GROUP)
        {
            if (old_data.contains("gid"))
            {
                jsonEvent["data"]["old_attributes"]["gid"] = old_data["gid"];
                changed_attributes.push_back("gid");
            }
            else
            {
                jsonEvent["data"]["old_attributes"]["gid"] = data.at("gid");
            }
        }

        if (data.at("user_name") != "")
        {
            if (old_data.contains("user_name"))
            {
                jsonEvent["data"]["old_attributes"]["user_name"] = old_data["user_name"];
                changed_attributes.push_back("user_name");
            }
            else
            {
                jsonEvent["data"]["old_attributes"]["user_name"] = data.at("user_name");
            }
        }

        if (data.at("group_name") != "")
        {
            if (old_data.contains("group_name"))
            {
                jsonEvent["data"]["old_attributes"]["group_name"] = old_data["group_name"];
                changed_attributes.push_back("group_name");
            }
            else
            {
                jsonEvent["data"]["old_attributes"]["group_name"] = data.at("group_name");
            }
        }

        if (ctx->config->options & CHECK_INODE)
        {
            if (old_data.contains("inode"))
            {
                jsonEvent["data"]["old_attributes"]["inode"] = old_data["inode"];
                changed_attributes.push_back("inode");
            }
            else
            {
                jsonEvent["data"]["old_attributes"]["inode"] = data.at("inode");
            }
        }

        if (ctx->config->options & CHECK_MTIME)
        {
            if (old_data.contains("mtime"))
            {
                jsonEvent["data"]["old_attributes"]["mtime"] = old_data["mtime"];
                changed_attributes.push_back("mtime");
            }
            else
            {
                jsonEvent["data"]["old_attributes"]["mtime"] = data.at("mtime");
            }
        }

        if (ctx->config->options & CHECK_MD5SUM)
        {
            if (old_data.contains("hash_md5"))
            {
                jsonEvent["data"]["old_attributes"]["hash_md5"] = old_data["hash_md5"];
                changed_attributes.push_back("md5");
            }
            else
            {
                jsonEvent["data"]["old_attributes"]["hash_md5"] = data.at("hash_md5");
            }
        }

        if (ctx->config->options & CHECK_SHA1SUM)
        {
            if (old_data.contains("hash_sha1"))
            {
                jsonEvent["data"]["old_attributes"]["hash_sha1"] = old_data["hash_sha1"];
                changed_attributes.push_back("sha1");
            }
            else
            {
                jsonEvent["data"]["old_attributes"]["hash_sha1"] = data.at("hash_sha1");
            }
        }

        if (ctx->config->options & CHECK_SHA256SUM)
        {
            if (old_data.contains("hash_sha256"))
            {
                jsonEvent["data"]["old_attributes"]["hash_sha256"] = old_data["hash_sha256"];
                changed_attributes.push_back("sha256");
            }
            else
            {
                jsonEvent["data"]["old_attributes"]["hash_sha256"] = data.at("hash_sha256");
            }
        }

        if (data.at("attributes") != "" && ctx->config->options & CHECK_ATTRS)
        {
            if (old_data.contains("attributes"))
            {
                jsonEvent["data"]["old_attributes"]["attributes"] = old_data["attributes"];
                changed_attributes.push_back("attributes");
            }
            else
            {
                jsonEvent["data"]["old_attributes"]["attributes"] = data.at("attributes");
            }
        }

        if (data.at("checksum") != "")
        {
            if (old_data.contains("checksum"))
            {
                jsonEvent["data"]["old_attributes"]["checksum"] = old_data["checksum"];
            }
            else
            {
                jsonEvent["data"]["old_attributes"]["checksum"] = data.at("checksum");
            }
        }

        jsonEvent["data"]["changed_attributes"] = changed_attributes;
    }


    return jsonEvent;
}

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

    FIMDB::instance().removeItem(deleteQuery.query());
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

    FIMDB::instance().executeQuery(selectQuery.query(), internalCallback);

    if (entryFromPath.size() == 1)
    {
        callback(entryFromPath.front());
    }
    else
    {
        throw no_entry_found { "No entry found for " + path};
    }
}

void DB::updateFile(const nlohmann::json& file, create_json_event_ctx* ctx, std::function<void(nlohmann::json)> callbackPrimitive)
{
    const auto callback
    {
        [file, callbackPrimitive, ctx, this](ReturnTypeCallback type, const nlohmann::json resultJson)
        {
            if (ctx->event->report_event)
            {
                callbackPrimitive(createJsonEvent(file, resultJson, type, ctx));
            }
        }
    };

    FIMDB::instance().updateItem(file, callback);

    return;
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

    FIMDB::instance().executeQuery(selectQuery.query(), localCallback);
}


#ifdef __cplusplus
extern "C" {
#endif

FIMDBErrorCode fim_db_get_path(const char* file_path, callback_context_t callback)
{
    auto retVal { FIMDB_ERR };

    if (!file_path || !callback.callback)
    {
        FIMDB::instance().logFunction(LOG_ERROR, "Invalid parameters");
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

FIMDBErrorCode fim_db_remove_path(const char* path)
{
    auto retVal { FIMDB_ERR };

    if (!path)
    {
        FIMDB::instance().logFunction(LOG_ERROR, "Invalid parameters");
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
            FIMDB::instance().logFunction(LOG_ERROR, err.what());
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
    auto count { 0 };

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
    auto retVal { FIMDB_ERR };

    if (!data || !callback.callback)
    {
        FIMDB::instance().logFunction(LOG_ERROR, "Invalid parameters");
    }
    else
    {
        try
        {
            const auto file { std::make_unique<FileItem>(data, true) };
            create_json_event_ctx* ctx { reinterpret_cast<create_json_event_ctx*>(callback.context)};
            DB::instance().updateFile(*file->toJSON(), ctx, [callback](const nlohmann::json jsonResult)
            {
                const std::unique_ptr<cJSON, CJsonSmartDeleter> spJson{ cJSON_Parse(jsonResult.dump().c_str()) };
                callback.callback(spJson.get(), callback.context);
            });
            retVal = FIMDB_OK;
        }
        // LCOV_EXCL_START
        catch (DbSync::max_rows_error& max_row)
        {
            FIMDB::instance().logFunction(LOG_WARNING, "Reached maximum files limit monitored, due to db_entry_limit configuration for files.");
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
                                        const unsigned long dev,
                                        callback_context_t callback)
{
    auto retVal { FIMDB_ERR };

    if (!callback.callback)
    {
        FIMDB::instance().logFunction(LOG_ERROR, "Invalid parameters");
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
            FIMDB::instance().logFunction(LOG_ERROR, err.what());
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
        FIMDB::instance().logFunction(LOG_ERROR, "Invalid parameters");
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
            FIMDB::instance().logFunction(LOG_ERROR, err.what());
        }

        // LCOV_EXCL_STOP
    }

    return retVal;
}


#ifdef __cplusplus
}
#endif
