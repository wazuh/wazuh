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

#ifndef _FIMDBHELPER_HPP
#define _FIMDBHELPER_HPP
#include "fimDB.hpp"

namespace FIMDBHelper
{
    template<typename T>
#ifndef WIN32
    /**
    * @brief Init the FIM DB instance.
    *
    * @param sync_interval Interval when the sync is performed
    * @param file_limit Max number of files.
    * @param sync_callback Synchronization callback.
    * @param logCallback Logging callback.
    */
    void initDB(const unsigned int sync_interval, const unsigned int file_limit,
                fim_sync_callback_t sync_callback, logging_callback_t logCallback,
                std::shared_ptr<DBSync>handler_DBSync, std::shared_ptr<RemoteSync>handler_RSync)
    {
        T::getInstance().init(sync_interval, file_limit, sync_callback, logCallback, handler_DBSync, handler_RSync);
    }
#else
    /**
    * @brief Init the FIM DB instance.
    *
    * @param sync_interval Interval when the sync is performed
    * @param file_limit Max number of files.
    * @param registry_limit Max number of registries.
    * @param sync_callback Synchronization callback.
    * @param logCallback Logging callback.
    */
    void initDB(const unsigned int sync_interval, const unsigned int file_limit, const unsigned int registry_limit,
                fim_sync_callback_t sync_callback, logging_callback_t logCallback,
                std::shared_ptr<DBSync>handler_DBSync, std::shared_ptr<RemoteSync>handler_RSync)
    {
        T::getInstance().init(sync_interval, file_limit, registry_limit, sync_callback, logCallback, handler_DBSync,
                              handler_RSync);
    }
#endif

    /**
    * @brief Delete a row from a table
    *
    * @param tableName a string with the table name
    * @param filter a string with a filter to delete an element to the database
    *
    */
    template<typename T>
    void removeFromDB(const std::string& tableName, const std::string& filter)
    {
        const auto deleteJsonStatement = R"({
                                                "table": "",
                                                "query": {
                                                    "data":[
                                                    {
                                                    }],
                                                    "where_filter_opt":""
                                                }
        })";
        auto deleteJson = nlohmann::json::parse(deleteJsonStatement);
        deleteJson["table"] = tableName;
        deleteJson["query"]["where_filter_opt"] = filter;

        T::getInstance().removeItem(deleteJson);
    }

    /**
    * @brief Get count of all entries in a table
    *
    * @param tableName a string with the table name
    * @param count a int with count values
    * @param query a json to modify the query
    *
    */
    template<typename T>
    int getCount(const std::string& tableName, const nlohmann::json& query = {})
    {
        auto count { 0 };
        nlohmann::json countQuery;

        if (!query.empty())
        {
            countQuery = query;
        }
        else
        {
            const auto countQueryStatement = R"({
                                                    "table":"",
                                                    "query":{"column_list":["count(*) AS count"],
                                                    "row_filter":"",
                                                    "distinct_opt":false,
                                                    "order_by_opt":"",
                                                    "count_opt":100}
            })";
            countQuery = nlohmann::json::parse(countQueryStatement);
            countQuery["table"] = tableName;

        }

        auto callback
        {
            [&count](ReturnTypeCallback type, const nlohmann::json & jsonResult)
            {
                if (ReturnTypeCallback::SELECTED == type)
                {
                    count = jsonResult["count"];
                }
            }
        };
        T::getInstance().executeQuery(countQuery, callback);

        return count;
    }

    /**
    * @brief Insert or update a row from a table.
    *
    * @param item a json with a RegistryKey, RegistryValue or File with their parameters
    *
    * @return true if this operation was a update, false otherwise.
    */
    template<typename T>
    bool updateItem(const nlohmann::json& item)
    {
        auto result { false };

        const auto callback
        {
            [&result](ReturnTypeCallback type, const nlohmann::json&)
            {
                if (ReturnTypeCallback::MODIFIED == type)
                {
                    result = true;
                }
            }
        };

        T::getInstance().updateItem(item, callback);

        return result;
    }

    /**
    * @brief Get a item from a query
    *
    * @param item a json object where will be saved the query information
    * @param query a json with a query to the database
    *
    */
    template<typename T>
    void getDBItem(nlohmann::json& item, const nlohmann::json& query)
    {
        const auto callback
        {
            [&item](ReturnTypeCallback type, const nlohmann::json & jsonResult)
            {
                if (type == ReturnTypeCallback::SELECTED)
                {
                    item = jsonResult["query"];
                }
            }
        };

        T::getInstance().executeQuery(query, callback);
    }
}

#endif //_FIMDBHELPER_H
