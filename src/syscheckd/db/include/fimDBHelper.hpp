/*
 * Wazuh Syscheckd
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
#include "dbItem.hpp"

namespace FIMDBHelper
{
    template<typename T>
#ifndef WIN32
    /**
    * @brief Init the FIM DB instance.
    *
    * @param sync_interval Interval when the sync is performed-
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
    * @param sync_interval Interval when the sync is performed-
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
    * @param query a json with a filter to delete an element to the database
    *
    */
    template<typename T>
    void removeFromDB(const std::string& tableName, const nlohmann::json& filter)
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
        deleteJson["query"]["data"] = {filter};

        T::getInstance().removeItem(deleteJson);
    }
    /**
    * @brief Get count of all entries in a table
    *
    * @param tableName a string with the table name
    * @param count a int with count values
    *
    */
    template<typename T>
    void getCount(const std::string& tableName, int& count)
    {
        const auto countQueryStatement = R"({
                                                "table":"",
                                                "query":{"column_list":["count(*) AS count"],
                                                "row_filter":"",
                                                "distinct_opt":false,
                                                "order_by_opt":"",
                                                "count_opt":100}
        })";
        auto countQuery = nlohmann::json::parse(countQueryStatement);
        countQuery["table"] = tableName;
        auto callback
        {
            [&count](ReturnTypeCallback type, const nlohmann::json & jsonResult)
            {
                if (type == ReturnTypeCallback::SELECTED)
                {
                    count = jsonResult["query"]["count"];
                }
            }
        };
        T::getInstance().executeQuery(countQuery, callback);
    }

    /**
    * @brief Insert a new row from a table.
    *
    * @param tableName a string with the table name
    * @param item a RegistryKey, RegistryValue or File with their parameters
    *
    */
    template<typename T>
    void insertItem(const std::string& tableName, const nlohmann::json& item)
    {
        const auto insertStatement = R"(
                                            {
                                                "table": "",
                                                "data":[
                                                    {
                                                    }
                                                ]
                                            }
        )";
        auto insert =  nlohmann::json::parse(insertStatement);
        insert["table"] = tableName;
        insert["data"] = {item};

        T::getInstance().insertItem(insert);
    }

    /**
    * @brief Update a row from a table.
    *
    * @param tableName a string with the table name
    * @param item a RegistryKey, RegistryValue or File with their parameters
    *
    * @return 0 on success, another value otherwise.
    */
    template<typename T>
    void updateItem(const std::string& tableName, const nlohmann::json& item)
    {
        const auto updateStatement = R"(
                                            {
                                                "table": "",
                                                "data":[
                                                    {
                                                    }
                                                ]
                                            }
        )";
        auto update = nlohmann::json::parse(updateStatement);
        update["table"] = tableName;
        update["data"] = nlohmann::json::array({item});
        bool error = false;
        const auto callback
        {
            [&error](ReturnTypeCallback type, const nlohmann::json&)
            {
                if (type == ReturnTypeCallback::DB_ERROR)
                {
                    error = true;
                }
            }
        };

        T::getInstance().updateItem(update, callback);
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

    /**
    * @brief Create a new query to database
    *
    * @param tableName a string with table name
    * @param columnList an array with the column list
    * @param filter a string with a filter to a table
    * @param order a string with the column to order in result
    *
    * @return a nlohmann::json with a database query
    */
    nlohmann::json dbQuery(const std::string & tableName, const nlohmann::json & columnList, const std::string & filter,
                           const std::string & order)
    {
        nlohmann::json query;
        query["table"] = tableName;
        query["query"]["column_list"] = columnList["column_list"];
        query["query"]["row_filter"] = filter;
        query["query"]["distinct_opt"] = false;
        query["query"]["order_by_opt"] = order;
        query["query"]["count_opt"] = 100;

        return query;
    }

    /**
    * @brief Start the synchronization module of FIM
    */
    template<typename T>
    void fimSyncStart()
    {
        std::mutex sync_mutex;
        std::unique_lock<std::mutex> lock{sync_mutex};

        T::getInstance().registerRSync();
        T::getInstance().loopRSync(lock);
    }
}

#endif //_FIMDBHELPER_H
