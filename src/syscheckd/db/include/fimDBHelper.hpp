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

    void initDB(const std::string&, int, int, void(*sync_callback)(const char* log, const char* tag), void(*loggFunction)(modules_log_level_t level));

    /**
    * @brief Insert a new row from a table.
    *
    * @param tableName a string with the table name
    * @param item a RegistryKey, RegistryValue or File with their parameters
    *
    * @return 0 on success, another value otherwise.
    */
    int insertItem(const std::string &, const nlohmann::json &);

    /**
    * @brief Get count of all entries in a table
    *
    * @param tableName a string with the table name
    *
    * @return amount of entries on success, 0 otherwise.
    */
    int getCount(const std::string &);

    /**
    * @brief Get a item from a query
    *
    * @param item a json object where will be saved the query information
    * @param query a json with a query to the database
    *
    * @return a file, registryKey or registryValue, nullptr otherwise.
    */
    int getDBItem(nlohmann::json &, const nlohmann::json &);

    /**
    * @brief Delete a row from a table
    *
    * @param tableName a string with the table name
    * @param query a json with a filter to delete an element to the database
    *
    * @return 0 on success, another value otherwise.
    */
    int removeFromDB(const std::string &, const nlohmann::json &);

    /**
    * @brief Update a row from a table.
    *
    * @param tableName a string with the table name
    * @param item a RegistryKey, RegistryValue or File with their parameters
    *
    * @return 0 on success, another value otherwise.
    */
    int updateItem(const std::string &, const nlohmann::json &);

    // Template function must be defined in fimHelper.hpp
    template<typename T>
    int FIMDBHelper::removeFromDB(const std::string& tableName, const nlohmann::json& filter)
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

        return T::getInstance().removeItem(deleteJson);
    }

    template<typename T>
    int FIMDBHelper::getCount(const std::string & tableName, int & count)
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
        auto callback {
            [&count](ReturnTypeCallback type, const nlohmann::json & jsonResult)
            {
                if(type == ReturnTypeCallback::SELECTED)
                {
                   count = jsonResult["query"]["count"];
                }
            }
        };
        return T::getInstance().executeQuery(countQuery, callback);
    }

    template<typename T>
    int FIMDBHelper::insertItem(const std::string & tableName, const nlohmann::json & item)
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

        return T::getInstance().insertItem(insert);
    }

    template<typename T>
    int FIMDBHelper::updateItem(const std::string & tableName, const nlohmann::json & item)
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
        update["data"] = {item};
        bool error = false;
        auto callback {
            [&error](ReturnTypeCallback type, const nlohmann::json &)
            {
                if (type == ReturnTypeCallback::DB_ERROR)
                {
                    error = true;
                }
            }
        };
        if(error)
        {
            return static_cast<int>(dbQueryResult::DBSYNC_ERROR);
        }

        return T::getInstance().updateItem(update, callback);
    }

    template<typename T>
    int FIMDBHelper::getDBItem(nlohmann::json & item, const nlohmann::json & query)
    {
        auto callback {
            [&item](ReturnTypeCallback type, const nlohmann::json & jsonResult)
            {
                if (type == ReturnTypeCallback::SELECTED)
                {
                    item = jsonResult["query"];
                }
            }
        };

        return T::getInstance().executeQuery(query, callback);
    }

    template<typename T>
    void FIMDBHelper::initDB(const std::string& path, unsigned int sync_interval, unsigned int file_limit,
                            fim_sync_callback_t sync_callback,
                            void(*loggFunction)(modules_log_level_t level))
    {
        auto handler_DBSync = std::make_shared<DBSync>(HostType::AGENT, DbEngineType::SQLITE3, path, T::CreateStatement());
        auto handler_RSync = std::make_shared<RemoteSync>();

        T::getInstance().init(sync_interval, file_limit, sync_callback, loggFunction, handler_DBSync, handler_RSync);
    }
}

#endif //_FIMDBHELPER_H
