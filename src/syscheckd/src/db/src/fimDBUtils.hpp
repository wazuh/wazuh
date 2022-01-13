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
#include <string>
#include <json.hpp>

namespace FimDBUtils
{
    /**
    * @brief Build query to delete a file from the database.
    *
    * @param tableName a string with the table name.
    * @param filter a vector of pair strings with the filter to apply.
    *
    */

    inline nlohmann::json buildRemoveQuery(const std::string& tableName,
                                           const std::vector<std::pair<std::string, std::string>>& filter)
    {
        const auto deleteJsonStatement = R"({
                                                "table": "",
                                                "query": {
                                                }
        })";
        auto deleteJson = nlohmann::json::parse(deleteJsonStatement);
        deleteJson["table"] = tableName;

        for (const auto& item : filter)
        {
            deleteJson["query"]["data"].push_back({item});
        }

        deleteJson["query"]["where_filter_opt"] = "";
        return deleteJson;
    }

    /**
    * @brief Build query to select data from the database.
    *
    * @param tableName a string with table name
    * @param columnList an array with the column list
    * @param filter a string with a filter to a table
    * @param order a string with the column to order in result
    *
    * @return a nlohmann::json with a database query
    */
    inline nlohmann::json buildSelectQuery(const std::string& tableName,
                                           const nlohmann::json& columnList,
                                           const std::string& filter,
                                           const std::string& order)
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
};
