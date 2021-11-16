/*
 * Wazuh Syscheckd
 * Copyright (C) 2015-2021, Wazuh Inc.
 * November 1, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "fimDBHelper.hpp"
#include "fimDB.hpp"

template<class T>
int FIMDBHelper::removeFromDB(const std::string& tableName, const nlohmann::json& filter)
{
    auto deleteJson = R"({
                            "table": "",
                            "query": {
                                "data":[
                                {
                                }],
                                "where_filter_opt":""
                            }
    })"_json;
    deleteJson["table"] = tableName;
    deleteJson["query"]["data"] = {filter};

    return T::getInstance().removeItem(deleteJson);
}

template<class T>
int FIMDBHelper::getCount(const std::string & tableName)
{
    auto countQuery = R"({
                            "table":"",
                            "query":{"column_list":["count(*) AS count"],
                            "row_filter":"",
                            "distinct_opt":false,
                            "order_by_opt":"",
                            "count_opt":100}
    })"_json;
    countQuery["table"] = tableName;
    auto count = 0;
    auto callback {
        [&count](ReturnTypeCallback type, const nlohmann::json & jsonResult)
        {
        }
    };
    T::getInstance().executeQuery(countQuery, callback);

    return count;
}

template<class T>
int FIMDBHelper::insertItem(const std::string & tableName, const nlohmann::json & item)
{
    auto insertStatement = R"(
                            {
                                "table": "",
                                "data":[
                                    {
                                    }
                                ]
                            }   
    )"_json;
    insertStatement["table"] = tableName;
    insertStatement["data"] = {item};

    return T::getInstance().insertItem(insertStatement);
}

template<class T>
int FIMDBHelper::updateItem(const std::string & tableName, const nlohmann::json & item)
{
    auto updateStatement = R"(
                            {
                                "table": "",
                                "data":[
                                    {
                                    }
                                ]
                            }   
    )"_json;
    updateStatement["table"] = tableName;
    updateStatement["data"] = {item};
    auto callback {
        [](ReturnTypeCallback type, const nlohmann::json & jsonResult)
        {
        }
    };

    return T::getInstance().updateItem(updateStatement, callback);
}

template<class T>
int FIMDBHelper::getDBItem(DBItem & item, const nlohmann::json & query)
{
    auto callback {
        [&item](ReturnTypeCallback type, const nlohmann::json & jsonResult)
        {
            //TODO: Parse query and generate a DBItem
        }
    };

    return T::getInstance().executeQuery(query, callback);
}
