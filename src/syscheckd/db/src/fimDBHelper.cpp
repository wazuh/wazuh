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

    return FIMDB::fimDB->getInstance()->removeItem(nlohmann::json::parse(deleteJson));
}

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
    }
    FIMDB::fimDB->getInstance()->executeQuery(countQuery, callback);

    return count;
}

int FIMDBHelper::insertItem(const std::string & tableName, const DBItem & item)
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
    insertStatement["data"] = {*item->toJSON()};

    return FIMDB::fimDB->getInstance()->insertItem(nlohmann::json::parse(insertStatement));
}

int FIMDBHelper::updateItem(const std::string & tableName, const DBItem & item)
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
    auto updateItem;
    auto callback {
        [&updateItem](ReturnTypeCallback type, const nlohmann::json & jsonResult)
        {
        }
    }

    return FIMDB::fimDB->getInstance()->updateItem(nlohmann::json::parse(updateStatement), callback);
}

std::unique_ptr<DBItem> FIMDBHelper::getDBItem(const nlohmann::json & query)
{
    auto item;
    auto callback {
        [&item](ReturnTypeCallback type, const nlohmann::json & jsonResult)
        {
            //TODO: Parse query and generate a DBItem
        }
    }
    FIMDB::fimDB->getInstance()->executeQuery(query, callback);

    return std::make_unique(item);
}
