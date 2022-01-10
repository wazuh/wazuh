/**
 * @file fimDBUtils.hpp
 * @brief Definition of FIM custom actions.
 * @date 2021-12-15
 *
 * @copyright Copyright (C) 2015-2021 Wazuh, Inc.
 */
#include "fimDBHelper.hpp"


namespace FimDBUtils
{

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
    inline nlohmann::json dbQuery(const std::string& tableName, const nlohmann::json& columnList, const std::string& filter,
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

    /**
     * @brief Get all the paths asociated to an inode
     *
     * @param inode Inode.
     * @param dev Device.
     *
     * @return a vector with paths asociated to the inode.
     */

    template <typename T>
    static std::vector<std::string> getPathsFromINode(const unsigned long inode, const unsigned long dev)
    {
        std::vector<std::string> paths;
        nlohmann::json resultQuery;

        try
        {
            const auto filter = "WHERE inode=" + std::to_string(inode) + " AND dev=" + std::to_string(dev);
            const auto fileColumnList = R"({"column_list":["path"]})"_json;
            const auto query = dbQuery(FIMBD_FILE_TABLE_NAME, fileColumnList, filter, FILE_PRIMARY_KEY);
            FIMDBHelper::getDBItem<T>(resultQuery, query);

            for (const auto& item : resultQuery["path"].items())
            {
                paths.push_back(item.value());
            }
        }
        catch (const DbSync::dbsync_error& err)
        {
            T::getInstance().logFunction(LOG_ERROR, err.what());
        }
        catch (const std::exception& ex)
        {
            T::getInstance().logFunction(LOG_ERROR, ex.what());
        }

        return paths;
    }

    /**
     * @brief Get path list using the sqlite LIKE operator using @pattern. (stored in @file).
     * @param pattern Pattern that will be used for the LIKE operation.
     *
     * @return a vector with every paths on success, a empty vector otherwise.
     */

    template <typename T>
    static std::vector<std::string> getPathsFromPattern(const std::string& pattern)
    {
        std::vector<std::string> paths;
        nlohmann::json resultQuery;

        try
        {
            const auto filter { "WHERE path LIKE '" + std::string(pattern) + "'" };
            const auto fileColumnList = R"({"column_list":["path"]})"_json;
            const auto queryFromPattern = dbQuery(FIMBD_FILE_TABLE_NAME, fileColumnList, filter, FILE_PRIMARY_KEY);
            FIMDBHelper::getDBItem<T>(resultQuery, queryFromPattern);

            for (const auto& item : resultQuery)
            {
                paths.push_back(item["path"]);
            }

        }
        catch (const DbSync::dbsync_error& err)
        {
            T::getInstance().logFunction(LOG_ERROR, err.what());
        }
        catch (const std::exception& ex)
        {
            T::getInstance().logFunction(LOG_ERROR, ex.what());
        }

        return paths;
    }
};
