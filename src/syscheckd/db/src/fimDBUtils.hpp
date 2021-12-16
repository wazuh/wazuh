/**
 * @file fimActions.hpp
 * @brief Definition of FIM custom actions.
 * @date 2021-12-15
 *
 * @copyright Copyright (C) 2015-2021 Wazuh, Inc.
 */
#include "json.hpp"
#include "fimDBHelper.hpp"


namespace FimDBUtils {

    /**
     * @brief Get all the paths asociated to an inode
     *
     * @param inode Inode.
     * @param dev Device.
     *
     * @return a vector with paths asociated to the inode.
     */

    static std::vector<std::string> getPathsFromINode(const unsigned long inode, const unsigned long dev)
    {
        std::vector<std::string> paths;
        nlohmann::json resultQuery;

        try
        {
            const auto filter { std::string("WHERE inode=") + std::to_string(inode) + std::string(" AND dev=") + std::to_string(dev) };
            const auto query { FIMDBHelper::dbQuery(FIMBD_FILE_TABLE_NAME, FILE_PRIMARY_KEY, filter, FILE_PRIMARY_KEY) };
            FIMDBHelper::getDBItem<FIMDB>(resultQuery, query);

            for (const auto& item : resultQuery["path"].items())
            {
                paths.push_back(item.value());
            }
        }
        catch (const DbSync::dbsync_error& err)
        {
            FIMDB::getInstance().logErr(LOG_ERROR, err.what());
        }
        return paths;
    }

    /**
     * @brief Get path list using the sqlite LIKE operator using @pattern. (stored in @file).
     * @param pattern Pattern that will be used for the LIKE operation.
     *
     * @return a vector with every paths on success, a empty vector otherwise.
     */


    static std::vector<std::string> getPathsFromPattern(const std::string & pattern)
    {
        std::vector<std::string> paths;
        nlohmann::json resultQuery;

        try
        {
            const auto filter { std::string("WHERE path LIKE") + std::string(pattern) };
            const auto queryFromPattern { FIMDBHelper::dbQuery(FIMBD_FILE_TABLE_NAME, FILE_PRIMARY_KEY, filter, FILE_PRIMARY_KEY) };
            FIMDBHelper::getDBItem<FIMDB>(resultQuery, queryFromPattern);

            for (const auto& item : resultQuery["path"].items())
            {
                paths.push_back(item.value());
            }

        }
        catch (const DbSync::dbsync_error& err)
        {
            FIMDB::getInstance().logErr(LOG_ERROR, err.what());
        }
        return paths;
    }
};
