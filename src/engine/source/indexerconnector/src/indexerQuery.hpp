/*
 * Wazuh - Indexer query.
 * Copyright (C) 2015, Wazuh Inc.
 * Nov 4, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INDEXER_QUERY_HPP
#define _INDEXER_QUERY_HPP

#include <string>

#include <nlohmann/json.hpp>

/**
 * @brief IndexerQuery class.
 *
 * This class helps to create OpenSearch queries.
 *
 *
 */
class IndexerQuery
{

public:
    /**
     * @brief Method to set up a bulk index operation
     *
     * @param index Index name to use
     * @param id Document ID to use, may be empty
     * @param data Data to add to the query
     * @return std::string Builded query.
     */
    static std::string bulkIndex(const std::string& index, const std::string& id, const std::string& data)
    {
        std::string indexerQuery;
        indexerQuery += R"({"index":{"_index":")" + index + "\"";
        if (!id.empty())
        {
            indexerQuery += R"(,"_id":")" + id + "\"";
        }
        indexerQuery += R"(}})";
        indexerQuery += "\n";
        indexerQuery += data;
        indexerQuery += "\n";

        return indexerQuery;
    }

    /**
     * @brief Method to set up a delete index operation
     *
     * @param index Index name to use
     * @param id Document ID to use.
     * @return std::string Builded query.
     */
    static std::string deleteIndex(const std::string& index, const std::string& id)
    {
        std::string indexerQuery;
        indexerQuery += R"({"delete":{"_index":")" + index + "\"";
        indexerQuery += R"(,"_id":")" + id + "\"";
        indexerQuery += R"(}})";
        indexerQuery += "\n";

        return indexerQuery;
    }
};

#endif // _INDEXER_QUERY_HPP
