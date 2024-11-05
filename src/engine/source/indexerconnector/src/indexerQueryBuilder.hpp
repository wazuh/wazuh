/*
 * Wazuh - Indexer query builder.
 * Copyright (C) 2015, Wazuh Inc.
 * Nov 4, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INDEXER_QUERY_BUILDER_HPP
#define _INDEXER_QUERY_BUILDER_HPP

#include <string>

#include <nlohmann/json.hpp>

#include <base/utils/builder.hpp>

/**
 * @brief IndexerQueryBuilder class.
 *
 * This class is a builder for creating OpenSearch queries.
 *
 * @note This class is not thread-safe. Implements the Builder pattern.
 *
 */
class IndexerQueryBuilder : public base::utils::patterns::Builder<IndexerQueryBuilder>
{
private:
    std::string m_indexerQuery; ///< The query string

public:
    /**
     * @brief Construct a new Indexer Query Builder object
     */
    IndexerQueryBuilder() = default;

    /**
     * @brief Method to set up a bulk index operation
     *
     * @param index Index name to use
     * @param id Document ID to use, may be empty
     * @return IndexerQueryBuilder& Reference to the builder object
     */
    IndexerQueryBuilder& bulkIndex(const std::string& index, const std::string& id)
    {
        m_indexerQuery += R"({"index":{"_index":")" + index + R"(")";
        if (!id.empty())
        {
            m_indexerQuery += R"(,"_id":")" + id + R"(")";
        }
        m_indexerQuery += R"(}})";
        m_indexerQuery += "\n";
        return *this;
    }

    /**
     * @brief Method to set up a delete index operation
     *
     * @param index Index name to use
     * @param id Document ID to use, may be empty
     * @return IndexerQueryBuilder& Reference to the builder object
     */
    IndexerQueryBuilder& deleteIndex(const std::string& index, const std::string& id)
    {
        m_indexerQuery += R"({"delete":{"_index":")" + index + R"(")";
        if (!id.empty())
        {
            m_indexerQuery += R"(,"_id":")" + id + R"(")";
        }
        m_indexerQuery += R"(}})";
        m_indexerQuery += "\n";
        return *this;
    }

    /**
     * @brief Method to set up a delete by query operation
     *
     * @return IndexerQueryBuilder& Reference to the builder object
     */
    IndexerQueryBuilder& deleteByQuery()
    {
        m_indexerQuery += R"({"query":{"bool":{"filter":{"terms":{"agent.id":[)";
        return *this;
    }

    /**
     * @brief Method to add agent IDs to the delete-by-query operation
     *
     * @param agentIds List of agent IDs to delete
     * @return IndexerQueryBuilder& Reference to the builder object
     *
     * @note This method appends the agent IDs to the query and closes the JSON structure
     */
    IndexerQueryBuilder& appendId(const std::vector<std::string>& agentIds)
    {
        if (agentIds.empty())
        {
            throw std::runtime_error("Agent ID list is empty.");
        }

        // Use a string stream to build the agent IDs string efficiently
        std::ostringstream agentIdsStream;
        for (const auto& agentId : agentIds)
        {
            agentIdsStream << R"(")" << agentId << R"(")"
                           << ",";
        }

        // Convert the stream to a string and remove the trailing comma
        std::string agentIdsStr = agentIdsStream.str();
        if (!agentIdsStr.empty())
        {
            agentIdsStr.pop_back(); // Remove the last comma
        }

        // Append the agent IDs to the query and close the JSON structure
        m_indexerQuery += agentIdsStr;
        m_indexerQuery += R"(]}}}})";

        return *this;
    }

    /**
     * @brief Method to add data to the query in bulk operations
     *
     * @param data Data to add to the query
     * @return IndexerQueryBuilder& Reference to the builder object
     */
    IndexerQueryBuilder& addData(const std::string& data)
    {
        m_indexerQuery += data;
        m_indexerQuery += "\n";
        return *this;
    }

    /**
     * @brief Method to build the query
     *
     * @return std::string The built query
     */
    std::string build() const { return m_indexerQuery; }

    /**
     * @brief Method to clear the query
     *
     * @return IndexerQueryBuilder& Reference to the builder object
     */
    IndexerQueryBuilder& clear()
    {
        m_indexerQuery.clear();
        return *this;
    }
};

#endif // _INDEXER_QUERY_BUILDER_HPP
