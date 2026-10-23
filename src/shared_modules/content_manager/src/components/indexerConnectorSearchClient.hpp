/*
 * Wazuh content manager
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INDEXER_CONNECTOR_SEARCH_CLIENT_HPP
#define _INDEXER_CONNECTOR_SEARCH_CLIENT_HPP

#include "indexerConnector.hpp"
#include "indexerSearchClient.hpp"
#include "sharedDefs.hpp"
#include <memory>
#include <string>
#include <utility>

/**
 * @brief Production IIndexerSearchClient: one IndexerConnectorSync behind the seam.
 *
 * Kept out of IndexerDownloader.hpp so that the unit tests of the downloader do not link the
 * indexer connector.
 */
class IndexerConnectorSearchClient final : public IIndexerSearchClient
{
public:
    explicit IndexerConnectorSearchClient(const nlohmann::json& indexerConfig)
        : m_connector(indexerConfig, LoggingContext {WM_CONTENTUPDATER, {}})
    {
    }

    nlohmann::json executeSearchQuery(const std::string& index, const nlohmann::json& searchQuery) override
    {
        return m_connector.executeSearchQuery(index, searchQuery);
    }

    SearchPit createPointInTime(const std::vector<std::string>& indices, std::string_view keepAlive) override
    {
        const auto pit = m_connector.createPointInTime(indices, keepAlive);
        return SearchPit {pit.getPitId(), pit.getKeepAlive()};
    }

    void deletePointInTime(const SearchPit& pit) override
    {
        m_connector.deletePointInTime(toPointInTime(pit));
    }

    nlohmann::json search(const SearchPit& pit,
                          std::size_t size,
                          const nlohmann::json& query,
                          const nlohmann::json& sort,
                          const std::optional<nlohmann::json>& searchAfter,
                          const std::optional<nlohmann::json>& source,
                          const std::optional<nlohmann::json>& slice) override
    {
        return m_connector.search(toPointInTime(pit), size, query, sort, searchAfter, source, slice);
    }

private:
    // The requests only carry the id and the keep-alive; the creation time is not used by them.
    static PointInTime toPointInTime(const SearchPit& pit)
    {
        return PointInTime {pit.id, 0, pit.keepAlive};
    }

    IndexerConnectorSync m_connector;
};

/// Factory the production chain hands to IndexerDownloader.
inline std::unique_ptr<IIndexerSearchClient> makeIndexerConnectorSearchClient(const nlohmann::json& indexerConfig)
{
    return std::make_unique<IndexerConnectorSearchClient>(indexerConfig);
}

#endif // _INDEXER_CONNECTOR_SEARCH_CLIENT_HPP
