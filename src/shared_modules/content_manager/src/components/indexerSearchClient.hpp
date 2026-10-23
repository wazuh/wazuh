/*
 * Wazuh content manager
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INDEXER_SEARCH_CLIENT_HPP
#define _INDEXER_SEARCH_CLIENT_HPP

#include "json.hpp"
#include <cstddef>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

/**
 * @brief A point-in-time handle as the downloader sees it: what every page request carries.
 */
struct SearchPit
{
    std::string id;        ///< PIT id returned by the indexer.
    std::string keepAlive; ///< Keep-alive renewed by every search that uses the PIT.
};

/**
 * @brief The indexer operations the feed downloader needs. The production implementation wraps
 *        IndexerConnectorSync; the unit tests serve an in-memory index.
 *
 * One instance is used from one thread at a time: the downloader creates one per slice worker, as it
 * created one connector per slice before the seam existed.
 */
class IIndexerSearchClient
{
public:
    virtual ~IIndexerSearchClient() = default;

    /// Plain search on an index (consumer status, global-map documents).
    virtual nlohmann::json executeSearchQuery(const std::string& index, const nlohmann::json& searchQuery) = 0;

    virtual SearchPit createPointInTime(const std::vector<std::string>& indices, std::string_view keepAlive) = 0;

    virtual void deletePointInTime(const SearchPit& pit) = 0;

    /// One page of a PIT search; mirrors IndexerConnectorSync::search.
    virtual nlohmann::json search(const SearchPit& pit,
                                  std::size_t size,
                                  const nlohmann::json& query,
                                  const nlohmann::json& sort,
                                  const std::optional<nlohmann::json>& searchAfter = std::nullopt,
                                  const std::optional<nlohmann::json>& source = std::nullopt,
                                  const std::optional<nlohmann::json>& slice = std::nullopt) = 0;
};

/// Builds a client from the updater's `indexer` configuration block.
using IndexerSearchClientFactory =
    std::function<std::unique_ptr<IIndexerSearchClient>(const nlohmann::json& indexerConfig)>;

#endif // _INDEXER_SEARCH_CLIENT_HPP
