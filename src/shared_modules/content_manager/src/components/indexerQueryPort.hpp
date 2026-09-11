/*
 * Wazuh content manager
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INDEXER_QUERY_PORT_HPP
#define _INDEXER_QUERY_PORT_HPP

#include "indexerConnector.hpp"
#include <json.hpp>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

/**
 * @brief The five indexer operations the content cycle needs, behind an interface.
 *
 * This is the seam the old `IndexerDownloader` did not have: it took `IndexerConnectorSync` by
 * concrete type, so ~1050 of its 1408 lines were `LCOV_EXCL`'d as "integration-only". Everything
 * above this interface — the PIT session, the readiness gate, the change detectors, the paginator
 * and the cycle — is now driven by a fake in unit tests.
 *
 * Implementations may throw (`IndexerConnectorException`) on transport failure; `ContentCycle` is
 * the single place that catches, and it does so inside the `.so`.
 */
class IIndexerQueryPort
{
public:
    virtual ~IIndexerQueryPort() = default;

    /**
     * @brief Open a Point-in-Time over a set of indices.
     *
     * @param indices Index names to include.
     * @param keepAlive Lease duration, e.g. "5m".
     * @param expandWildcards Whether wildcard patterns in @p indices should be expanded.
     * @return The open PIT.
     */
    virtual PointInTime
    openPit(const std::vector<std::string>& indices, std::string_view keepAlive, bool expandWildcards) = 0;

    /**
     * @brief Release a PIT. Never throws: a leaked lease expires on its own.
     *
     * @param pit PIT to release.
     */
    virtual void closePit(const PointInTime& pit) noexcept = 0;

    /**
     * @brief Run one search inside a PIT.
     *
     * @param pit PIT to search within.
     * @param size Maximum hits to return.
     * @param query Query object.
     * @param sort Sort array. Required for `search_after` pagination.
     * @param searchAfter Optional cursor from the previous page's last `sort` value.
     * @param source Optional `_source` filter.
     * @param slice Optional slice descriptor, e.g. `{"id": 0, "max": 2}`.
     * @return The `hits` object of the response.
     */
    virtual nlohmann::json search(const PointInTime& pit,
                                  std::size_t size,
                                  const nlohmann::json& query,
                                  const nlohmann::json& sort,
                                  const std::optional<nlohmann::json>& searchAfter,
                                  const std::optional<nlohmann::json>& source,
                                  const std::optional<nlohmann::json>& slice) = 0;

    /**
     * @brief Run one search against an index, outside any PIT.
     *
     * Used only by the cheap pre-flight consumer probe, which deliberately does not pay for a PIT.
     *
     * @param index Index name.
     * @param body Full search request body.
     * @return The raw search response.
     */
    virtual nlohmann::json searchIndex(std::string_view index, const nlohmann::json& body) = 0;

    /**
     * @brief A fresh, independently usable port over the same indexer.
     *
     * Called only by the paginator, once per slice worker: HTTP state must not be shared across
     * threads. The clones are destroyed when the fetch returns.
     *
     * @return A new port equivalent to this one.
     */
    virtual std::unique_ptr<IIndexerQueryPort> clone() const = 0;
};

#endif // _INDEXER_QUERY_PORT_HPP
