/*
 * Wazuh content manager
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CONTENT_INDEXER_HPP
#define _CONTENT_INDEXER_HPP

#include <cstddef>
#include <cstdint>
#include <json.hpp>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace content_manager
{
    /**
     * @brief An open Point-in-Time, as the content cycle carries it between calls.
     *
     * The library's own type rather than the indexer connector's `PointInTime`, so this header — part
     * of the public contract — does not have to include the connector's header (see D1).
     */
    struct ContentPit
    {
        std::string id;                 ///< PIT id the indexer returned.
        std::uint64_t creationTime {0}; ///< Creation time the indexer returned.
        std::string keepAlive;          ///< Lease the PIT was opened with, e.g. "5m".
    };

    /**
     * @brief The host's indexer, as the content manager uses it: four read operations, nothing else.
     *
     * The library never builds an indexer connection of its own (D1). Each host hands the connector it
     * already owns to every registration — through `makeContentIndexer` (contentIndexerAdapters.hpp)
     * or its own implementation — so a process runs one connector, one health monitor and one
     * keystore read, and an indexer outage is reported once.
     *
     * **Implementations must accept concurrent calls**: slice workers of one download, cycles of
     * several topics, the scheduler and the on-demand lane all use the one instance at once. They must
     * not hold a lock of their own across a request. They may throw on transport failure; the content
     * cycle is the single place that catches, inside the library.
     */
    class IContentIndexer
    {
    public:
        virtual ~IContentIndexer() = default;

        /**
         * @brief Open a Point-in-Time over a set of indices.
         *
         * @param indices Index names to include.
         * @param keepAlive Lease duration, e.g. "5m".
         * @param expandWildcards Whether wildcard patterns in @p indices should be expanded.
         * @return The open PIT.
         */
        virtual ContentPit
        openPit(const std::vector<std::string>& indices, std::string_view keepAlive, bool expandWildcards) = 0;

        /**
         * @brief Release a PIT. Never throws: a leaked lease expires on its own.
         *
         * @param pit PIT to release.
         */
        virtual void closePit(const ContentPit& pit) noexcept = 0;

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
        virtual nlohmann::json search(const ContentPit& pit,
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
         * @param size Maximum hits to return.
         * @param query Query object.
         * @param source Optional `_source` filter.
         * @return The `hits` object of the response (`{"total": …, "hits": [...]}`).
         */
        virtual nlohmann::json searchIndex(std::string_view index,
                                           std::size_t size,
                                           const nlohmann::json& query,
                                           const std::optional<nlohmann::json>& source) = 0;
    };
} // namespace content_manager

#endif // _CONTENT_INDEXER_HPP
