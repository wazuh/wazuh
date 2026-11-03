/*
 * Wazuh content manager
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _PIT_SESSION_HPP
#define _PIT_SESSION_HPP

#include "consumerGate.hpp"
#include "contentIndexer.hpp"
#include <json.hpp>
#include <string>
#include <utility>
#include <vector>

/**
 * @brief One Point-in-Time, and the consistency guarantee built on top of it.
 *
 * The consumer status document lives in its own index, so checking it *before* opening the PIT
 * leaves a window in which the indexer starts rewriting content between the check and the snapshot
 * — which is precisely the state the check exists to avoid. This class closes that window by
 * pulling the consumer index into the PIT and validating the document from inside the snapshot.
 *
 * Doing so costs two things, both handled here:
 *  - the consumer index's documents would otherwise show up in a `match_all` data query, so
 *    @ref scopeToData excludes them query-side and @ref isConsumerDoc lets the paginator drop any
 *    that still arrive (belt and braces: the two defences fail differently);
 *  - a sort key can end up unmapped across every index in the PIT, which makes the whole search
 *    fail. The consumer index lacking the key is not enough to cause that on its own — OpenSearch
 *    needs it mapped in only one index — but a cold start, where the data index has no documents
 *    and so no dynamic mapping either, is. The cursor sort carries an `unmapped_type` for that (see
 *    FactoryContentUpdater).
 *
 * The PIT is opened by the constructor (which can therefore throw) and always released by the
 * destructor (which cannot).
 */
class PitSession final
{
public:
    /// What the session is opened over.
    struct Config
    {
        std::vector<std::string> dataIndices; ///< Indices holding the content itself.
        std::string consumerStatusIndex;      ///< "" disables in-PIT validation entirely.
        std::string consumerStatusId;         ///< `_id` of the consumer document.
        std::string keepAlive {"5m"};         ///< PIT lease duration.
        bool expandWildcards {false};         ///< Expand wildcard patterns in `dataIndices`.
    };

    /**
     * @brief Open the PIT.
     *
     * @param port Indexer access. Must outlive the session.
     * @param cfg Session configuration.
     * @throws std::exception whatever the indexer throws when the PIT cannot be opened.
     */
    PitSession(content_manager::IContentIndexer& port, Config cfg)
        : m_port {port}
        , m_config {std::move(cfg)}
        , m_pit {port.openPit(indices(), m_config.keepAlive, m_config.expandWildcards)}
    {
    }

    ~PitSession()
    {
        m_port.closePit(m_pit);
    }

    PitSession(const PitSession&) = delete;
    PitSession& operator=(const PitSession&) = delete;

    /**
     * @brief Read the consumer's status from inside the snapshot.
     *
     * @return The consumer's state. `Ready` when validation is disabled.
     * @throws std::exception whatever the indexer throws when the search fails.
     */
    ConsumerGate::Result validateConsumerReady()
    {
        if (!validationEnabled())
        {
            return ConsumerGate::Result {ConsumerGate::Status::Ready, {}, {}};
        }

        return ConsumerGate::parse(m_port.search(m_pit,
                                                 1,
                                                 ConsumerGate::statusQuery(m_config.consumerStatusId),
                                                 docSort(),
                                                 std::nullopt,
                                                 ConsumerGate::statusSourceFilter(),
                                                 std::nullopt));
    }

    /**
     * @brief Count how many of a set of document ids are present in the snapshot.
     *
     * Runs inside the PIT, so it sees exactly the content the fetch will read.
     *
     * @param ids Document ids to look for.
     * @return How many were found.
     * @throws std::exception whatever the indexer throws when the search fails.
     */
    std::size_t countDocuments(const std::vector<std::string>& ids)
    {
        const nlohmann::json query {{"ids", {{"values", ids}}}};
        const nlohmann::json source {{"includes", nlohmann::json::array()}, {"excludes", nlohmann::json::array()}};

        const auto hits =
            m_port.search(m_pit, ids.size(), scopeToData(query), docSort(), std::nullopt, source, std::nullopt);
        const auto& hitArray = hits.contains("hits") ? hits.at("hits") : nlohmann::json::array();
        return hitArray.is_array() ? hitArray.size() : 0U;
    }

    /// @return The open PIT.
    const content_manager::ContentPit& pit() const noexcept
    {
        return m_pit;
    }

    /// @return True when the consumer index is part of this PIT.
    bool validationEnabled() const noexcept
    {
        return !m_config.consumerStatusIndex.empty() && !m_config.consumerStatusId.empty();
    }

    /**
     * @brief Restrict a caller's query to the data indices.
     *
     * With the consumer index inside the PIT, an unrestricted `match_all` would return consumer
     * documents as if they were content. This wraps the query so they cannot match.
     *
     * @param userQuery The detector-supplied query.
     * @return The query to actually send.
     */
    nlohmann::json scopeToData(const nlohmann::json& userQuery) const
    {
        if (!validationEnabled())
        {
            return userQuery;
        }

        nlohmann::json scoped;
        scoped["bool"]["must"] = nlohmann::json::array({userQuery});
        scoped["bool"]["must_not"] = nlohmann::json::array(
            {nlohmann::json {{"terms", {{"_index", nlohmann::json::array({m_config.consumerStatusIndex})}}}}});
        return scoped;
    }

    /**
     * @brief Whether a hit came from the consumer index rather than from the content.
     *
     * @param hit One search hit.
     * @return True when the hit must not be delivered to the sink.
     */
    bool isConsumerDoc(const nlohmann::json& hit) const noexcept
    {
        if (!validationEnabled())
        {
            return false;
        }

        const auto it = hit.find("_index");
        return it != hit.end() && it->is_string() && it->get_ref<const std::string&>() == m_config.consumerStatusIndex;
    }

    /// `_doc` then `_id`: metafields every index of the PIT has, so no `unmapped_type` is needed even
    /// with the consumer index in it, and `_id` breaks the ties `_doc` has across shards. Not
    /// `_shard_doc`, which OpenSearch 2.x rejects ("No mapping found for [_shard_doc]").
    static const nlohmann::json& docSort()
    {
        static const nlohmann::json sort =
            nlohmann::json::array({nlohmann::json {{"_doc", "asc"}}, nlohmann::json {{"_id", "asc"}}});
        return sort;
    }

private:
    /// @return The data indices, plus the consumer index when validation is enabled.
    std::vector<std::string> indices() const
    {
        auto all = m_config.dataIndices;
        if (validationEnabled())
        {
            all.emplace_back(m_config.consumerStatusIndex);
        }
        return all;
    }

    content_manager::IContentIndexer& m_port;
    Config m_config;
    content_manager::ContentPit m_pit;
};

#endif // _PIT_SESSION_HPP
