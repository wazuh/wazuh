/*
 * Wazuh content manager
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PIT_SESSION_HPP
#define _PIT_SESSION_HPP

#include "indexerQueryPort.hpp"
#include "loggerHelper.h"
#include "sharedDefs.hpp"
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
 * pulling `consumerStatusIndex` into the PIT and validating the document from inside the snapshot,
 * the way the Engine's `validateConsumerReadyInPit` already does.
 *
 * Doing so costs two things, both handled here:
 *  - the consumer index's documents would otherwise show up in a `match_all` data query, so
 *    @ref scopeToData excludes them query-side and @ref isConsumerDoc lets the paginator drop any
 *    that still arrive (belt and braces: the two defences fail differently);
 *  - a sort key can end up unmapped across every index in the PIT, which makes the whole search
 *    fail. The consumer index lacking the key is not enough to cause that on its own — OpenSearch
 *    needs it mapped in only one index — but a cold start, where the data index has no documents
 *    and so no dynamic mapping either, is. Injecting `unmapped_type` is the factory's job, not this
 *    class's, because it needs the detector's field name — see FactoryContentUpdater.
 *
 * The PIT is opened by the constructor (which can therefore throw) and always released by the
 * destructor (which cannot).
 */
class PitSession final
{
public:
    /// How ready the consumer that feeds this content is.
    enum class Readiness
    {
        Ready,    ///< `status == "ready"`: the snapshot is safe to read.
        NotReady, ///< The consumer is running, failed, or reports a status we do not know.
        Missing,  ///< No consumer document at all — the normal state of a fresh install.
        Unusable  ///< The document exists but carries no readable status.
    };

    /// What the session is opened over.
    struct Config
    {
        std::vector<std::string> dataIndices;  ///< Indices holding the content itself.
        std::string consumerStatusIndex;       ///< "" disables in-PIT validation entirely.
        std::string consumerStatusId;          ///< `_id` of the consumer document.
        std::string keepAlive {"5m"};          ///< PIT lease duration.
        bool expandWildcards {false};          ///< Expand wildcard patterns in `dataIndices`.
    };

    /**
     * @brief Open the PIT.
     *
     * @param port Indexer access. Must outlive the session.
     * @param cfg Session configuration.
     * @throws IndexerConnectorException if the PIT cannot be opened.
     */
    PitSession(IIndexerQueryPort& port, Config cfg)
        : m_port {port}
        , m_config {std::move(cfg)}
        , m_pit {port.openPit(buildIndices(m_config), m_config.keepAlive, m_config.expandWildcards)}
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
     * @param[out] rawStatus If non-null, receives the raw status string for logging.
     * @return The consumer's readiness. `Ready` when validation is disabled.
     * @throws IndexerConnectorException if the search itself fails.
     */
    Readiness validateConsumerReady(std::string* rawStatus = nullptr)
    {
        if (!validationEnabled())
        {
            return Readiness::Ready;
        }

        const nlohmann::json query {{"ids", {{"values", nlohmann::json::array({m_config.consumerStatusId})}}}};
        const nlohmann::json source {{"includes", nlohmann::json::array({"status"})},
                                     {"excludes", nlohmann::json::array()}};

        const auto hits = m_port.search(m_pit, 1, query, consumerSort(), std::nullopt, source, std::nullopt);

        const auto& hitArray = hits.contains("hits") ? hits.at("hits") : nlohmann::json::array();
        if (!hitArray.is_array() || hitArray.empty())
        {
            return Readiness::Missing;
        }

        const auto& hit = hitArray.front();
        if (!hit.contains("_source") || !hit.at("_source").is_object())
        {
            return Readiness::Unusable;
        }

        const auto& hitSource = hit.at("_source");
        if (!hitSource.contains("status") || !hitSource.at("status").is_string())
        {
            return Readiness::Unusable;
        }

        const auto status = hitSource.at("status").get<std::string>();
        if (rawStatus != nullptr)
        {
            *rawStatus = status;
        }

        if (status.empty())
        {
            return Readiness::Unusable;
        }

        return status == "ready" ? Readiness::Ready : Readiness::NotReady;
    }

    /**
     * @brief Count how many of a set of document ids are present in the snapshot.
     *
     * Backs the generalized global-maps precondition. Because it runs inside the PIT it is, unlike
     * the poll it replaces, free of the same time-of-check/time-of-use race as the readiness check.
     *
     * @param ids Document ids to look for.
     * @return How many were found.
     * @throws IndexerConnectorException if the search fails.
     */
    std::size_t countDocuments(const nlohmann::json& ids)
    {
        const nlohmann::json query {{"ids", {{"values", ids}}}};
        const nlohmann::json source {{"includes", nlohmann::json::array()}, {"excludes", nlohmann::json::array()}};

        const auto hits = m_port.search(m_pit, ids.size(), scopeToData(query), consumerSort(), std::nullopt, source, std::nullopt);
        const auto& hitArray = hits.contains("hits") ? hits.at("hits") : nlohmann::json::array();
        return hitArray.is_array() ? hitArray.size() : 0U;
    }

    /// @return The open PIT.
    const PointInTime& pit() const noexcept
    {
        return m_pit;
    }

    /// @return True when the consumer index is part of this PIT.
    bool validationEnabled() const noexcept
    {
        return !m_config.consumerStatusIndex.empty() && !m_config.consumerStatusId.empty();
    }

    /// @return The consumer status index, or "" when validation is disabled.
    const std::string& consumerStatusIndex() const noexcept
    {
        return m_config.consumerStatusIndex;
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
        if (m_config.consumerStatusIndex.empty())
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
        if (m_config.consumerStatusIndex.empty())
        {
            return false;
        }

        const auto it = hit.find("_index");
        return it != hit.end() && it->is_string() && it->get_ref<const std::string&>() == m_config.consumerStatusIndex;
    }

    /**
     * @brief The index list a session with this configuration opens its PIT over.
     *
     * Exposed as a static so the factory can validate and log it without opening anything.
     *
     * @param cfg Session configuration.
     * @return Data indices, plus the consumer index when validation is enabled.
     */
    static std::vector<std::string> buildIndices(const Config& cfg)
    {
        auto indices = cfg.dataIndices;
        if (!cfg.consumerStatusIndex.empty() && !cfg.consumerStatusId.empty())
        {
            indices.emplace_back(cfg.consumerStatusIndex);
        }
        return indices;
    }

private:
    /// `_shard_doc` is a PIT-synthesised metafield: mapped in every index of any PIT, which is what
    /// makes it safe for the probes that must also see the consumer index.
    static const nlohmann::json& consumerSort()
    {
        static const nlohmann::json sort = nlohmann::json::array(
            {nlohmann::json {{"_shard_doc", "asc"}}, nlohmann::json {{"_id", "asc"}}});
        return sort;
    }

    IIndexerQueryPort& m_port;
    Config m_config;
    PointInTime m_pit;
};

#endif // _PIT_SESSION_HPP
