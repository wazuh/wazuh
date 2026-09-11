/*
 * Wazuh content manager
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INDEXER_CONNECTOR_QUERY_PORT_HPP
#define _INDEXER_CONNECTOR_QUERY_PORT_HPP

#include "indexerQueryPort.hpp"
#include "loggerHelper.h"
#include "sharedDefs.hpp"
#include <memory>
#include <utility>

/**
 * @brief The one production implementation of @ref IIndexerQueryPort, over `IndexerConnectorSync`.
 *
 * Every connector it builds comes from a caller-supplied @ref IndexerSession, so a process holding
 * several registrations against the same indexer pays for one health-monitor thread and one startup
 * health-check round in total rather than one per connector. `flush_interval_seconds` is forced to
 * 0 because this connector only ever reads: there is nothing for a background flush thread to do.
 *
 * This is the only file in the module that still needs `LCOV_EXCL`: it is a thin forwarding shim
 * onto a live indexer, and everything above it is unit-tested through the interface.
 */
// LCOV_EXCL_START
class IndexerConnectorQueryPort final : public IIndexerQueryPort
{
public:
    /**
     * @brief Build a port over a shared session.
     *
     * @param config Indexer configuration. Its `hosts` list must equal the session's.
     * @param session Session whose health monitor and credentials every connector reuses.
     * @throws IndexerConnectorException if the configuration is rejected by the connector.
     */
    IndexerConnectorQueryPort(nlohmann::json config, std::shared_ptr<IndexerSession> session)
        : m_config {std::move(config)}
        , m_session {std::move(session)}
        , m_connector {makeConnector(m_config, *m_session)}
    {
    }

    PointInTime
    openPit(const std::vector<std::string>& indices, std::string_view keepAlive, bool expandWildcards) override
    {
        return m_connector->createPointInTime(indices, keepAlive, expandWildcards);
    }

    void closePit(const PointInTime& pit) noexcept override
    {
        try
        {
            m_connector->deletePointInTime(pit);
        }
        catch (const std::exception& e)
        {
            // A leaked PIT expires on its own after keepAlive; never let this abort a cycle.
            logDebug2(WM_CONTENTUPDATER, "Failed to delete PIT: %s", e.what());
        }
    }

    nlohmann::json search(const PointInTime& pit,
                          std::size_t size,
                          const nlohmann::json& query,
                          const nlohmann::json& sort,
                          const std::optional<nlohmann::json>& searchAfter,
                          const std::optional<nlohmann::json>& source,
                          const std::optional<nlohmann::json>& slice) override
    {
        return m_connector->search(pit, size, query, sort, searchAfter, source, slice);
    }

    nlohmann::json searchIndex(std::string_view index, const nlohmann::json& body) override
    {
        return m_connector->executeSearchQuery(std::string {index}, body);
    }

    std::unique_ptr<IIndexerQueryPort> clone() const override
    {
        return std::make_unique<IndexerConnectorQueryPort>(m_config, m_session);
    }

private:
    static std::unique_ptr<IndexerConnectorSync> makeConnector(const nlohmann::json& config,
                                                               const IndexerSession& session)
    {
        auto readOnlyConfig = config;
        readOnlyConfig["flush_interval_seconds"] = 0;
        return std::make_unique<IndexerConnectorSync>(
            readOnlyConfig, session, LoggingContext {WM_CONTENTUPDATER, {}});
    }

    nlohmann::json m_config;
    /// Held, not merely borrowed: clone() builds further connectors from it after construction.
    std::shared_ptr<IndexerSession> m_session;
    std::unique_ptr<IndexerConnectorSync> m_connector;
};
// LCOV_EXCL_STOP

#endif // _INDEXER_CONNECTOR_QUERY_PORT_HPP
