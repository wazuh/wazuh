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

#include "contentIndexerAdapters.hpp"
#include "indexerConnector.hpp"
#include "loggerHelper.h"
#include "sharedDefs.hpp"

#include <stdexcept>
#include <utility>

// LCOV_EXCL_START - thin forwarding shims onto a live indexer; everything above IContentIndexer is
// unit-tested through fakes, and these are exercised end to end by the hosts' integration suites.
namespace
{
    PointInTime toPointInTime(const content_manager::ContentPit& pit)
    {
        return PointInTime {pit.id, pit.creationTime, pit.keepAlive};
    }

    content_manager::ContentPit toContentPit(const PointInTime& pit)
    {
        return content_manager::ContentPit {pit.getPitId(), pit.getCreationTime(), pit.getKeepAlive()};
    }

    /// Forwards to a connector of either kind. Holds it shared: the host may drop its own reference
    /// before the last registration using it is gone.
    template<typename TConnector>
    class ConnectorIndexerBase : public content_manager::IContentIndexer
    {
    public:
        explicit ConnectorIndexerBase(std::shared_ptr<TConnector> connector)
            : m_connector(std::move(connector))
        {
            if (!m_connector)
            {
                throw std::invalid_argument {"The content manager needs the host's indexer connector; got null"};
            }
        }

        content_manager::ContentPit
        openPit(const std::vector<std::string>& indices, std::string_view keepAlive, bool expandWildcards) override
        {
            return toContentPit(m_connector->createPointInTime(indices, keepAlive, expandWildcards));
        }

        void closePit(const content_manager::ContentPit& pit) noexcept override
        {
            try
            {
                m_connector->deletePointInTime(toPointInTime(pit));
            }
            catch (const std::exception& e)
            {
                // A leaked PIT expires on its own after keepAlive; never let this abort a cycle.
                logDebug2(WM_CONTENTUPDATER, "Failed to delete PIT: %s", e.what());
            }
            catch (...)
            {
                logDebug2(WM_CONTENTUPDATER, "Failed to delete PIT.");
            }
        }

        nlohmann::json search(const content_manager::ContentPit& pit,
                              std::size_t size,
                              const nlohmann::json& query,
                              const nlohmann::json& sort,
                              const std::optional<nlohmann::json>& searchAfter,
                              const std::optional<nlohmann::json>& source,
                              const std::optional<nlohmann::json>& slice) override
        {
            return m_connector->search(toPointInTime(pit), size, query, sort, searchAfter, source, slice);
        }

    protected:
        std::shared_ptr<TConnector> m_connector;
    };

    class SyncConnectorIndexer final : public ConnectorIndexerBase<IndexerConnectorSync>
    {
    public:
        using ConnectorIndexerBase::ConnectorIndexerBase;

        nlohmann::json searchIndex(std::string_view index,
                                   std::size_t size,
                                   const nlohmann::json& query,
                                   const std::optional<nlohmann::json>& source) override
        {
            nlohmann::json body {{"size", size}, {"query", query}};
            if (source.has_value())
            {
                body["_source"] = *source;
            }

            // The sync connector returns the whole response; the contract is the hits object, which
            // is what the async connector already returns.
            auto response = m_connector->executeSearchQuery(std::string {index}, body);
            if (response.is_object() && response.contains("hits"))
            {
                return std::move(response.at("hits"));
            }
            return nlohmann::json::object();
        }
    };

    class AsyncConnectorIndexer final : public ConnectorIndexerBase<IndexerConnectorAsync>
    {
    public:
        using ConnectorIndexerBase::ConnectorIndexerBase;

        nlohmann::json searchIndex(std::string_view index,
                                   std::size_t size,
                                   const nlohmann::json& query,
                                   const std::optional<nlohmann::json>& source) override
        {
            return m_connector->search(index, size, query, source);
        }
    };
} // namespace

namespace content_manager
{
    std::shared_ptr<IContentIndexer> makeContentIndexer(std::shared_ptr<IndexerConnectorSync> connector)
    {
        return std::make_shared<SyncConnectorIndexer>(std::move(connector));
    }

    std::shared_ptr<IContentIndexer> makeContentIndexer(std::shared_ptr<IndexerConnectorAsync> connector)
    {
        return std::make_shared<AsyncConnectorIndexer>(std::move(connector));
    }
} // namespace content_manager
// LCOV_EXCL_STOP
