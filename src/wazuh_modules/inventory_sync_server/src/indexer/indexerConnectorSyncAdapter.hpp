/*
 * Wazuh inventory sync server module
 * Copyright (C) 2015, Wazuh Inc.
 * July 30, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVSYNC_INDEXER_CONNECTOR_SYNC_ADAPTER_HPP
#define _INVSYNC_INDEXER_CONNECTOR_SYNC_ADAPTER_HPP

#include "IIndexerConnectorSync.hpp"

#include <indexerConnector.hpp>

#include <json.hpp>
#include <utility>

namespace invsync::indexer
{

    /**
     * @brief Wraps the real `IndexerConnectorSync`, built on a shared session.
     *
     * This is the connector class the older `inventory_sync` module uses, and the whole point of this
     * module is to eventually replace it -- reusing the class means reusing its config keys
     * (`max_bulk_size`, `flush_interval_seconds`) and its staged-bulk/query API. Every method is a
     * 1:1 forward; `scopeLock`/`registerNotify`/`invokePendingCallbacks` stay behind the seam on
     * purpose (see IIndexerConnectorSync.hpp).
     *
     * `m_inner` is held by value in the member-init-list, so a constructor failure (`hosts` not
     * matching the session's, an unreasonable `max_retry_delay_seconds`) throws out of THIS
     * constructor too -- which is exactly the signal the facade's startup gate is built on.
     *
     * Taking the session means this constructor performs NO health check and NO keystore read of its
     * own: the session already did both, once, for every connector built from it.
     */
    class IndexerConnectorSyncAdapter final : public IIndexerConnectorSync
    {
    public:
        IndexerConnectorSyncAdapter(const nlohmann::json& config, const IndexerSession& session, LoggingContext logging)
            : m_inner {config, session, std::move(logging)}
        {
        }

        bool isAvailable() const override
        {
            return m_inner.isAvailable();
        }

        void bulkIndex(std::string_view id, std::string_view index, std::string_view data) override
        {
            m_inner.bulkIndex(id, index, data);
        }

        void
        bulkIndex(std::string_view id, std::string_view index, std::string_view data, std::string_view version) override
        {
            m_inner.bulkIndex(id, index, data, version);
        }

        void bulkDelete(std::string_view id, std::string_view index) override
        {
            m_inner.bulkDelete(id, index);
        }

        void
        deleteByQuery(const std::string& index, const std::string& agentId, const std::string& clusterName) override
        {
            m_inner.deleteByQuery(index, agentId, clusterName);
        }

        void executeUpdateByQuery(const std::vector<std::string>& indices, const nlohmann::json& updateQuery) override
        {
            m_inner.executeUpdateByQuery(indices, updateQuery);
        }

        nlohmann::json executeSearchQuery(const std::string& index, const nlohmann::json& searchQuery) override
        {
            return m_inner.executeSearchQuery(index, searchQuery);
        }

        void flush() override
        {
            m_inner.flush();
        }

    private:
        IndexerConnectorSync m_inner;
    };

} // namespace invsync::indexer

#endif // _INVSYNC_INDEXER_CONNECTOR_SYNC_ADAPTER_HPP
