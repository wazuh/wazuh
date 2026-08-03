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

#ifndef _INVSYNC_INDEXER_CONNECTOR_ASYNC_ADAPTER_HPP
#define _INVSYNC_INDEXER_CONNECTOR_ASYNC_ADAPTER_HPP

#include "IIndexerConnectorAsync.hpp"

#include <indexerConnector.hpp>

#include <json.hpp>
#include <string_view>
#include <utility>

namespace invsync::indexer
{

    /**
     * @brief Wraps the real `IndexerConnectorAsync`, built on a shared session.
     *
     * Held alongside the sync connector rather than instead of it: the async variant is the
     * high-throughput, fire-and-forget write path for functionality still to come, while the sync one
     * carries the read/versioned-upsert API the ported `inventory_sync` logic needs. They are NOT
     * interchangeable -- notably `bulk_max_bytes` here is the same concept as the sync connector's
     * `max_bulk_size`, under a different key name, and each silently ignores the other's.
     *
     * Forwards the seam's whole surface -- `isAvailable()` plus the two fire-and-forget writes -- and
     * nothing more; see IIndexerConnectorAsync.hpp for what is deliberately left off. `m_inner` is held
     * by value in the member-init-list so a constructor failure throws out of THIS constructor, feeding
     * the facade's startup gate.
     *
     * Taking the session means this constructor performs NO health check and NO keystore read of its
     * own -- the reason adding this second connector costs no extra startup latency.
     */
    class IndexerConnectorAsyncAdapter final : public IIndexerConnectorAsync
    {
    public:
        IndexerConnectorAsyncAdapter(const nlohmann::json& config,
                                     const IndexerSession& session,
                                     LoggingContext logging)
            : m_inner {config, session, std::move(logging)}
        {
        }

        bool isAvailable() const override
        {
            return m_inner.isAvailable();
        }

        void index(std::string_view id, std::string_view index, std::string_view data) override
        {
            m_inner.index(id, index, data);
        }

        void indexDataStream(std::string_view index, std::string_view data) override
        {
            m_inner.indexDataStream(index, data);
        }

    private:
        IndexerConnectorAsync m_inner;
    };

} // namespace invsync::indexer

#endif // _INVSYNC_INDEXER_CONNECTOR_ASYNC_ADAPTER_HPP
