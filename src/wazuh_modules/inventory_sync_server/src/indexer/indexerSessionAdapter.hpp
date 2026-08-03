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

#ifndef _INVSYNC_INDEXER_SESSION_ADAPTER_HPP
#define _INVSYNC_INDEXER_SESSION_ADAPTER_HPP

#include "IIndexerSession.hpp"

#include <indexerConnector.hpp>

#include <json.hpp>
#include <utility>

namespace invsync::indexer
{

    /**
     * @brief Wraps the real `IndexerSession` behind IIndexerSession.
     *
     * `m_inner` is held BY VALUE in the member-init-list, so a construction failure (no hosts, a
     * missing CA file) throws out of THIS constructor -- which is exactly the signal the facade's
     * startup gate is built on.
     *
     * Constructing this is where the module pays, ONCE, for: validating `hosts`/`ssl.*`, merging CA
     * certificates, reading the keystore, and one synchronous round of `GET /_cat/health` per host.
     * Both connectors are then built from it and reuse all of that, which is what keeps adding the
     * async connector from doubling the module's startup cost.
     *
     * Exposes the real session through session() because the connector adapters need to pass it to
     * their own constructors. Nothing else reads it.
     */
    class IndexerSessionAdapter final : public IIndexerSession
    {
    public:
        IndexerSessionAdapter(const nlohmann::json& config, LoggingContext logging)
            : m_inner {config, std::move(logging)}
        {
        }

        /// The wrapped session, for handing to a connector's session-taking constructor.
        const IndexerSession& session() const
        {
            return m_inner;
        }

    private:
        IndexerSession m_inner;
    };

} // namespace invsync::indexer

#endif // _INVSYNC_INDEXER_SESSION_ADAPTER_HPP
