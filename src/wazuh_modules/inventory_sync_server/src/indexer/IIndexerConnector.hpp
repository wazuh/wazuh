/*
 * Wazuh inventory sync server module
 * Copyright (C) 2015, Wazuh Inc.
 * July 29, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVSYNC_INDEXER_I_INDEXER_CONNECTOR_HPP
#define _INVSYNC_INDEXER_I_INDEXER_CONNECTOR_HPP

namespace invsync::indexer
{

    /**
     * @brief Neutral seam over the real indexer connector.
     *
     * Deliberately minimal: today the facade only needs to know whether construction succeeded
     * (see IndexerConnectorAdapter) -- nothing calls isAvailable() from the startup gate itself,
     * since the gate is "did construction throw", not "is it currently reachable" (a construction
     * that succeeds with an unreachable host is not retried; availability becomes a per-request
     * concern once real sync logic lands, mirroring how the older inventory_sync module already
     * treats it).
     *
     * This exists as an interface (rather than using IndexerConnectorSync directly) for exactly one
     * reason: IndexerConnectorSync's own constructor does real, synchronous network I/O (a health
     * check per configured host), which a unit test must not have to wait on. The interface plus an
     * injectable factory (InventorySyncServerFacade::IndexerConnectorFactory) is what lets a test
     * substitute a fake that fails or succeeds instantly and deterministically.
     */
    class IIndexerConnector
    {
    public:
        virtual ~IIndexerConnector() = default;

        /// @brief Whether at least one configured host currently answers healthy.
        virtual bool isAvailable() const = 0;
    };

} // namespace invsync::indexer

#endif // _INVSYNC_INDEXER_I_INDEXER_CONNECTOR_HPP
