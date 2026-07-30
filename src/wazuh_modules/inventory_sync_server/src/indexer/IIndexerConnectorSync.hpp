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

#ifndef _INVSYNC_INDEXER_I_INDEXER_CONNECTOR_SYNC_HPP
#define _INVSYNC_INDEXER_I_INDEXER_CONNECTOR_SYNC_HPP

namespace invsync::indexer
{

    /**
     * @brief Seam over the real IndexerConnectorSync.
     *
     * Deliberately NOT a shared base with IIndexerConnectorAsync, even though both currently expose
     * only isAvailable(). Two reasons:
     *
     *  - The library classes diverge completely past that point. Sync has
     *    bulkIndex/bulkDelete/flush/scopeLock/registerNotify/deleteByQuery/executeSearchQuery; async
     *    has index/indexDataStream/getQueueSize/getDroppedEvents. A common base would have to become
     *    the union of both (every implementer stubbing half) or force a downcast at every write site.
     *  - A common base invites a `std::vector<IIndexerConnector*>` or a single `bool indexerOk`, which
     *    is exactly what loses connector identity. The two keep independent round-robin cursors, so
     *    isAvailable() can legitimately disagree between them; the type system should force the caller
     *    to say which one it is asking.
     *
     * The interface exists at all so a unit test can substitute a fake: the real connector's
     * constructor throws on invalid configuration, which is the signal the startup gate is built on,
     * and a test needs to drive that outcome deterministically.
     */
    class IIndexerConnectorSync
    {
    public:
        virtual ~IIndexerConnectorSync() = default;

        /// @brief Whether at least one configured host currently answers healthy.
        virtual bool isAvailable() const = 0;
    };

} // namespace invsync::indexer

#endif // _INVSYNC_INDEXER_I_INDEXER_CONNECTOR_SYNC_HPP
