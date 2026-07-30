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

#ifndef _INVSYNC_INDEXER_I_INDEXER_CONNECTOR_ASYNC_HPP
#define _INVSYNC_INDEXER_I_INDEXER_CONNECTOR_ASYNC_HPP

namespace invsync::indexer

{

    /**
     * @brief Seam over the real IndexerConnectorAsync.
     *
     * Separate from IIndexerConnectorSync on purpose -- see the rationale in IIndexerConnectorSync.hpp.
     * The two are structurally identical today and are still kept apart so that "which connector is
     * this?" is answered by the type at every call site.
     */
    class IIndexerConnectorAsync
    {
    public:
        virtual ~IIndexerConnectorAsync() = default;

        /// @brief Whether at least one configured host currently answers healthy.
        virtual bool isAvailable() const = 0;
    };

} // namespace invsync::indexer

#endif // _INVSYNC_INDEXER_I_INDEXER_CONNECTOR_ASYNC_HPP
