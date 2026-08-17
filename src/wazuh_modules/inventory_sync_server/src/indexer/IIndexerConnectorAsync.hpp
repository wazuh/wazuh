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

#include <string_view>

namespace invsync::indexer
{

    /**
     * @brief Seam over the real IndexerConnectorAsync.
     *
     * Separate from IIndexerConnectorSync on purpose -- see the rationale in IIndexerConnectorSync.hpp.
     * The two are kept apart so that "which connector is this?" is answered by the type at every call
     * site; they are no longer structurally identical anyway, since only this one exposes the
     * fire-and-forget write path below.
     *
     * Deliberately a SUBSET of the library's async API: only what the endpoints need. Every virtual
     * added here also has to be implemented by the test fakes, so the seam grows on demand rather
     * than mirroring `IndexerConnectorAsync` wholesale. Not exposed (available on the real class if
     * ever needed): the `index()` overload taking an explicit document version, the id-less
     * `index(index, data)`, `getQueueSize()`, `getDroppedEvents()`, and the point-in-time/search API.
     *
     * @note This header is reachable from the endpoint headers, which the unit tests include. Keep it
     * free of `loggerHelper.h` and of anything that pulls it in: `Log::GLOBAL_LOG_FUNCTION` has hidden
     * visibility and a separately-linked test binary cannot resolve it.
     */
    class IIndexerConnectorAsync
    {
    public:
        virtual ~IIndexerConnectorAsync() = default;

        /// @brief Whether at least one configured host currently answers healthy.
        virtual bool isAvailable() const = 0;

        /**
         * @brief Queue a document for indexing. Fire-and-forget: this enqueues and returns.
         *
         * Parameter names mirror the library's (`indexerConnector.hpp`) so the 1:1 mapping is visible
         * at the adapter. Nothing here reports whether the write eventually succeeded -- that is the
         * nature of the async connector, and why `isAvailable()` is the only health signal available
         * to a caller.
         */
        virtual void index(std::string_view id, std::string_view index, std::string_view data) = 0;

        /// @brief Queue a document for a data stream. Fire-and-forget, same as index().
        virtual void indexDataStream(std::string_view index, std::string_view data) = 0;
    };

} // namespace invsync::indexer

#endif // _INVSYNC_INDEXER_I_INDEXER_CONNECTOR_ASYNC_HPP
