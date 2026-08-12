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

#include <json.hpp>

#include <string>
#include <string_view>
#include <vector>

namespace invsync::indexer
{

    /**
     * @brief Seam over the real IndexerConnectorSync.
     *
     * Deliberately NOT a shared base with IIndexerConnectorAsync, even though both expose
     * isAvailable(). Two reasons:
     *
     *  - The library classes diverge completely past that point. Sync has the staged-bulk/query API
     *    below; async has index/indexDataStream/getQueueSize/getDroppedEvents. A common base would
     *    have to become the union of both (every implementer stubbing half) or force a downcast at
     *    every write site.
     *  - A common base invites a `std::vector<IIndexerConnector*>` or a single `bool indexerOk`, which
     *    is exactly what loses connector identity. The two keep independent round-robin cursors, so
     *    isAvailable() can legitimately disagree between them; the type system should force the caller
     *    to say which one it is asking.
     *
     * The seam exposes exactly what the sync pipeline needs and nothing more: `scopeLock`,
     * `registerNotify` and `invokePendingCallbacks` deliberately do NOT cross it. Each pipeline worker
     * owns its connector and calls `flush()` on its own thread, so the connector's cross-thread
     * notify/lock machinery -- the source of the legacy module's deadlock footguns -- never comes
     * into play behind this interface.
     *
     * Errors keep the real connector's contract: methods throw (IndexerConnectorException and friends)
     * and the caller maps that to an HTTP result. The constructor of the real connector throws on
     * invalid configuration, which is the signal the startup gate is built on, and a test needs to
     * drive that outcome deterministically -- the original reason this interface exists.
     */
    class IIndexerConnectorSync
    {
    public:
        virtual ~IIndexerConnectorSync() = default;

        /// @brief Whether at least one configured host currently answers healthy.
        virtual bool isAvailable() const = 0;

        /// @brief Stages an index (upsert) operation into the connector's bulk buffer.
        virtual void bulkIndex(std::string_view id, std::string_view index, std::string_view data) = 0;

        /// @brief Same, with an explicit document version (external_gte versioning).
        virtual void
        bulkIndex(std::string_view id, std::string_view index, std::string_view data, std::string_view version) = 0;

        /// @brief Stages a delete operation into the connector's bulk buffer.
        virtual void bulkDelete(std::string_view id, std::string_view index) = 0;

        /// @brief Immediate delete-by-query of every document of an agent (optionally cluster-scoped).
        virtual void
        deleteByQuery(const std::string& index, const std::string& agentId, const std::string& clusterName) = 0;

        /// @brief Immediate _update_by_query ("query" + "script") over the given indices.
        virtual void executeUpdateByQuery(const std::vector<std::string>& indices,
                                          const nlohmann::json& updateQuery) = 0;

        /// @brief Immediate _search against one index; returns the raw response body.
        virtual nlohmann::json executeSearchQuery(const std::string& index, const nlohmann::json& searchQuery) = 0;

        /// @brief Sends the staged bulk operations now, on the caller's thread. Throws on failure.
        virtual void flush() = 0;
    };

} // namespace invsync::indexer

#endif // _INVSYNC_INDEXER_I_INDEXER_CONNECTOR_SYNC_HPP
