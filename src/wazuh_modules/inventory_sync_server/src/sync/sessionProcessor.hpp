/*
 * Wazuh inventory sync server module
 * Copyright (C) 2015, Wazuh Inc.
 * August 4, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVSYNC_SYNC_SESSION_PROCESSOR_HPP
#define _INVSYNC_SYNC_SESSION_PROCESSOR_HPP

#include "common/metricNames.hpp"
#include "indexer/IIndexerConnectorSync.hpp"
#include "sync/fullSessionValidator.hpp"

#include <memory>
#include <string>
#include <utility>

namespace invsync::sync
{

    /**
     * @brief How a worker must schedule a session (design doc 03 §7, "group commit").
     *
     * BulkData sessions only STAGE into the worker's connector; their durability -- and their
     * response -- arrives with the batch flush. Immediate sessions execute their own I/O and
     * respond by themselves, so the worker must flush (and answer) the open batch BEFORE running
     * one: their effects would otherwise overtake bulk writes of an earlier session of the same
     * agent, breaking the per-agent FIFO the sharding exists to provide (delete-then-reindex,
     * checksum-after-delta).
     */
    enum class SessionKind
    {
        BulkData, ///< ModuleDelta x SyncData: staged, flushed with the batch.
        Immediate ///< Cleans, ModuleCheck, Metadata*/Group*: runs and answers on its own.
    };

    SessionKind classify(const ValidatedSession& session) noexcept;

    /// What a processing step decided. `staged == true` means bulk operations are sitting in the
    /// worker's connector and the (already `status`/`body`-filled) response must be delivered only
    /// after a successful flush.
    struct ProcessOutcome
    {
        int status {200};
        std::string body;
        bool staged {false};
    };

    /**
     * @brief Applies one validated session through a worker's indexer connector.
     *
     * Stateless except for the manager's cluster name; one instance is shared by every worker.
     * Per-DOCUMENT policy is skip-with-WARN (a bad document never fails the request); connector
     * exceptions are deliberately NOT caught here -- the worker maps them to 503/500 because the
     * mapping needs the connector's availability, and it owns the batch the failure poisons.
     */
    class SessionProcessor final
    {
    public:
        /// @param metrics OPTIONAL registry for the document counters (D18); null counts nothing.
        explicit SessionProcessor(std::string managerClusterName,
                                  const std::shared_ptr<wazuh::metrics::IManager>& metrics = nullptr)
            : m_managerClusterName {std::move(managerClusterName)}
        {
            if (metrics)
            {
                m_docsIndexed =
                    metrics->getOrCreateCounter(invsync::metrics::DOCS_INDEXED, "Documents staged/indexed", "count");
                m_docsSkipped = metrics->getOrCreateCounter(
                    invsync::metrics::DOCS_SKIPPED, "Documents skipped by per-document policy", "count");
                m_bytesIngested = metrics->getOrCreateCounter(
                    invsync::metrics::BYTES_INGESTED, "Serialized document bytes staged for indexing", "bytes");
            }
        }

        /// @brief Stages a ModuleDelta x SyncData session into the connector's bulk buffer.
        ProcessOutcome stageBulk(const ValidatedSession& session, indexer::IIndexerConnectorSync& connector) const;

        /// @brief Executes a self-contained session (Cleans / ModuleCheck / Metadata* / Group*),
        ///        including whatever flush IT needs; the caller must have cut the batch first.
        ProcessOutcome executeImmediate(const ValidatedSession& session,
                                        indexer::IIndexerConnectorSync& connector) const;

        /// @brief Deletes every document of @p agentId across AGENT_DELETION_SCOPE (wazuh-states-*,
        ///        wazuh-agent-config, wazuh-agent-stats; this cluster's scope) and flushes -- the
        ///        whole-agent deletion behind DELETE /agents (design doc 04). Immediate-style: the
        ///        caller must have cut the batch first. An index that does not exist counts as
        ///        success (404-as-success), same as the legacy delete. Documents written inside the
        ///        index refresh interval can survive it: see the note on the implementation.
        ProcessOutcome executeDeleteAgent(const std::string& agentId, indexer::IIndexerConnectorSync& connector) const;

    private:
        ProcessOutcome executeCleans(const ValidatedSession& session, indexer::IIndexerConnectorSync& connector) const;
        ProcessOutcome executeChecksum(const ValidatedSession& session,
                                       indexer::IIndexerConnectorSync& connector) const;
        ProcessOutcome executeMetadataOrGroups(const ValidatedSession& session,
                                               indexer::IIndexerConnectorSync& connector) const;

        std::string m_managerClusterName;
        // D18 counters, resolved once at construction (null when metrics are off, e.g. most tests).
        std::shared_ptr<wazuh::metrics::ICounter> m_docsIndexed;
        std::shared_ptr<wazuh::metrics::ICounter> m_docsSkipped;
        std::shared_ptr<wazuh::metrics::ICounter> m_bytesIngested;
    };

} // namespace invsync::sync

#endif // _INVSYNC_SYNC_SESSION_PROCESSOR_HPP
