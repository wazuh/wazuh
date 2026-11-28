/*
 * Wazuh inventory sync server module
 * Copyright (C) Wazuh Inc.
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
#include "indexer/agentDeleteSweeper.hpp"
#include "sync/fullSessionValidator.hpp"

#include "indexer_client/client.hpp"

#include <atomic>
#include <chrono>
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

    /**
     * @brief The by-id half of a whole-agent deletion, handed to every worker.
     *
     * Default-constructed (`byId == false`) the deletion runs only its by-query half -- what unit tests built on the
     * sync fakes alone exercise. In production the facade sets `byId` and the weak handles: an expired `agentState`
     * then fails the deletion 503 (the module is stopping), never skips the half.
     */
    struct AgentDeletionDeps
    {
        bool byId {false};
        std::weak_ptr<indexer_client::IWriter> agentState;  ///< The `agent-state` bucket's writer.
        std::weak_ptr<indexer::AgentDeleteSweeper> sweeper; ///< note()d once the by-id deletes succeeded.
        std::shared_ptr<const std::atomic<bool>> closing;   ///< The module's closing flag; null = never.
        std::chrono::milliseconds budget {70000};           ///< Budgets::deletion: by-query + by-id wait.
        std::chrono::milliseconds slice {250};              ///< Granularity of the by-id wait (closing, ready()).
    };

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
        /// Indexer search page size while draining a session.
        static constexpr std::size_t DEFAULT_QUERY_BATCH_SIZE {1000};

    public:
        /// @param metrics OPTIONAL registry for the document counters (D18); null counts nothing.
        /// queryBatchSize follows the module's <=0 -> default convention, so modulesd can pass the
        /// internal option through unconditionally.
        explicit SessionProcessor(std::string managerClusterName,
                                  const std::shared_ptr<wazuh::metrics::IManager>& metrics = nullptr,
                                  int queryBatchSize = 0)
            : m_managerClusterName {std::move(managerClusterName)}
            , m_queryBatchSize {queryBatchSize > 0 ? static_cast<std::size_t>(queryBatchSize)
                                                   : DEFAULT_QUERY_BATCH_SIZE}
        {
            if (metrics)
            {
                m_docsIndexed =
                    metrics->getOrCreateCounter(invsync::metrics::DOCS_INDEXED,
                                                "Documents staged into bulk operations (upserts and deletes; by-query "
                                                "deletes/updates are not counted)",
                                                "count");
                m_docsSkipped = metrics->getOrCreateCounter(
                    invsync::metrics::DOCS_SKIPPED,
                    "Documents skipped by the per-document allowlist policy (bulk path only)",
                    "count");
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

        /**
         * @brief The whole-agent deletion behind POST /_internal/agents/delete (design doc 04), run on the agent's
         *        shard worker so two deletions of one agent never overlap. Immediate-style: the caller must
         *        have cut and answered the batch first, and computes `until` (= now + deletion.budget) right after.
         *
         * With `deletion.byId`: cancel(agent) on `agent-state` (drops the agent's pending /stats and /config writes),
         * then ONE Group with the deletes of AGENT_DELETION_SCOPE_BY_ID tagged with the agent and committed at once.
         *Then the by-query over AGENT_DELETION_SCOPE_BY_QUERY (this cluster's `wazuh-states-*`) through
         * deleteAgentByQuery, which bounds itself. Then the Group's ticket is waited until `until`, in slices
         * that watch `closing` and ready(). A by-id result Failed(ItemPermanent) with 404 index_not_found_exception
         * counts as success, like a missing index on the by-query half. On a refusal, a failure, the
         * deadline or closing it cancel(agent)s without waiting and throws ConnectorError with the failure class of its
         * cause; on success it note()s the agent to the sweeper. State documents written inside the index refresh
         * interval can survive the by-query: see the note on the implementation.
         */
        ProcessOutcome executeDeleteAgent(const std::string& agentId,
                                          indexer::IIndexerConnectorSync& connector,
                                          const AgentDeletionDeps& deletion = {},
                                          std::chrono::steady_clock::time_point until = {}) const;

    private:
        ProcessOutcome executeCleans(const ValidatedSession& session, indexer::IIndexerConnectorSync& connector) const;
        ProcessOutcome executeChecksum(const ValidatedSession& session,
                                       indexer::IIndexerConnectorSync& connector) const;
        ProcessOutcome executeMetadataOrGroups(const ValidatedSession& session,
                                               indexer::IIndexerConnectorSync& connector) const;

        std::string m_managerClusterName;

        std::size_t m_queryBatchSize {DEFAULT_QUERY_BATCH_SIZE};
        // D18 counters, resolved once at construction (null when metrics are off, e.g. most tests).
        std::shared_ptr<wazuh::metrics::ICounter> m_docsIndexed;
        std::shared_ptr<wazuh::metrics::ICounter> m_docsSkipped;
        std::shared_ptr<wazuh::metrics::ICounter> m_bytesIngested;
    };

} // namespace invsync::sync

#endif // _INVSYNC_SYNC_SESSION_PROCESSOR_HPP
