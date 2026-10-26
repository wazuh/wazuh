/*
 * Wazuh inventory sync server module
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVSYNC_INDEXER_I_INDEXER_CONNECTOR_SYNC_HPP
#define _INVSYNC_INDEXER_I_INDEXER_CONNECTOR_SYNC_HPP

#include <json.hpp>

#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace invsync::indexer
{

    /**
     * @brief A connector failure with its coarse cause attached, for metrics.
     *
     * The seam's own mirror of the real connector's exception category, so the pipeline can count
     * WHY group commits fail without depending on the connector library's exception type. The
     * adapter translates; fakes can throw it directly. Callers that do not care still catch it as
     * std::exception -- the cause changes what the operator should look at, never what the caller
     * does (the recovery is always re-staging).
     */
    class ConnectorError final : public std::runtime_error
    {
    public:
        enum class Cause
        {
            Other,              ///< Hard rejection or unexpected state.
            DocumentRejected,   ///< The indexer answered but rejected documents or confirmed nothing.
            RetryExhausted,     ///< The retry budget ran out on a retryable condition (429, transport).
            ConflictsExhausted, ///< A by-query's version-conflict allowance ran out against a competing
                                ///< writer: the documents are consistent and the caller may retry later.
            Unavailable         ///< The indexer could not take the work now (no usable node, throttled, queue full,
                                ///< transport, 5xx, closing): the caller answers 503 and the agent retries.
        };

        ConnectorError(const std::string& what, Cause cause)
            : std::runtime_error(what)
            , m_cause(cause)
        {
        }

        Cause cause() const noexcept
        {
            return m_cause;
        }

    private:
        Cause m_cause;
    };

    /**
     * @brief The outcome of one session of a group commit (I136).
     *
     * `ok` is true only when every operation the session staged was confirmed; otherwise `cause` is
     * the session's class (Unavailable wins over the permanent ones: a transient failure is the one a
     * re-POST can fix) and `reason` the first failure's text.
     */
    struct SessionOutcome
    {
        bool ok {true};
        ConnectorError::Cause cause {ConnectorError::Cause::Other};
        std::string reason;
    };

    /**
     * @brief Seam over the module's writer, IndexerClientSyncAdapter (built on indexer_client).
     *
     * The only connector seam left in the module (E7c): POST /stats, POST /config and the by-id half of a deletion
     * write through the Client's `agent-state` bucket directly, and keep no seam of their own.
     *
     * The seam exposes exactly what the sync pipeline needs and nothing more: `scopeLock`,
     * `registerNotify` and `invokePendingCallbacks` deliberately do NOT cross it. Each pipeline worker
     * owns its connector and calls `flush()` on its own thread, so the connector's cross-thread
     * notify/lock machinery -- the source of the legacy module's deadlock footguns -- never comes
     * into play behind this interface.
     *
     * Errors keep the real adapter's contract: methods throw (ConnectorError, or std::runtime_error when the
     * client is gone) and the caller maps that to an HTTP result. The constructor of the real connector throws on
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

        /**
         * @brief The same delete-by-query, for a whole-agent deletion: its caller (the Task Manager,
         *        through the deletion route) waits far longer than an agent's `/stateful` request, so
         *        the implementation may give it a longer budget (I145). Defaults to deleteByQuery().
         */
        virtual void
        deleteAgentByQuery(const std::string& index, const std::string& agentId, const std::string& clusterName)
        {
            deleteByQuery(index, agentId, clusterName);
        }

        /// @brief Immediate _update_by_query ("query" + "script") over the given indices.
        virtual void executeUpdateByQuery(const std::vector<std::string>& indices,
                                          const nlohmann::json& updateQuery) = 0;

        /// @brief Immediate _search against one index; returns the raw response body.
        virtual nlohmann::json executeSearchQuery(const std::string& index, const nlohmann::json& searchQuery) = 0;

        /// @brief Sends the staged bulk operations now, on the caller's thread. Throws on failure.
        virtual void flush() = 0;

        /// @brief Closes the range of the session staged since the previous call (I136). A session
        ///        that staged nothing is never closed. Default: nothing to track.
        virtual void endSession() {}

        /**
         * @brief Sends what is staged and answers one outcome per closed session, in endSession()
         *        order (I136). Never throws for an indexer failure: that is in the outcomes.
         *
         * The default keeps a connector without per-session results all-or-nothing, as flush() is:
         * every session succeeds or every one carries the flush's cause.
         */
        virtual std::vector<SessionOutcome> flushSessions(std::size_t sessions)
        {
            try
            {
                flush();
                return std::vector<SessionOutcome>(sessions);
            }
            catch (const ConnectorError& e)
            {
                return std::vector<SessionOutcome>(sessions, SessionOutcome {false, e.cause(), e.what()});
            }
            catch (const std::exception& e)
            {
                return std::vector<SessionOutcome>(sessions,
                                                   SessionOutcome {false, ConnectorError::Cause::Other, e.what()});
            }
        }

        /// @brief Drops what is staged and not yet sent, and the session ranges, after the caller
        ///        already answered those sessions (the poisoned-batch path). Default: nothing to drop.
        virtual void discard() {}
    };

} // namespace invsync::indexer

#endif // _INVSYNC_INDEXER_I_INDEXER_CONNECTOR_SYNC_HPP
