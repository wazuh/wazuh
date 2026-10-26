/*
 * Wazuh inventory sync server module
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "indexerClientSyncAdapter.hpp"

#include <algorithm>
#include <iterator>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace invsync::indexer
{
    namespace
    {
        constexpr std::uint64_t MIB {1024 * 1024};
        constexpr std::uint64_t QUOTA_FLOOR {64 * MIB};
        constexpr std::uint64_t QUOTA_HEADROOM {1 * MIB};
        constexpr std::size_t DEFAULT_BULK_MAX_BYTES {10 * MIB};
        constexpr std::chrono::milliseconds DEFAULT_RETRY_DURATION {15000};
        constexpr std::chrono::milliseconds DEFAULT_RETRY_CAP {15000};
        constexpr std::chrono::milliseconds STATEFUL_MIN {5000};
        constexpr std::chrono::milliseconds STATEFUL_MAX {18000};
        constexpr std::chrono::milliseconds STATEFUL_UNBOUNDED {18000};
        constexpr std::chrono::milliseconds DELETION_MAX {540000};
        constexpr std::chrono::milliseconds DELETION_UNBOUNDED {70000};
        constexpr std::chrono::milliseconds RETRY_MARGIN {3000};
        constexpr std::uint32_t DEFAULT_RETRY_ATTEMPTS {5};
        constexpr std::uint64_t KIB {1024};
        constexpr std::uint64_t AGENT_STATE_FLOOR {16 * KIB};
        constexpr std::uint64_t AGENT_STATE_SLACK {RESULT_RESERVE_BYTES + 4 * KIB}; // reserve + headroom (I149b)
        constexpr std::uint64_t DEFAULT_ASYNC_BULK_MAX_BYTES {4 * MIB};
        /// settleAbandoned()'s bound past the runtime's request timeout (as VD's abandon() and the sweeper's window).
        constexpr std::chrono::seconds ABANDON_MARGIN {5};
    } // namespace

    Budgets budgets(const inventory_sync_server_config_t& config)
    {
        Budgets result;
        const auto seconds = config.indexer_sync_max_retry_duration_seconds;
        // < 0: no opinion (the default); 0: the bound is disabled; > 0: the operator's value.
        const auto duration = seconds < 0 ? DEFAULT_RETRY_DURATION
                                          : std::chrono::milliseconds {static_cast<std::int64_t>(seconds) * 1000};
        if (seconds == 0)
        {
            result.stateful = STATEFUL_UNBOUNDED;
            result.deletion = DELETION_UNBOUNDED;
        }
        else
        {
            result.stateful = std::clamp(duration + RETRY_MARGIN, STATEFUL_MIN, STATEFUL_MAX);
            result.deletion = std::min(3 * duration + std::chrono::milliseconds {25000}, DELETION_MAX);
        }
        const auto retryBase = seconds == 0 ? DEFAULT_RETRY_DURATION : duration;
        result.statefulRetry = std::min(retryBase, result.stateful - RETRY_MARGIN);
        result.deletionRetry = std::min(retryBase, result.deletion - RETRY_MARGIN);
        return result;
    }

    indexer_client::BucketSpec inventoryBucketSpec(const inventory_sync_server_config_t& config,
                                                   std::uint64_t quotaBudget,
                                                   std::chrono::milliseconds blockTimeout,
                                                   std::string* warning)
    {
        indexer_client::BucketSpec spec;
        spec.name = INVENTORY_BUCKET;

        std::uint64_t bulkMax = config.indexer_sync_connector_max_bulk_size > 0
                                    ? static_cast<std::uint64_t>(config.indexer_sync_connector_max_bulk_size)
                                    : DEFAULT_BULK_MAX_BYTES;
        std::uint64_t quota = std::max(QUOTA_FLOOR, bulkMax + RESULT_RESERVE_BYTES + QUOTA_HEADROOM);
        quota = std::min(quota, quotaBudget);
        if (bulkMax + RESULT_RESERVE_BYTES + QUOTA_HEADROOM > quota)
        {
            const auto clipped = quota > RESULT_RESERVE_BYTES + QUOTA_HEADROOM
                                     ? quota - RESULT_RESERVE_BYTES - QUOTA_HEADROOM
                                     : quota / 2;
            if (warning)
            {
                *warning = "the indexer _bulk cap (" + std::to_string(bulkMax) +
                           " bytes) does not fit what the runtime's global quota leaves the inventory bucket after "
                           "agent-state (" +
                           std::to_string(quotaBudget) + " bytes); using " + std::to_string(clipped) + " bytes";
            }
            bulkMax = clipped;
        }
        spec.quotaBytes = static_cast<std::size_t>(quota);
        spec.bulk.maxBytes = static_cast<std::size_t>(bulkMax);

        const auto attempts = config.indexer_sync_max_retry_attempts;
        spec.retry.maxAttempts = attempts == 0  ? std::nullopt
                                 : attempts < 0 ? std::optional<std::uint32_t> {DEFAULT_RETRY_ATTEMPTS}
                                                : std::optional<std::uint32_t> {static_cast<std::uint32_t>(attempts)};
        spec.retry.maxDuration = budgets(config).statefulRetry;
        spec.retry.cap =
            config.indexer_sync_max_retry_delay_seconds > 0
                ? std::chrono::milliseconds {static_cast<std::int64_t>(config.indexer_sync_max_retry_delay_seconds) *
                                             1000}
                : DEFAULT_RETRY_CAP;
        spec.retry.base = std::min(spec.retry.base, spec.retry.cap);

        spec.overflow.kind = indexer_client::Overflow::Kind::Block;
        spec.overflow.blockTimeout = blockTimeout;
        spec.onConflict.kind = indexer_client::ConflictPolicy::Kind::Success;
        spec.onAmbiguous5xx = indexer_client::AmbiguousPolicy::Retry;
        spec.ordered = false;
        return spec;
    }

    indexer_client::BucketSpec agentStateBucketSpec(const inventory_sync_server_config_t& config,
                                                    std::uint64_t globalQuotaBytes,
                                                    std::string* warning)
    {
        indexer_client::BucketSpec spec;
        spec.name = AGENT_STATE_BUCKET;

        const std::uint64_t top = std::max(globalQuotaBytes / 4, std::min(AGENT_STATE_FLOOR, globalQuotaBytes / 2));
        std::uint64_t bulkMax = config.indexer_async_bulk_max_bytes > 0
                                    ? static_cast<std::uint64_t>(config.indexer_async_bulk_max_bytes)
                                    : DEFAULT_ASYNC_BULK_MAX_BYTES;
        const std::uint64_t requested = config.indexer_async_max_queue_bytes > 0
                                            ? static_cast<std::uint64_t>(config.indexer_async_max_queue_bytes)
                                            : globalQuotaBytes / 4;
        std::string notes;
        std::uint64_t quota = std::max({requested, bulkMax + AGENT_STATE_SLACK, AGENT_STATE_FLOOR});
        quota = std::min(quota, top);
        if (requested > quota)
        {
            notes = "the agent-state queue (" + std::to_string(requested) +
                    " bytes) is capped by the runtime's global quota (a quarter of it, or 16 KiB within half "
                    "of it): using " +
                    std::to_string(quota) + " bytes";
        }
        if (bulkMax + AGENT_STATE_SLACK > quota)
        {
            const auto clipped = quota > AGENT_STATE_SLACK ? quota - AGENT_STATE_SLACK : quota / 2;
            notes += std::string(notes.empty() ? "" : "; ") + "the agent-state _bulk cap (" + std::to_string(bulkMax) +
                     " bytes) does not fit its quota: using " + std::to_string(clipped) + " bytes";
            bulkMax = clipped;
        }
        if (warning)
        {
            *warning = notes;
        }
        spec.quotaBytes = static_cast<std::size_t>(quota);
        spec.bulk.maxBytes = static_cast<std::size_t>(bulkMax);

        spec.retry.maxAttempts = std::nullopt;
        spec.retry.maxDuration = std::nullopt;
        spec.retry.cap =
            config.indexer_async_max_retry_delay_seconds > 0
                ? std::chrono::milliseconds {static_cast<std::int64_t>(config.indexer_async_max_retry_delay_seconds) *
                                             1000}
                : DEFAULT_RETRY_CAP;
        spec.retry.base = std::min(spec.retry.base, spec.retry.cap);

        spec.overflow.kind = indexer_client::Overflow::Kind::Reject;
        spec.onConflict.kind = indexer_client::ConflictPolicy::Kind::Success;
        spec.onAmbiguous5xx = indexer_client::AmbiguousPolicy::Retry;
        spec.ordered = true;
        return spec;
    }

    ConnectorError::Cause translateCause(indexer_client::Cause cause)
    {
        using C = indexer_client::Cause;
        switch (cause)
        {
            case C::None: return ConnectorError::Cause::Other; // Not a failure; never asked for.
            case C::VersionConflict: return ConnectorError::Cause::ConflictsExhausted;
            case C::RetryExhausted: return ConnectorError::Cause::RetryExhausted;
            case C::TransportTimeout:
            case C::TransportConnect:
            case C::TransportTls:
            case C::Throttled:
            case C::Server5xx:
            case C::ItemRetryable:
            case C::Unavailable:
            case C::QueueFull:
            case C::SubmitTimeout:
            case C::WaitTimeout:
            case C::Shutdown:
            case C::ClientClosed:
            case C::Cancelled: return ConnectorError::Cause::Unavailable;
            case C::ItemPermanent:
            case C::Client4xx:
            case C::PayloadTooLarge:
            case C::GroupTooLarge: return ConnectorError::Cause::DocumentRejected;
            case C::Ambiguous:
            case C::Reentrancy:
            case C::PitExpired:
            case C::PitStaleGeneration:
            case C::NotFound:
            case C::InvalidConfig:
            case C::InvalidArgument:
            case C::InvalidState:
            case C::UsageError: return ConnectorError::Cause::Other;
        }
        return ConnectorError::Cause::Other; // LCOV_EXCL_LINE -- every enumerator is handled above
    }

    namespace
    {
        using Clock = std::chrono::steady_clock;
        using indexer_client::Deadline;

        /// Same filter as the deleteByQuery of the v1 connector (`indexerConnectorSyncImpl.hpp`; the v1 was removed
        /// in 5.x).
        bool isSafeIndexName(std::string_view index)
        {
            if (index.empty())
            {
                return false;
            }
            return std::all_of(index.begin(),
                               index.end(),
                               [](char c)
                               {
                                   return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                                          c == '-' || c == '_' || c == '.' || c == '*';
                               });
        }

        bool isTransient(ConnectorError::Cause cause)
        {
            return cause == ConnectorError::Cause::Unavailable || cause == ConnectorError::Cause::RetryExhausted ||
                   cause == ConnectorError::Cause::ConflictsExhausted;
        }

        /// Records a failure: the first one sets the reason; a transient cause wins over a permanent one.
        void markFailed(SessionOutcome& outcome, ConnectorError::Cause cause, const std::string& reason)
        {
            if (outcome.ok)
            {
                outcome.ok = false;
                outcome.cause = cause;
                outcome.reason = reason;
            }
            else if (!isTransient(outcome.cause) && isTransient(cause))
            {
                outcome.cause = cause;
            }
        }

        std::string reasonOf(indexer_client::Cause cause, const std::string& reason)
        {
            return reason.empty() ? std::string {indexer_client::toString(cause)} : reason;
        }

        /// (index, _id): an index name never holds a NUL, so the pair is unambiguous.
        std::string keyOf(std::string_view index, std::string_view id)
        {
            std::string key;
            key.reserve(index.size() + 1 + id.size());
            key.append(index);
            key.push_back('\0');
            key.append(id);
            return key;
        }
    } // namespace

    /**
     * States (I137b, I139, I142, I145, I145b):
     *  - open: a Group in Building, the chunk staging now (never cancelled: cancel(tag) does not see it).
     *  - pending: at most one committed chunk, with its GroupTicket; its Group was dropped right after commit().
     *  - abandoned: a pending chunk whose batch expired (deadline or closing): cancel(tag) was asked, not awaited; it
     *    stays the one pending chunk and keeps its keys in the barrier until its ticket is ready().
     * A batch (the sessions since the last flushSessions()/discard()) has a deadline from its first add; `m_generation`
     * tells a harvested chunk whether its sessions are still the current ones.
     */
    struct IndexerClientSyncAdapter::Impl
    {
        struct Session
        {
            SessionOutcome outcome;
            std::size_t unresolved {0}; ///< Ops added and not yet resolved.
            bool ignoring {false};      ///< Failed while staging: its remaining ops are dropped (I142).
        };

        struct OpenChunk
        {
            std::optional<indexer_client::Group> group;
            std::vector<std::size_t> sessions; ///< Session of each op, in add order.
            std::unordered_set<std::string> keys;
            std::size_t bytes {0};
        };

        struct PendingChunk
        {
            bool active {false};
            bool abandoned {false};
            std::uint64_t generation {0};
            indexer_client::GroupTicket ticket;
            std::vector<std::size_t> sessions;
            std::unordered_set<std::string> keys;
        };

        std::shared_ptr<indexer_client::IClient> client;
        std::shared_ptr<indexer_client::IWriter> writer;
        std::shared_ptr<indexer_client::IQuery> query;
        AdapterOptions options;
        std::shared_ptr<const std::atomic<bool>> closing;
        std::string tag;

        std::vector<Session> sessions;
        std::optional<std::size_t> current; ///< The session being staged, once it added (or tried) an op.
        std::optional<Deadline> deadline;   ///< The batch's, from its first add (I145).
        std::uint64_t generation {0};
        OpenChunk open;
        PendingChunk pending;

        bool isClosing() const
        {
            return closing && closing->load();
        }

        std::chrono::milliseconds slice() const
        {
            return std::max(options.blockSlice, std::chrono::milliseconds {1});
        }

        std::size_t currentSession()
        {
            if (!current)
            {
                sessions.emplace_back();
                current = sessions.size() - 1;
            }
            return *current;
        }

        /// Copies a resolved chunk's results to its sessions and drops its ticket (and so its reserves).
        void harvest(const indexer_client::Outcome<std::vector<indexer_client::OpResult>>& results)
        {
            if (pending.generation == generation)
            {
                for (std::size_t i = 0; i < pending.sessions.size(); ++i)
                {
                    auto& session = sessions[pending.sessions[i]];
                    if (session.unresolved > 0)
                    {
                        --session.unresolved;
                    }
                    if (!results.ok())
                    {
                        markFailed(
                            session.outcome, translateCause(results.cause), reasonOf(results.cause, results.reason));
                    }
                    else if (i >= results.value.size())
                    {
                        markFailed(session.outcome, ConnectorError::Cause::Other, "missing result for an operation");
                    }
                    else if (const auto& result = results.value[i]; result.status != indexer_client::Status::Ok)
                    {
                        markFailed(
                            session.outcome, translateCause(result.cause), reasonOf(result.cause, result.reason));
                    }
                }
            }
            pending = PendingChunk {};
        }

        /// The batch ran out of time or the module is closing (I145, I145b): cancel the unresolved chunk without
        /// waiting (it stays pending, abandoned), drop the open one uncommitted, fail every unresolved session.
        void expire(const char* reason)
        {
            if (pending.active)
            {
                if (pending.ticket.ready())
                {
                    harvest(pending.ticket.wait(Clock::now()));
                }
                else if (!pending.abandoned)
                {
                    try
                    {
                        static_cast<void>(writer->cancel(tag));
                    }
                    catch (...) // LCOV_EXCL_LINE -- the library answers through the ticket; never let it escape.
                    {
                    }
                    pending.abandoned = true;
                }
            }

            // The open chunk is dropped uncommitted: its ops were never sent, so their sessions fail (a 200 here
            // would claim data the indexer never got).
            for (const auto index : open.sessions)
            {
                if (sessions[index].unresolved > 0)
                {
                    --sessions[index].unresolved;
                }
                markFailed(sessions[index].outcome, ConnectorError::Cause::Unavailable, reason);
            }
            open = OpenChunk {}; // Without commit: the Group is abandoned and its reservation released.

            for (std::size_t i = 0; i < sessions.size(); ++i)
            {
                const bool staging = current && *current == i;
                if (sessions[i].unresolved > 0 || staging)
                {
                    markFailed(sessions[i].outcome, ConnectorError::Cause::Unavailable, reason);
                }
                if (staging)
                {
                    sessions[i].ignoring = true;
                }
            }
            deadline.reset();
        }

        /**
         * @brief Waits for the pending chunk, in slices that watch `closing` and the batch deadline.
         *
         * @param until How long the waiter may wait: the batch deadline for a write, the call's for a query.
         * @param batchWait True for a write: the batch's expiry ends the wait. A query keeps waiting for the abandoned
         *                  chunk until its own deadline, which alone fails it without touching the batch.
         * @return true once nothing is pending.
         */
        bool settlePending(Deadline until, bool batchWait)
        {
            while (pending.active)
            {
                if (pending.ticket.ready())
                {
                    harvest(pending.ticket.wait(Clock::now()));
                    return true;
                }
                if (isClosing())
                {
                    expire("closing");
                    return false;
                }
                const auto now = Clock::now();
                if (deadline && now >= *deadline)
                {
                    expire("deadline");
                    if (batchWait)
                    {
                        return false;
                    }
                }
                if (now >= until)
                {
                    return false;
                }
                auto next = std::min<Deadline>(now + slice(), until);
                if (deadline)
                {
                    next = std::min(next, *deadline);
                }
                static_cast<void>(pending.ticket.wait(next));
            }
            return true;
        }

        /// Commits the open chunk once the previous one is resolved; the Group is dropped right after commit().
        bool commitOpen(Deadline until, bool batchWait)
        {
            if (!open.group || open.sessions.empty())
            {
                return true;
            }
            if (!settlePending(until, batchWait))
            {
                return false;
            }
            if (isClosing())
            {
                expire("closing");
                return false;
            }
            if (!open.group || open.sessions.empty())
            {
                return true; // The batch expired while waiting (a query's barrier keeps waiting): the open chunk is
                             // gone.
            }
            pending.ticket = open.group->commit();
            pending.active = true;
            pending.abandoned = false;
            pending.generation = generation;
            pending.sessions = std::move(open.sessions);
            pending.keys = std::move(open.keys);
            open = OpenChunk {};
            return true;
        }

        void stage(indexer_client::Op::Kind kind,
                   std::string_view id,
                   std::string_view index,
                   std::string_view data,
                   std::string_view version)
        {
            const auto session = currentSession();
            if (sessions[session].ignoring)
            {
                return;
            }
            if (isClosing())
            {
                expire("closing");
                return;
            }
            const auto now = Clock::now();
            if (!deadline)
            {
                deadline = now + options.budgets.stateful;
            }
            else if (now >= *deadline)
            {
                expire("deadline");
                return;
            }

            // I139: two ops of one key are never unresolved at once.
            auto key = keyOf(index, id);
            if (open.keys.count(key) > 0)
            {
                if (!commitOpen(*deadline, true) || !settlePending(*deadline, true))
                {
                    return;
                }
            }
            else if (pending.active && pending.keys.count(key) > 0 && !settlePending(*deadline, true))
            {
                return;
            }

            const auto makeOp = [&]
            {
                indexer_client::Op op;
                op.kind = kind;
                op.index = std::string {index};
                op.id = std::string {id};
                op.body = std::string {data};
                op.version = std::string {version};
                op.tag = tag;
                return op;
            };

            auto op = makeOp();
            // What the library will charge for it, never less (I137b; indexer_client/chunking.hpp, D88).
            const auto estimate = indexer_client::estimateCharge(op, RESULT_RESERVE_BYTES);
            if (!open.sessions.empty() && open.bytes + estimate > options.capBytes && !commitOpen(*deadline, true))
            {
                return;
            }
            if (!open.group)
            {
                open.group.emplace(writer->group());
            }
            auto cause = open.group->add(std::move(op));
            if (cause == indexer_client::Cause::GroupTooLarge && !open.sessions.empty())
            {
                if (!commitOpen(*deadline, true))
                {
                    return;
                }
                open.group.emplace(writer->group());
                cause = open.group->add(makeOp());
            }
            if (cause != indexer_client::Cause::None)
            {
                markFailed(
                    sessions[session].outcome, translateCause(cause), reasonOf(cause, open.group->lastAddReason()));
                sessions[session].ignoring = true;
                return;
            }

            open.sessions.push_back(session);
            open.keys.insert(std::move(key));
            open.bytes += estimate;
            ++sessions[session].unresolved;
        }

        void reset()
        {
            sessions.clear();
            current.reset();
            deadline.reset();
            ++generation;
        }

        void discard()
        {
            open = OpenChunk {};
            if (pending.active)
            {
                if (pending.ticket.ready())
                {
                    pending = PendingChunk {};
                }
                else if (!pending.abandoned)
                {
                    try
                    {
                        static_cast<void>(writer->cancel(tag));
                    }
                    catch (...) // LCOV_EXCL_LINE -- the library answers through the ticket; never let it escape.
                    {
                    }
                    pending.abandoned = true;
                }
            }
            reset();
        }

        bool runtimeClosing() const
        {
            return options.runtime.shutdownDeadline().has_value();
        }

        /// One request at most (a cancelled op is never sent again, I80): the runtime's request timeout + margin.
        Clock::duration abandonBound() const
        {
            Clock::duration timeout = options.runtime.snapshot().requestTimeout;
            if (timeout <= Clock::duration::zero())
            {
                timeout = indexer_client::RuntimeConfig {}.requestTimeout;
            }
            return timeout + ABANDON_MARGIN;
        }

        AbandonedWrite settleAbandoned()
        {
            if (!pending.active)
            {
                return AbandonedWrite::Settled;
            }
            const auto bound = Clock::now() + abandonBound();
            while (!pending.ticket.ready())
            {
                if (isClosing() || runtimeClosing())
                {
                    return AbandonedWrite::Closing;
                }
                const auto now = Clock::now();
                if (now >= bound)
                {
                    return AbandonedWrite::TimedOut;
                }
                static_cast<void>(pending.ticket.wait(std::min<Deadline>(bound, now + slice())));
            }
            harvest(pending.ticket.wait(Clock::now()));
            return AbandonedWrite::Settled;
        }

        /// D49: every pending write is resolved before a query goes out, within the call's own deadline.
        void barrier(Deadline until, const char* what)
        {
            if (isClosing())
            {
                expire("closing");
                throw ConnectorError(std::string {what} + ": the module is closing",
                                     ConnectorError::Cause::Unavailable);
            }
            if (!commitOpen(until, false) || !settlePending(until, false))
            {
                throw ConnectorError(std::string {what} + ": pending writes did not resolve in time",
                                     ConnectorError::Cause::Unavailable);
            }
        }

        indexer_client::QueryOptions queryOptions(std::chrono::milliseconds maxDuration) const
        {
            indexer_client::QueryOptions result;
            result.retry = options.queryRetry;
            result.retry.maxDuration = maxDuration;
            result.pageDeadline = options.pageDeadline;
            return result;
        }

        template<class T>
        static void throwIfFailed(const indexer_client::Outcome<T>& outcome, const char* what)
        {
            if (!outcome.ok())
            {
                throw ConnectorError(std::string {what} + " failed: " + reasonOf(outcome.cause, outcome.reason),
                                     translateCause(outcome.cause));
            }
        }

        void runDeleteByQuery(const std::string& index,
                              const std::string& agentId,
                              const std::string& clusterName,
                              std::chrono::milliseconds budget,
                              std::chrono::milliseconds maxDuration)
        {
            const auto until = Clock::now() + budget;
            barrier(until, "deleteByQuery");

            nlohmann::json agentClause;
            agentClause["terms"]["wazuh.agent.id"] = nlohmann::json::array({agentId});
            nlohmann::json body;
            if (clusterName.empty())
            {
                body["query"]["bool"]["filter"] = std::move(agentClause);
            }
            else
            {
                nlohmann::json clusterClause;
                clusterClause["term"]["wazuh.cluster.name"] = clusterName;
                body["query"]["bool"]["filter"] =
                    nlohmann::json::array({std::move(agentClause), std::move(clusterClause)});
            }

            indexer_client::DbqOptions dbq;
            dbq.proceedOnConflicts = true;
            throwIfFailed(query->deleteByQuery({index}, body, dbq, queryOptions(maxDuration), until), "deleteByQuery");
        }

        std::vector<SessionOutcome> flushSessions(std::size_t count)
        {
            if (isClosing())
            {
                expire("closing");
            }
            else if (deadline && Clock::now() >= *deadline)
            {
                expire("deadline"); // Never commit a chunk whose batch already ran out of time.
            }
            else if (deadline)
            {
                if (commitOpen(*deadline, true))
                {
                    settlePending(*deadline, true);
                }
            }
            else if (pending.active && pending.ticket.ready())
            {
                harvest(pending.ticket.wait(Clock::now()));
            }

            std::vector<SessionOutcome> outcomes;
            outcomes.reserve(count);
            for (auto& session : sessions)
            {
                if (session.outcome.ok && session.unresolved > 0) // LCOV_EXCL_LINE -- expire() already failed it.
                {
                    markFailed(session.outcome, ConnectorError::Cause::Unavailable, "unresolved");
                }
                outcomes.push_back(std::move(session.outcome));
            }
            // A caller that counts sessions differently gets its count, and every session fails: the mapping of
            // results to sessions is not trustworthy, so no success can be proved.
            if (outcomes.size() != count)
            {
                outcomes.assign(count,
                                SessionOutcome {false, ConnectorError::Cause::Other, "session bookkeeping mismatch"});
            }
            reset();
            return outcomes;
        }
    };

    IndexerClientSyncAdapter::IndexerClientSyncAdapter(std::shared_ptr<indexer_client::IClient> client,
                                                       AdapterOptions options,
                                                       std::shared_ptr<const std::atomic<bool>> closing,
                                                       std::string tag)
        : m_impl(std::make_unique<Impl>())
    {
        if (!client)
        {
            throw std::runtime_error("IndexerClientSyncAdapter: no indexer client");
        }
        m_impl->writer = client->writer(INVENTORY_BUCKET);
        m_impl->query = client->query();
        if (!m_impl->writer || !m_impl->query)
        {
            throw std::runtime_error(std::string {"IndexerClientSyncAdapter: the indexer client has no "} +
                                     (m_impl->writer ? "query interface" : "writer for bucket 'inventory'"));
        }
        m_impl->client = std::move(client);
        m_impl->options = std::move(options);
        m_impl->closing = std::move(closing);
        m_impl->tag = std::move(tag);
    }

    IndexerClientSyncAdapter::~IndexerClientSyncAdapter()
    {
        try
        {
            m_impl->discard();
        }
        catch (...) // LCOV_EXCL_LINE -- a destructor never throws.
        {
        }
    }

    bool IndexerClientSyncAdapter::isAvailable() const
    {
        return m_impl->client->health().anyUsable();
    }

    void IndexerClientSyncAdapter::bulkIndex(std::string_view id, std::string_view index, std::string_view data)
    {
        m_impl->stage(indexer_client::Op::Kind::Index, id, index, data, {});
    }

    void IndexerClientSyncAdapter::bulkIndex(std::string_view id,
                                             std::string_view index,
                                             std::string_view data,
                                             std::string_view version)
    {
        m_impl->stage(indexer_client::Op::Kind::IndexVersionedScript, id, index, data, version);
    }

    void IndexerClientSyncAdapter::bulkDelete(std::string_view id, std::string_view index)
    {
        m_impl->stage(indexer_client::Op::Kind::Delete, id, index, {}, {});
    }

    void IndexerClientSyncAdapter::deleteByQuery(const std::string& index,
                                                 const std::string& agentId,
                                                 const std::string& clusterName)
    {
        const auto& budgets = m_impl->options.budgets;
        m_impl->runDeleteByQuery(index, agentId, clusterName, budgets.stateful, budgets.statefulRetry);
    }

    void IndexerClientSyncAdapter::deleteAgentByQuery(const std::string& index,
                                                      const std::string& agentId,
                                                      const std::string& clusterName)
    {
        const auto& budgets = m_impl->options.budgets;
        m_impl->runDeleteByQuery(index, agentId, clusterName, budgets.deletion, budgets.deletionRetry);
    }

    void IndexerClientSyncAdapter::executeUpdateByQuery(const std::vector<std::string>& indices,
                                                        const nlohmann::json& updateQuery)
    {
        const auto until = Clock::now() + m_impl->options.budgets.stateful;
        m_impl->barrier(until, "updateByQuery");

        // As the v1: an unsafe name is skipped and nothing left is a no-op success.
        std::vector<std::string> safe;
        safe.reserve(indices.size());
        std::copy_if(indices.begin(), indices.end(), std::back_inserter(safe), isSafeIndexName);
        if (safe.empty())
        {
            return;
        }
        Impl::throwIfFailed(
            m_impl->query->updateByQuery(
                std::move(safe), updateQuery, m_impl->queryOptions(m_impl->options.budgets.statefulRetry), until),
            "updateByQuery");
    }

    nlohmann::json IndexerClientSyncAdapter::executeSearchQuery(const std::string& index,
                                                                const nlohmann::json& searchQuery)
    {
        const auto until = Clock::now() + m_impl->options.budgets.stateful;
        m_impl->barrier(until, "search");
        auto outcome = m_impl->query->search(
            index, searchQuery, m_impl->queryOptions(m_impl->options.budgets.statefulRetry), until);
        Impl::throwIfFailed(outcome, "search");
        return std::move(outcome.value);
    }

    void IndexerClientSyncAdapter::flush()
    {
        if (m_impl->sessions.empty())
        {
            return;
        }
        const auto outcomes = m_impl->flushSessions(m_impl->sessions.size());
        std::optional<SessionOutcome> failure;
        for (const auto& outcome : outcomes)
        {
            if (!outcome.ok)
            {
                if (!failure)
                {
                    failure = outcome;
                }
                else
                {
                    markFailed(*failure, outcome.cause, outcome.reason);
                }
            }
        }
        if (failure)
        {
            throw ConnectorError(failure->reason, failure->cause);
        }
    }

    void IndexerClientSyncAdapter::endSession()
    {
        m_impl->current.reset();
    }

    std::vector<SessionOutcome> IndexerClientSyncAdapter::flushSessions(std::size_t sessions)
    {
        return m_impl->flushSessions(sessions);
    }

    void IndexerClientSyncAdapter::discard()
    {
        m_impl->discard();
    }

    AbandonedWrite IndexerClientSyncAdapter::settleAbandoned()
    {
        return m_impl->settleAbandoned();
    }

    bool IndexerClientSyncAdapter::holdsAbandonedWrite()
    {
        const auto& pending = m_impl->pending;
        return pending.active && pending.abandoned && !pending.ticket.ready() && !m_impl->isClosing();
    }

} // namespace invsync::indexer
