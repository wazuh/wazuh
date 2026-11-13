/*
 * Wazuh indexer client
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _INDEXER_CLIENT_RUNTIME_INTERNAL_HPP
#define _INDEXER_CLIENT_RUNTIME_INTERNAL_HPP

// Internal glue between the runtime (runtime.cpp), the client handles (client.cpp) and the tickets (tickets.cpp).
// asio stays inside runtime.cpp: nothing here names an asio type.

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "indexer_client/client.hpp"
#include "indexer_client/types.hpp"

namespace indexer_client::detail::write
{
    class Bucket;
    class WritePath;
    struct OpState;
} // namespace indexer_client::detail::write

namespace indexer_client::detail::query
{
    class PitRegistry;
} // namespace indexer_client::detail::query

namespace indexer_client::detail
{
    struct RuntimeState;
    struct ClientState;

    /// Releases a consumer name so that a later client may reuse it. No-op if the runtime is gone or restarted.
    void releaseClientName(const std::weak_ptr<RuntimeState>& runtime, std::uint64_t epoch, const std::string& name);

    /// The live clients of a runtime, from its weak registry (written by RuntimeRef::client(), erased by
    /// releaseClientName), locked after the runtime mutex is dropped, plus those whose name was released once
    /// the stop began, which the runtime keeps until its last summary; empty once the runtime is gone. The caller may
    /// end up holding a client's last reference: dropping it releases the name (takes the runtime mutex) and, on a
    /// runtime thread, destroys its buckets there.
    std::vector<std::shared_ptr<ClientState>> runtimeLiveClients(const std::weak_ptr<RuntimeState>& runtime);

    /// The runtime's shutdown deadline, if beginShutdown() fixed one and the runtime is still the same epoch.
    std::optional<TimePoint> runtimeShutdownDeadline(const std::weak_ptr<RuntimeState>& runtime, std::uint64_t epoch);

    /// Counts one usage error in the process-wide counter read by detail::testing::usageErrors().
    void countUsageError();

    /// An internal invariant was found broken. Logs `what` at ERROR and counts it (read by the test
    /// build through testing_hooks::internalErrors()); never aborts, in any build. The caller then takes its recovery
    /// path (encode(): the op is refused InvalidState; ~Bucket: completes what is left; a resolution with a bucket
    /// other than the op's: carries on with the caller's).
    void internalError(const char* what) noexcept;

    /// Runs `action` under the lock that serializes RuntimeOwner::start() and shutdown() when no runtime exists (no
    /// runtime thread can be running); false, without running it, otherwise (setLogFunction).
    bool withNoRuntime(const std::function<void()>& action);

    class NodeSet;
    /// The NodeSet of a client's runtime (Client::health()): null once that runtime is gone or another epoch runs.
    std::shared_ptr<NodeSet> runtimeNodeSet(const std::weak_ptr<RuntimeState>& runtime, std::uint64_t epoch);

    class Transport;
    /// The transport of a client's runtime (for queries): null once that runtime is gone or another
    /// epoch runs.
    std::shared_ptr<Transport> runtimeTransport(const std::weak_ptr<RuntimeState>& runtime, std::uint64_t epoch);

    /// The PIT registry of a client's runtime: null once that runtime is gone or another epoch runs.
    std::shared_ptr<query::PitRegistry> runtimePitRegistry(const std::weak_ptr<RuntimeState>& runtime,
                                                           std::uint64_t epoch);

    /// (runtime/logSummary.hpp) What the log summary reads from its runtime; nullopt once the runtime is gone.
    struct LogSummarySources final
    {
        Duration interval {Duration {60000}}; ///< RuntimeConfig::logSummaryInterval.
        std::shared_ptr<write::WritePath> writePath;
        std::shared_ptr<query::PitRegistry> pits;
    };
    std::optional<LogSummarySources> runtimeLogSummarySources(const std::weak_ptr<RuntimeState>& runtime);

    /// Runs `task` on loop 0 once `delay` has passed, with the log summary's own timers (LoopTimers); false once
    /// they stopped (stopAndJoin, before the write path stops) or the runtime is gone.
    bool runtimeLogSummaryAfter(const std::weak_ptr<RuntimeState>& runtime, Duration delay, std::function<void()> task);

    /// One-shot completion shared by every ticket kind: set once, waited on by consumer threads only.
    template<class T>
    struct Completion
    {
        mutable std::mutex mutex;
        mutable std::condition_variable cv;
        std::optional<Outcome<T>> result;

        void complete(Outcome<T> outcome)
        {
            {
                std::lock_guard<std::mutex> lock(mutex);
                if (result)
                {
                    return;
                }
                result = std::move(outcome);
            }
            cv.notify_all();
        }

        bool isReady() const
        {
            std::lock_guard<std::mutex> lock(mutex);
            return result.has_value();
        }

        /// The caller has already rejected runtime threads (Reentrancy).
        Outcome<T> waitUntil(Deadline deadline) const
        {
            std::unique_lock<std::mutex> lock(mutex);
            if (!cv.wait_until(lock, deadline, [this] { return result.has_value(); }))
            {
                return Outcome<T>::failure(Cause::WaitTimeout, "wait deadline expired before the result");
            }
            return *result;
        }
    };

    struct TicketState final : Completion<OpResult>
    {
        TicketState() = default;
        TicketState(const TicketState&) = delete;
        TicketState& operator=(const TicketState&) = delete;
        /// Returns the op's RESULT_RESERVE when `reserveArmed` (writer.cpp): to the bucket while it lives, else to the
        /// global cap while the write path lives, else nothing (its budget is gone).
        ~TicketState();

        /// The RESULT_RESERVE of an accepted op without callback lives as long as the last Ticket (or
        /// the resolution's local reference). Armed by submit once the reserve is charged; both references are weak
        /// (the reserve never keeps the runtime alive). Never dropped while holding a bucket mutex.
        std::weak_ptr<write::WritePath> reservePath;
        std::weak_ptr<write::Bucket> reserveBucket;
        bool reserveArmed {false};
    };

    struct CancelState final : Completion<Unit>
    {
    };

    /// A confirmable group. NORMATIVE contract: write/group.hpp.
    struct GroupState final : Completion<std::vector<OpResult>>
    {
        enum class Phase
        {
            Building,
            Committed,
            Done,
            Abandoned
        };

        GroupState() = default;
        GroupState(const GroupState&) = delete;
        GroupState& operator=(const GroupState&) = delete;
        ~GroupState(); ///< Returns reservesHeld x RESULT_RESERVE (group.cpp).

        std::atomic<bool> committed {false}; ///< commit() runs once.
        std::weak_ptr<ClientState> client;
        std::weak_ptr<write::Bucket> bucket;
        std::weak_ptr<write::WritePath> path;

        std::mutex groupMutex; ///< A leaf (group.hpp); guards the members below.
        Phase phase {Phase::Building};
        std::vector<std::shared_ptr<write::OpState>> ops; ///< Building only.
        std::uint64_t reservedBytes {0};                  ///< Payload + reserves of the Building ops.
        std::uint32_t reservesHeld {0};                   ///< RESULT_RESERVEs this group still owes back.
        std::vector<OpResult> results;                    ///< One slot per op, in add order (Committed).
        std::size_t remaining {0};
        std::string lastAddReason; ///< Why the last add() was refused; empty after an accepted one.
    };

    /// Where every query wait sleeps. One per runtime, shared with each of its clients; the transport
    /// callback of a query attempt, Client::requestClose() and RuntimeState::stopAndJoin() notify it (notify_all:
    /// a waiter re-checks its own attempt, client and `stopping`). A leaf: nothing else is locked under `mutex`.
    struct QueryGate final
    {
        std::mutex mutex;
        std::condition_variable cv;
        bool stopping {false}; ///< Set once by stopAndJoin(), before the write path stops.
    };

    /// Polymorphic hand-over run when a PitState dies (pit.cpp defines the derived one; its virtual destructor is
    /// reached through the vtable, so no PitState symbol has to be visible outside the library).
    struct PitHandoff
    {
        virtual ~PitHandoff() = default;
    };

    /// A managed PIT. NORMATIVE contract: query/pit.hpp. Shared by its Pit handles and PitSessions.
    struct PitState final
    {
        std::mutex mutex;  ///< A leaf; guards `id` and `lastUse`.
        std::string id;    ///< Renewed by a 2xx carrying another pit_id (last arrival wins).
        TimePoint lastUse; ///< When the end of the last attempt that may have been sent was seen (an upper bound).
        Duration keepAlive {Duration {0}};
        std::uint64_t generation {0}; ///< Process-wide counter at creation (never reused).
        std::atomic<bool> expired {false};
        std::atomic<bool> drained {false}; ///< The shutdown drain deleted it: the hand-over gives nothing.
        QueryOptions options;              ///< The pit() options: they govern every page and search.
        bool wholeResponseCap {false};     ///< PitOptions::wholeResponseCap: pages capped by maxResponseBytes.
        std::vector<std::string> indices;
        std::shared_ptr<ClientState> client;
        std::weak_ptr<query::PitRegistry> registry;
        /// Last member, so destroyed first while the others still hold their values: pit.cpp's hand-over gives
        /// {id, keepAlive, lastUse} to the registry unless `drained`.
        std::unique_ptr<PitHandoff> handoff;
    };

    /// One cursor (slice) over a PitState.
    struct CursorState final
    {
        std::shared_ptr<PitState> pit;
        CursorQuery query;
        std::optional<Slice> slice;
        std::string invalid; ///< Non-empty: the first next() returns InvalidArgument with this reason.
        std::mutex mutex;    ///< Held by the one next() in progress (an overlapping one is refused); guards below.
        nlohmann::json searchAfter; ///< The last hit's sort; null before the first page.
        bool firstPage {true};
        std::atomic<bool> exhausted {false};
    };

    /// Per-consumer state. The runtime is referenced weakly: a client never keeps the runtime alive.
    struct ClientState final
    {
        std::weak_ptr<RuntimeState> runtime;
        std::uint64_t epoch {0};
        std::string consumer;
        std::vector<BucketSpec> buckets;
        /// The client's buckets, in the order of `buckets` (created by WritePath::registerClient).
        std::vector<std::shared_ptr<write::Bucket>> bucketStates;
        /// Completions posted to the pool and not yet finished (callback run, reserve released);
        /// awaitClosed waits on it and reports the rest as CloseReport.callbacksInFlight.
        std::mutex completionsMutex;
        std::condition_variable completionsDone;
        std::uint64_t outstandingCompletions {0};
        /// Ops of this client resolved Dropped(ClientClosed) / Dropped(Shutdown) (CloseReport).
        std::atomic<std::uint64_t> droppedClientClosed {0};
        std::atomic<std::uint64_t> droppedShutdown {0};
        /// (write/writer.hpp «Close») Under completionsMutex: the callback cutoff (max until awaitClosed sets
        /// it), the callbacks started and not finished, and drainDone (notified by every resolution of one of the
        /// client's ops after requestClose(), for awaitClosed's drain wait).
        std::condition_variable drainDone;
        TimePoint callbackCutoff {TimePoint::max()};
        std::uint64_t callbacksRunning {0};
        std::atomic<std::uint64_t> callbacksSkipped {0};
        std::atomic<std::uint64_t> callbackOverruns {0};
        std::atomic<std::int64_t> callbackMaxDurationMicros {0};
        /// (runtime/logSummary.hpp) The maximum callback duration of the current log summary interval (the summary
        /// exchanges it with 0) and the callbackOverruns the previous summary saw (under the summary's mutex).
        std::atomic<std::int64_t> callbackIntervalMaxMicros {0};
        std::uint64_t overrunsLogged {0};
        /// Ops of the client resolved after requestClose(), not Dropped(ClientClosed|Shutdown) (CloseReport::drained).
        std::atomic<std::uint64_t> drained {0};
        Duration callbackBudget {Duration {200}};
        /// Serializes awaitClosed (only it takes this mutex); `closeReport` set ⇔ the first call drained and swept
        /// (every call, that one included, reports the live counters).
        std::mutex closeMutex;
        std::optional<CloseReport> closeReport;
        /// The runtime's write path (set by RuntimeRef::client); weak, like `runtime`.
        std::weak_ptr<write::WritePath> writePath;
        Duration drain {Duration {10000}};
        /// The runtime's query gate and the configuration values a query needs (copied at creation).
        std::shared_ptr<QueryGate> queryGate;
        Duration requestTimeout {Duration {60000}};
        Duration probeInterval {Duration {10000}};
        std::uint64_t maxResponseBytes {64u << 20};
        std::atomic<bool> closeRequested {false};
        std::atomic<bool> nameReleased {false};

        void releaseName()
        {
            if (!nameReleased.exchange(true))
            {
                releaseClientName(runtime, epoch, consumer);
            }
        }

        ~ClientState()
        {
            releaseName();
        }
    };

    /// The CPU pool's queue (NoDropWithoutCounter): tasks posted and not yet taken by a worker, and the peak
    /// since the runtime started. Zeros when no runtime runs. Internal access (component suite).
    struct PoolStats final
    {
        std::uint64_t postsPending {0};
        std::uint64_t peakPostsPending {0};
    };
    PoolStats runtimePoolStats();

    /// Stub writer: every operation is Cause::Unavailable (Client::writer() when the runtime is gone).
    std::shared_ptr<IWriter> makeStubWriter(std::shared_ptr<ClientState> client, std::string bucket);
} // namespace indexer_client::detail

#endif // _INDEXER_CLIENT_RUNTIME_INTERNAL_HPP
