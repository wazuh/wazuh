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

#include "write/sender.hpp"

#include <algorithm>
#include <chrono>
#include <exception>
#include <future>
#include <mutex>
#include <string>
#include <system_error>
#include <unordered_map>
#include <utility>

#include <asio/io_context.hpp>
#include <asio/post.hpp>
#include <asio/steady_timer.hpp>

#include "health/nodeSet.hpp"
#include "runtime/runtimeInternal.hpp"
#include "transport/seams.hpp"
#include "transport/transport.hpp"
#include "write/response.hpp"
#include "write/scheduler.hpp"
#include "write/writer.hpp"

// The bulk sender (plan 18 I68; the normative rules are in sender.hpp). Handlers, pool tasks, transport callbacks and
// the NodeSet hook capture the shared state (strongly, or weakly for the hook the NodeSet keeps forever), never
// `this`. The sender's mutex is a leaf: nothing is called with it held except arithmetic on its own members, and no
// OpState, Batch or TicketState reference is dropped under it.

namespace indexer_client::detail::write
{
    namespace
    {
        /// Loop-0 state and everything the mutex guards, per node.
        struct NodeSlot final
        {
            bool down {true}; ///< Mirrored from NodeSet (initially Down, like the NodeSet's view).
            std::uint32_t inFlight {0};
            TimePoint notBefore {};    ///< 429: nothing is sent to the node before it (in force when > now).
            TimePoint notBeforeSet {}; ///< When the current notBefore was last raised.
            bool notBeforeEverSet {false};
            Duration pace {Duration {0}};
            std::uint64_t requests {0};
            std::uint64_t totalMicros {0};
            std::uint64_t failures {0};
        };

        /// One request between its submit and its completion (for the cancellation of stop()).
        struct Flight final
        {
            std::uint64_t transferId {0}; ///< 0 until Transport::submit returned.
        };

        struct SenderShared final
        {
            SenderShared(std::weak_ptr<WritePath> writePath,
                         std::shared_ptr<NodeSet> nodeSet,
                         std::shared_ptr<Transport> httpTransport,
                         asio::io_context& loop,
                         const RuntimeConfig& config)
                : path(std::move(writePath))
                , nodes(std::move(nodeSet))
                , transport(std::move(httpTransport))
                , loop0(loop)
                , paceInitial(std::min(config.paceInitial, config.retryAfterMax))
                , retryAfterMax(config.retryAfterMax)
            {
                const auto count = nodes ? nodes->size() : 0;
                urls.reserve(count);
                hosts.reserve(count);
                for (std::size_t i = 0; i < count; ++i)
                {
                    auto host = nodes->host(i);
                    hosts.push_back(host);
                    while (!host.empty() && host.back() == '/')
                    {
                        host.pop_back();
                    }
                    urls.push_back(host + "/_bulk");
                }
                slots.resize(count);
            }

            const std::weak_ptr<WritePath> path;
            const std::shared_ptr<NodeSet> nodes;
            const std::shared_ptr<Transport> transport;
            asio::io_context& loop0;
            const Duration paceInitial;
            const Duration retryAfterMax;
            std::vector<std::string> urls;
            std::vector<std::string> hosts;

            // ---- loop 0 only
            std::unique_ptr<asio::steady_timer> timer;
            std::optional<TimePoint> timerAt; ///< Expiry the timer waits for (none when idle).

            mutable std::mutex mutex; ///< Guards everything below (a leaf, see the header).
            bool stopped {false};
            bool timerArmed {false}; ///< A timer was ever armed (the destructor's usage-error check).
            std::vector<NodeSlot> slots;
            std::uint64_t mirroredGeneration {0};
            std::uint64_t nextFlight {0};
            std::unordered_map<std::uint64_t, Flight> flights;
            SenderStats counters; ///< Without `nodes` (built from `slots` by stats()).
        };

        std::string truncated(std::string text, std::size_t limit)
        {
            if (text.size() > limit)
            {
                text.resize(limit);
            }
            return text;
        }

        OpResult droppedResult(Cause cause)
        {
            OpResult result;
            result.status = Status::Dropped;
            result.cause = cause;
            result.reason = cause == Cause::ClientClosed ? "dropped: the client was closed"
                                                         : "dropped: the runtime is shutting down";
            return result;
        }

        /// `last` is the op's last error as Bucket::requeue copied it out (RequeueResult::exhaustedErrors).
        OpResult exhaustedResult(LastError last)
        {
            OpResult result;
            result.status = Status::Failed;
            result.cause = Cause::RetryExhausted;
            result.httpStatus = last.httpStatus;
            result.itemErrorType = std::move(last.itemErrorType);
            result.reason = truncated(std::string("retries exhausted; last error ") + toString(last.cause) +
                                          (last.reason.empty() ? std::string() : ": " + last.reason),
                                      OpResult::MAX_REASON);
            return result;
        }

        void armTimer(const std::shared_ptr<SenderShared>& shared);

        /// Any thread: queues an arm of the notBefore timer on loop 0 unless stopped. Posted under the mutex: stop()
        /// either sees it queued ahead of its own handler or the arm sees `stopped`.
        void postArm(const std::shared_ptr<SenderShared>& shared)
        {
            std::lock_guard<std::mutex> lock(shared->mutex);
            if (shared->stopped)
            {
                return;
            }
            asio::post(shared->loop0, [shared]() { armTimer(shared); });
        }

        /// Loop 0 only: (re)arms the timer at the earliest notBefore in force; a later one waits for the next arm.
        void armTimer(const std::shared_ptr<SenderShared>& shared)
        {
            std::optional<TimePoint> earliest;
            {
                std::lock_guard<std::mutex> lock(shared->mutex);
                if (shared->stopped)
                {
                    return;
                }
                const auto now = std::chrono::steady_clock::now();
                for (const auto& slot : shared->slots)
                {
                    if (slot.notBefore > now && (!earliest || slot.notBefore < *earliest))
                    {
                        earliest = slot.notBefore;
                    }
                }
                if (!earliest || (shared->timerAt && *shared->timerAt <= *earliest))
                {
                    return; // Nothing in force, or the armed expiry comes first (its handler re-arms).
                }
                shared->timerArmed = true;
            }
            if (!shared->timer)
            {
                shared->timer = std::make_unique<asio::steady_timer>(shared->loop0);
            }
            shared->timerAt = earliest;
            shared->timer->expires_at(*earliest); // Cancels a pending wait (operation_aborted).
            shared->timer->async_wait(
                [shared](const std::error_code& error)
                {
                    if (error)
                    {
                        return;
                    }
                    shared->timerAt.reset();
                    {
                        std::lock_guard<std::mutex> lock(shared->mutex);
                        if (shared->stopped)
                        {
                            return;
                        }
                    }
                    if (auto path = shared->path.lock())
                    {
                        path->sinkReady();
                    }
                    armTimer(shared); // The next notBefore still in force, if any.
                });
        }

        /// The NodeSet hook: mirrors every node's Down state from a consistent view (a hook from another thread may
        /// run late; the generation keeps an older view from overwriting a newer one), then wakes the scheduler.
        void refreshMirror(const std::shared_ptr<SenderShared>& shared, bool wake = true)
        {
            std::uint64_t generation = 0;
            HealthView view;
            for (;;)
            {
                generation = shared->nodes->generation();
                view = shared->nodes->view();
                if (shared->nodes->generation() == generation)
                {
                    break;
                }
            }
            {
                std::lock_guard<std::mutex> lock(shared->mutex);
                if (generation < shared->mirroredGeneration)
                {
                    return; // A newer view was already applied (and woke the scheduler).
                }
                shared->mirroredGeneration = generation;
                for (std::size_t i = 0; i < shared->slots.size() && i < view.nodes.size(); ++i)
                {
                    shared->slots[i].down = view.nodes[i].state == HealthView::NodeState::Down;
                }
            }
            if (!wake)
            {
                return;
            }
            if (auto path = shared->path.lock())
            {
                path->sinkReady();
            }
        }

        /// Gives a request's slot back (and forgets its flight); the caller wakes the scheduler afterwards.
        void releaseSlot(SenderShared& shared, std::size_t node, std::uint64_t flight)
        {
            std::lock_guard<std::mutex> lock(shared.mutex);
            auto& slot = shared.slots[node];
            if (slot.inFlight > 0)
            {
                --slot.inFlight;
            }
            shared.flights.erase(flight);
        }

        /// Moves `ops` back to the bucket's retry lane per `spec` and resolves what comes back exhausted or closed.
        /// No sender lock held.
        void requeueOps(SenderShared& shared,
                        const std::shared_ptr<WritePath>& path,
                        const std::shared_ptr<Bucket>& bucket,
                        std::vector<RequeueOp> ops,
                        const RequeueSpec& spec)
        {
            if (!bucket || ops.empty())
            {
                return;
            }
            auto result = bucket->requeue(std::move(ops), spec, std::chrono::steady_clock::now());
            if (spec.countAttempt || !result.exhausted.empty())
            {
                std::lock_guard<std::mutex> lock(shared.mutex);
                if (spec.countAttempt)
                {
                    ++shared.counters.retries;
                }
                shared.counters.exhausted += result.exhausted.size();
            }
            if (path)
            {
                for (std::size_t i = 0; i < result.exhausted.size(); ++i)
                {
                    path->resolve(result.exhausted[i],
                                  exhaustedResult(i < result.exhaustedErrors.size()
                                                      ? std::move(result.exhaustedErrors[i])
                                                      : LastError {}));
                }
                if (!result.closed.empty())
                {
                    const auto cause = bucket->closedCause().value_or(Cause::Shutdown);
                    for (const auto& op : result.closed)
                    {
                        path->resolve(op, droppedResult(cause));
                    }
                }
                if (result.notify)
                {
                    if (auto scheduler = path->scheduler())
                    {
                        scheduler->notify(bucket);
                    }
                }
            }
        }

        /// The whole batch back to the lane with the same last error.
        void requeueBatch(SenderShared& shared,
                          const std::shared_ptr<WritePath>& path,
                          const Batch& batch,
                          const LastError& error,
                          const RequeueSpec& spec)
        {
            std::vector<RequeueOp> ops;
            ops.reserve(batch.ops.size());
            for (const auto& op : batch.ops)
            {
                ops.push_back(RequeueOp {op, error});
            }
            requeueOps(shared, path, batch.bucket, std::move(ops), spec);
        }

        RequeueSpec spec(bool countAttempt, RequeueSpec::Delay delay)
        {
            RequeueSpec requeue;
            requeue.countAttempt = countAttempt;
            requeue.delay = delay;
            return requeue;
        }

        /// A submit that never got a callback (refused, seam, exception): slot back, then the batch to the lane with
        /// an attempt, then the scheduler woken.
        void refused(const std::shared_ptr<SenderShared>& shared,
                     const Batch& batch,
                     std::size_t node,
                     std::uint64_t flight,
                     std::string reason)
        {
            releaseSlot(*shared, node, flight);
            {
                std::lock_guard<std::mutex> lock(shared->mutex);
                ++shared->counters.submitRefused;
            }
            auto path = shared->path.lock();
            requeueBatch(*shared,
                         path,
                         batch,
                         LastError {Cause::InvalidState, 0, {}, truncated(std::move(reason), OpResult::MAX_REASON)},
                         spec(true, RequeueSpec::Delay::Backoff));
            if (path)
            {
                path->sinkReady();
            }
        }

        /// Items verdict: one resolution or requeue per op, item i <-> op i.
        void
        applyItems(SenderShared& shared, const std::shared_ptr<WritePath>& path, const Batch& batch, HttpResult& result)
        {
            std::string reason;
            auto items = classifyItems(result.body, batch.ops.size(), &reason);
            if (!items)
            {
                requeueBatch(shared,
                             path,
                             batch,
                             LastError {Cause::Server5xx,
                                        static_cast<int>(result.status),
                                        {},
                                        truncated(std::move(reason), OpResult::MAX_REASON)},
                             spec(true, RequeueSpec::Delay::Backoff));
                return;
            }
            std::vector<RequeueOp> retry;
            for (std::size_t i = 0; i < batch.ops.size(); ++i)
            {
                auto& item = (*items)[i];
                const auto& op = batch.ops[i];
                switch (item.verdict)
                {
                    case ItemVerdict::Conflict:
                        // I73: the op's effective ConflictPolicy (OpState::conflictRetry). Retry ⇒ back to the lane
                        // with the 409 as its last error (exhausted ⇒ Failed(RetryExhausted) with it); Success ⇒ Ok
                        // keeping the 409 and its type, as below.
                        if (op->conflictRetry)
                        {
                            retry.push_back(RequeueOp {op,
                                                       LastError {Cause::VersionConflict,
                                                                  item.httpStatus,
                                                                  std::move(item.itemErrorType),
                                                                  item.reason}});
                            break;
                        }
                        [[fallthrough]];
                    case ItemVerdict::Ok:
                    case ItemVerdict::NotFound:
                    {
                        OpResult ok;
                        ok.status = Status::Ok;
                        ok.outcome = item.outcome;
                        ok.httpStatus = item.httpStatus;
                        ok.itemErrorType = std::move(item.itemErrorType);
                        ok.reason = std::move(item.reason);
                        if (path)
                        {
                            path->resolve(op, std::move(ok));
                        }
                        break;
                    }
                    case ItemVerdict::Retry:
                        retry.push_back(RequeueOp {
                            op,
                            LastError {
                                Cause::ItemRetryable, item.httpStatus, std::move(item.itemErrorType), item.reason}});
                        break;
                    case ItemVerdict::Permanent:
                    default:
                    {
                        OpResult failed;
                        failed.status = Status::Failed;
                        failed.cause = Cause::ItemPermanent;
                        failed.outcome = item.outcome;
                        failed.httpStatus = item.httpStatus;
                        failed.itemErrorType = std::move(item.itemErrorType);
                        failed.reason = std::move(item.reason);
                        if (path)
                        {
                            path->resolve(op, std::move(failed));
                        }
                        break;
                    }
                }
            }
            requeueOps(shared, path, batch.bucket, std::move(retry), spec(true, RequeueSpec::Delay::Backoff));
        }

        /// A completion that threw after the slot was released: what is still unresolved goes back to the lane with an
        /// attempt (requeue skips the ops already resolved). Never throws.
        void requeueAfterFailure(SenderShared& shared,
                                 const std::shared_ptr<WritePath>& path,
                                 const Batch& batch,
                                 std::string reason) noexcept
        {
            try
            {
                requeueBatch(shared,
                             path,
                             batch,
                             LastError {Cause::InvalidState, 0, {}, truncated(std::move(reason), OpResult::MAX_REASON)},
                             spec(true, RequeueSpec::Delay::Backoff));
            }
            catch (...)
            {
                // Nothing left to try: the ops stay delivered and the shutdown sweep resolves them.
            }
        }

        /// A finished transfer (CPU pool): slot and node state first, under the mutex; everything else after it.
        void complete(const std::shared_ptr<SenderShared>& shared,
                      const Batch& batch,
                      std::size_t node,
                      std::uint64_t flight,
                      TimePoint sentAt,
                      HttpResult&& result)
        {
            auto outcome = classifyRequest(result, batch.ops.size());
            const auto now = std::chrono::steady_clock::now();
            bool armNeeded = false;
            bool stoppedNow = false;
            {
                std::lock_guard<std::mutex> lock(shared->mutex);
                stoppedNow = shared->stopped;
                auto& slot = shared->slots[node];
                if (slot.inFlight > 0)
                {
                    --slot.inFlight;
                }
                shared->flights.erase(flight);
                if (result.cause == TransportCause::None)
                {
                    // HTTP responses only: a timeout or a cancellation would skew E5's latency average.
                    ++slot.requests;
                    slot.totalMicros +=
                        static_cast<std::uint64_t>(std::max<std::int64_t>(0, result.timings.total.count()));
                }
                else
                {
                    ++slot.failures;
                }
                if (outcome.verdict == RequestVerdict::Throttled)
                {
                    // One burst of the window doubles the pace once: only a request that left after the notBefore in
                    // force was set (or before any was) makes it grow.
                    if (!slot.notBeforeEverSet || sentAt > slot.notBeforeSet)
                    {
                        slot.pace = slot.pace.count() == 0 ? shared->paceInitial
                                                           : std::min(slot.pace * 2, shared->retryAfterMax);
                    }
                    const auto wait = std::max(outcome.retryAfter.value_or(Duration {0}), slot.pace);
                    if (now + wait > slot.notBefore)
                    {
                        slot.notBefore = now + wait;
                        slot.notBeforeSet = now;
                        slot.notBeforeEverSet = true;
                        armNeeded = true;
                    }
                    ++shared->counters.throttled;
                }
                else if (result.cause == TransportCause::None && result.status >= 200 && result.status < 300)
                {
                    slot.pace = Duration {0}; // Never touches a notBefore in force.
                }
                switch (outcome.verdict)
                {
                    case RequestVerdict::Failover: ++shared->counters.failovers; break;
                    case RequestVerdict::Split: ++shared->counters.splits; break;
                    default: break;
                }
            }

            auto path = shared->path.lock();
            // Past the slot release nothing may leave the batch unresolved: an exception (bad_alloc in a requeue or a
            // resolution, or the test seam) sends what is still unresolved back to the lane (G-diff E3b-2 obj. 6).
            try
            {
                seams::beforeCompletion();
                const LastError error {outcome.cause, outcome.httpStatus, {}, outcome.reason};
                switch (outcome.verdict)
                {
                    case RequestVerdict::Ignore:
                        if (result.cause == TransportCause::Cancelled && stoppedNow)
                        {
                            // Cancelled by this sender's stop(): outside a runtime stop (a setSink) no sweep follows,
                            // so the batch goes back to the lane with no attempt and waits for the new sink; a closed
                            // bucket hands it back `closed` (Dropped). Shutdown stays Ignore: the sweep resolves.
                            requeueBatch(
                                *shared,
                                path,
                                batch,
                                LastError {Cause::Cancelled, 0, {}, "sender stopped with the request in flight"},
                                spec(false, RequeueSpec::Delay::Now));
                        }
                        break;
                    case RequestVerdict::Failover:
                        shared->nodes->report(node, result);
                        requeueBatch(*shared, path, batch, error, spec(outcome.mayHaveSent, RequeueSpec::Delay::Now));
                        break;
                    case RequestVerdict::Retry:
                        requeueBatch(*shared, path, batch, error, spec(true, RequeueSpec::Delay::Backoff));
                        break;
                    case RequestVerdict::Throttled:
                        shared->nodes->report(node, result);
                        if (armNeeded)
                        {
                            postArm(shared);
                        }
                        requeueBatch(*shared, path, batch, error, spec(false, RequeueSpec::Delay::Now));
                        break;
                    case RequestVerdict::Split:
                    {
                        auto split = spec(false, RequeueSpec::Delay::Now);
                        split.toHead = true;
                        split.halve = true;
                        requeueBatch(*shared, path, batch, error, split);
                        break;
                    }
                    case RequestVerdict::FailBatch:
                        if (path)
                        {
                            for (const auto& op : batch.ops)
                            {
                                OpResult failed;
                                failed.status = Status::Failed;
                                failed.cause = outcome.cause;
                                failed.httpStatus = outcome.httpStatus;
                                failed.reason = outcome.reason;
                                path->resolve(op, std::move(failed));
                            }
                        }
                        break;
                    case RequestVerdict::Items: applyItems(*shared, path, batch, result); break;
                }
            }
            catch (const std::exception& e)
            {
                requeueAfterFailure(*shared, path, batch, std::string("bulk completion failed: ") + e.what());
            }
            catch (...)
            {
                requeueAfterFailure(*shared, path, batch, "bulk completion failed: unexpected exception");
            }
            if (path)
            {
                path->sinkReady();
            }
        }

        /// CPU pool: assembles the body and submits it. Every exit without a callback gives the slot back.
        void send(const std::shared_ptr<SenderShared>& shared,
                  std::shared_ptr<Batch> batch,
                  std::size_t node,
                  std::uint64_t flight,
                  TimePoint sentAt)
        {
            // True once this task no longer owns the slot: the transfer was admitted (its callback completes the batch)
            // or the slot was already given back (stopped before the submit). The catch then must not call refused().
            bool admitted = false;
            try
            {
                bool stoppedBefore = false;
                {
                    std::lock_guard<std::mutex> lock(shared->mutex);
                    if (shared->stopped)
                    {
                        stoppedBefore = true;
                        auto& slot = shared->slots[node];
                        if (slot.inFlight > 0)
                        {
                            --slot.inFlight;
                        }
                    }
                    else
                    {
                        shared->flights.emplace(flight, Flight {}); // stop() cancels it once its id is known.
                    }
                }
                if (stoppedBefore)
                {
                    // Stopped before the submit: back to the lane with no attempt. During the runtime's stop the
                    // buckets are already closed, so they come back as closed and end Dropped(Shutdown) (the sweep
                    // may win first); after a setSink they wait in the lane for the new sink.
                    // The slot is already back: from here a failure must not give it back again in the catch.
                    admitted = true;
                    auto path = shared->path.lock();
                    requeueBatch(*shared,
                                 path,
                                 *batch,
                                 LastError {Cause::InvalidState, 0, {}, "sender stopped before the submit"},
                                 spec(false, RequeueSpec::Delay::Now));
                    if (path)
                    {
                        path->sinkReady();
                    }
                    return;
                }
                if (seams::refuseSubmit())
                {
                    refused(shared, *batch, node, flight, "bulk submit refused (test seam)");
                    return;
                }

                std::uint64_t size = 0;
                for (const auto& op : batch->ops)
                {
                    size += op->lines.size();
                }
                auto body = std::make_shared<std::string>();
                body->reserve(size);
                for (const auto& op : batch->ops)
                {
                    body->append(op->lines);
                }
                HttpRequest request;
                request.method = HttpMethod::Post;
                request.url = shared->urls[node];
                request.body = std::move(body);
                request.contentType = "application/json";

                const auto admission =
                    shared->transport->submit(std::move(request),
                                              [shared, batch, node, flight, sentAt](HttpResult&& result)
                                              { complete(shared, *batch, node, flight, sentAt, std::move(result)); });
                if (!admission.admitted)
                {
                    if (admission.cause == Cause::Shutdown)
                    {
                        releaseSlot(*shared, node, flight); // The runtime's sweep resolves the ops.
                        if (auto path = shared->path.lock())
                        {
                            path->sinkReady();
                        }
                        return;
                    }
                    refused(shared,
                            *batch,
                            node,
                            flight,
                            std::string("bulk submit not admitted: ") + toString(admission.cause));
                    return;
                }
                admitted = true;
                bool cancelNow = false;
                {
                    std::lock_guard<std::mutex> lock(shared->mutex);
                    ++shared->counters.sent;
                    if (auto it = shared->flights.find(flight); it != shared->flights.end())
                    {
                        it->second.transferId = admission.id;
                        cancelNow = shared->stopped; // stop() ran before the id was known.
                    }
                }
                if (cancelNow)
                {
                    shared->transport->cancel(admission.id);
                }
            }
            catch (const std::exception& e)
            {
                if (!admitted) // An admitted transfer keeps its slot and completes through its callback.
                {
                    refused(shared, *batch, node, flight, std::string("bulk submit failed: ") + e.what());
                }
            }
            catch (...)
            {
                if (!admitted)
                {
                    refused(shared, *batch, node, flight, "bulk submit failed: unexpected exception");
                }
            }
        }

        class BulkSinkImpl final : public BulkSink
        {
        public:
            explicit BulkSinkImpl(std::shared_ptr<SenderShared> shared)
                : m_shared(std::move(shared))
            {
            }

            ~BulkSinkImpl() override
            {
                std::lock_guard<std::mutex> lock(m_shared->mutex);
                if (m_shared->timerArmed && !m_shared->stopped)
                {
                    countUsageError(); // Its timer would die off loop 0; the runtime always stops it first.
                }
            }

            BulkSinkImpl(const BulkSinkImpl&) = delete;
            BulkSinkImpl& operator=(const BulkSinkImpl&) = delete;

            void start() override
            {
                if (!m_shared->nodes)
                {
                    return;
                }
                std::weak_ptr<SenderShared> weak = m_shared;
                m_shared->nodes->onTransition(
                    [weak](std::size_t /*index*/, NodeSet::State /*from*/, NodeSet::State /*to*/)
                    {
                        auto shared = weak.lock();
                        if (!shared)
                        {
                            return;
                        }
                        {
                            std::lock_guard<std::mutex> lock(shared->mutex);
                            if (shared->stopped)
                            {
                                return;
                            }
                        }
                        seams::beforeSenderMirror();
                        refreshMirror(shared);
                    });
            }

            std::size_t capacity() override
            {
                std::lock_guard<std::mutex> lock(m_shared->mutex);
                if (m_shared->stopped)
                {
                    return 0;
                }
                const auto now = std::chrono::steady_clock::now();
                std::size_t total = 0;
                for (const auto& slot : m_shared->slots)
                {
                    if (!slot.down && slot.notBefore <= now && slot.inFlight < NODE_WINDOW)
                    {
                        total += NODE_WINDOW - slot.inFlight;
                    }
                }
                return total;
            }

            void dispatch(Batch batch) override
            {
                auto shared = m_shared;
                auto held = std::make_shared<Batch>(std::move(batch));
                std::optional<std::size_t> node;
                std::uint64_t flight = 0;
                const auto now = std::chrono::steady_clock::now();
                bool stopped = false;
                {
                    std::lock_guard<std::mutex> lock(shared->mutex);
                    stopped = shared->stopped;
                    flight = ++shared->nextFlight;
                }
                if (!stopped && shared->nodes)
                {
                    // The filter runs under the NodeSet's mutex and takes the sender's (the allowed order); the slot
                    // is taken in the same step, so capacity() sees it at once.
                    node = shared->nodes->choose(
                        [&shared, now](std::size_t index)
                        {
                            std::lock_guard<std::mutex> lock(shared->mutex);
                            if (index >= shared->slots.size())
                            {
                                return false;
                            }
                            auto& slot = shared->slots[index];
                            if (shared->stopped || slot.notBefore > now || slot.inFlight >= NODE_WINDOW)
                            {
                                return false;
                            }
                            ++slot.inFlight;
                            return true;
                        });
                }
                if (!node)
                {
                    // No usable node (or stopped, e.g. replaced by setSink): back to the lane with no attempt; a
                    // closed bucket hands them back for Dropped. A health transition or the timer wakes the scheduler.
                    if (!stopped && shared->nodes)
                    {
                        // The Down mirror may lag the NodeSet (its hook runs after the transition is logged):
                        // refreshed here, so capacity() drops to 0 at once instead of the scheduler re-slicing the
                        // batch until the hook lands (G-diff E3b-2 obj. 4). No sender lock is held.
                        refreshMirror(shared, false);
                    }
                    requeueBatch(*shared,
                                 shared->path.lock(),
                                 *held,
                                 stopped ? LastError {Cause::InvalidState, 0, {}, "sender stopped before the submit"}
                                         : LastError {Cause::Unavailable, 0, {}, "no usable node"},
                                 spec(false, RequeueSpec::Delay::Now));
                    return;
                }
                bool posted = false;
                try
                {
                    if (auto path = shared->path.lock())
                    {
                        posted = path->postToPool([shared, held, index = *node, flight, now]()
                                                  { send(shared, held, index, flight, now); });
                    }
                }
                catch (...)
                {
                    posted = false;
                }
                if (!posted)
                {
                    bool nowStopped = false;
                    {
                        std::lock_guard<std::mutex> lock(shared->mutex);
                        nowStopped = shared->stopped;
                    }
                    if (nowStopped)
                    {
                        releaseSlot(*shared, *node, flight); // The pool refused after stop(): the sweep resolves.
                        return;
                    }
                    refused(shared, *held, *node, flight, "the CPU pool refused the bulk task");
                }
            }

            void stop() override
            {
                std::lock_guard<std::mutex> stopLock(m_stopMutex); // Concurrent callers wait for the first one.
                std::vector<std::uint64_t> toCancel;
                {
                    std::lock_guard<std::mutex> lock(m_shared->mutex);
                    if (m_shared->stopped)
                    {
                        return;
                    }
                    m_shared->stopped = true;
                    for (const auto& [flight, state] : m_shared->flights)
                    {
                        if (state.transferId != 0)
                        {
                            toCancel.push_back(state.transferId);
                        }
                    }
                }
                if (m_shared->transport)
                {
                    for (const auto id : toCancel)
                    {
                        m_shared->transport->cancel(id);
                    }
                }
                const auto dropTimer = [](SenderShared& shared)
                {
                    if (shared.timer)
                    {
                        shared.timer->cancel();
                        shared.timer.reset();
                    }
                    shared.timerAt.reset();
                };
                if (m_shared->loop0.get_executor().running_in_this_thread())
                {
                    dropTimer(*m_shared);
                    return;
                }
                auto done = std::make_shared<std::promise<void>>();
                auto future = done->get_future();
                asio::post(m_shared->loop0,
                           [shared = m_shared, done, dropTimer]()
                           {
                               dropTimer(*shared);
                               done->set_value();
                           });
                future.wait();
            }

            SenderStats stats() const override
            {
                std::lock_guard<std::mutex> lock(m_shared->mutex);
                SenderStats stats = m_shared->counters;
                const auto now = std::chrono::steady_clock::now();
                stats.nodes.reserve(m_shared->slots.size());
                for (std::size_t i = 0; i < m_shared->slots.size(); ++i)
                {
                    const auto& slot = m_shared->slots[i];
                    SenderNodeStats node;
                    node.host = m_shared->hosts[i];
                    node.down = slot.down;
                    node.inFlight = slot.inFlight;
                    if (slot.notBefore > now)
                    {
                        node.notBefore = slot.notBefore;
                    }
                    node.pace = slot.pace;
                    node.requests = slot.requests;
                    node.totalMicros = slot.totalMicros;
                    node.failures = slot.failures;
                    stats.nodes.push_back(std::move(node));
                }
                return stats;
            }

        private:
            std::shared_ptr<SenderShared> m_shared;
            std::mutex m_stopMutex;
        };
    } // namespace

    std::shared_ptr<BulkSink> BulkSink::create(std::weak_ptr<WritePath> path,
                                               std::shared_ptr<NodeSet> nodes,
                                               std::shared_ptr<Transport> transport,
                                               asio::io_context& loop0,
                                               const RuntimeConfig& config)
    {
        return std::make_shared<BulkSinkImpl>(
            std::make_shared<SenderShared>(std::move(path), std::move(nodes), std::move(transport), loop0, config));
    }

    SenderStats senderStats()
    {
        auto path = runtimeWritePath();
        auto sink = path ? std::dynamic_pointer_cast<BulkSink>(path->sink()) : nullptr;
        return sink ? sink->stats() : SenderStats {};
    }
} // namespace indexer_client::detail::write
