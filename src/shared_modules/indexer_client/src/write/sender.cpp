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
#include <array>
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
#include "write/encoding.hpp"
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
            TimePoint notBeforeSet {}; ///< Burst marker (I98): the last bulk 429 that doubled pace or raised notBefore.
            bool notBeforeEverSet {false};
            Duration pace {Duration {0}};
            std::uint64_t requests {0};
            std::uint64_t totalMicros {0};
            std::uint64_t failures {0};
            // Limiter (E5a, I98; sender.hpp). `window` starts at nodeWindowMax (SenderShared's constructor).
            double window {1};                ///< Real AIMD window; ⌊window⌋ requests may be in flight.
            std::uint64_t bulkTarget {0};     ///< Bytes; 0 = uncapped.
            TimePoint nextSendAt {};          ///< Pacing: nothing is sent to the node before it (in force when > now).
            std::uint32_t cleanSends {0};     ///< 2xx sent after notBeforeSet since the last relaxation or 429.
            TimePoint lastDecreaseAt {};      ///< One decrease per burst: only a request sent after it decreases again.
            TimePoint lastSentAt {};          ///< Set by the choose filter when it takes the slot.
            std::uint64_t lastBatchBytes {0}; ///< The bytes of that batch (the Throttled hook's `b`).
            std::array<std::chrono::microseconds, LATENCY_RING> ring {}; ///< timings.total of every HTTP response.
            std::size_t ringSize {0};
            std::size_t ringNext {0};
            std::uint64_t decreases429 {0};
            std::uint64_t decreasesThrottled {0};
            std::uint64_t decreasesLatency {0};
            std::uint64_t increases {0};
            std::uint64_t paceRelaxed {0};
            std::uint64_t throttled {0}; ///< E5c: request-level 429 answers.
            std::uint64_t server5xx {0}; ///< E5c: HTTP answers with a 5xx status.
            LatencyHistogram latency;    ///< E5c: timings.total of every HTTP answer.
        };

        /// One request between its submit and its completion (for the cancellation of stop() and cancelBucket()).
        struct Flight final
        {
            std::uint64_t transferId {0}; ///< 0 until Transport::submit returned.
            /// I99 (N5): the batch's bucket (identity only; the Batch holds it strongly) and a cancelBucket() that ran
            /// before the id was known (the task cancels it right after the submit, as cancelNow for stop()).
            const Bucket* bucket {nullptr};
            bool cancelRequested {false};
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
                , paceRelaxAfter(std::max<std::uint32_t>(1, config.paceRelaxAfter))
                , latencyTarget(config.latencyTarget)
                , nodeWindowMax(std::max<std::uint32_t>(1, config.nodeWindowMax))
                , bulkMinBytes(std::max<std::uint64_t>(1, config.bulkMinBytes))
                , ambiguousRetryWindow(config.ambiguousRetryWindow)
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
                for (auto& slot : slots)
                {
                    slot.window = static_cast<double>(nodeWindowMax); // I96: the window starts at its maximum.
                }
                pinnedWaiting.resize(count);
            }

            const std::weak_ptr<WritePath> path;
            const std::shared_ptr<NodeSet> nodes;
            const std::shared_ptr<Transport> transport;
            asio::io_context& loop0;
            const Duration paceInitial;
            const Duration retryAfterMax;
            const std::uint32_t paceRelaxAfter;
            const Duration latencyTarget;
            const std::uint32_t nodeWindowMax;   ///< I98: the AIMD window's cap and start.
            const std::uint64_t bulkMinBytes;    ///< I98: the bulk target's floor.
            const Duration ambiguousRetryWindow; ///< I79: how long an ambiguous batch stays pinned to its node.
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
            /// I79: per node, the ordered buckets whose pinned batch found the node unusable (weak, deduplicated);
            /// taken when the node is usable again (wakePinned).
            std::vector<std::vector<std::weak_ptr<Bucket>>> pinnedWaiting;
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
            switch (cause)
            {
                case Cause::ClientClosed: result.reason = "dropped: the client was closed"; break;
                case Cause::Cancelled: result.reason = "dropped: cancelled by cancel(tag)"; break;
                default: result.reason = "dropped: the runtime is shutting down"; break;
            }
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

        /// ⌊window⌋, the requests the node may have in flight (I98).
        std::uint32_t windowSlots(const NodeSlot& slot)
        {
            return std::max<std::uint32_t>(1, static_cast<std::uint32_t>(slot.window));
        }

        /// The node takes a bulk now: not Down (mirror), no notBefore nor nextSendAt in force, a free slot of its
        /// window; the mutex held. The ONE predicate of capacity(), batchLimit(), the choose filter and wakePinned
        /// (D47).
        bool usableLocked(const SenderShared& shared, std::size_t node, TimePoint now)
        {
            const auto& slot = shared.slots[node];
            return !slot.down && slot.notBefore <= now && slot.nextSendAt <= now && slot.inFlight < windowSlots(slot);
        }

        /// p95 of the node's ring, sorted[⌈0.95·n⌉ − 1], or nullopt below LATENCY_MIN_SAMPLES (I98); the mutex held.
        std::optional<std::chrono::microseconds> p95Locked(const NodeSlot& slot)
        {
            if (slot.ringSize < LATENCY_MIN_SAMPLES)
            {
                return std::nullopt;
            }
            std::array<std::chrono::microseconds, LATENCY_RING> sorted = slot.ring;
            std::sort(sorted.begin(), sorted.begin() + static_cast<std::ptrdiff_t>(slot.ringSize));
            return sorted[(95 * slot.ringSize + 99) / 100 - 1];
        }

        /// I98 decrease (the caller checked «once per burst»): halves the window and the bulk target, `bytes` being the
        /// batch's (lastBatchBytes for the Throttled hook); the mutex held. The caller counts the origin.
        void decreaseLocked(const SenderShared& shared, NodeSlot& slot, std::uint64_t bytes, TimePoint now)
        {
            slot.window = std::max(1.0, slot.window / 2);
            const auto base = slot.bulkTarget != 0 ? std::min(slot.bulkTarget, bytes) : bytes;
            slot.bulkTarget = std::max(shared.bulkMinBytes, base / 2);
            slot.lastDecreaseAt = now;
        }

        /// I98 increase: window += 1 / window (cap nodeWindowMax); a capped bulk target grows by max(bulkMinBytes, a
        /// quarter) and is uncapped again at BULK_TARGET_UNCAPPED; the mutex held.
        void increaseLocked(const SenderShared& shared, NodeSlot& slot)
        {
            const auto max = static_cast<double>(shared.nodeWindowMax);
            if (slot.window >= max && slot.bulkTarget == 0)
            {
                return; // Nothing left to recover.
            }
            slot.window = std::min(max, slot.window + 1.0 / slot.window);
            if (slot.bulkTarget != 0)
            {
                slot.bulkTarget += std::max(shared.bulkMinBytes, slot.bulkTarget / 4);
                if (slot.bulkTarget >= BULK_TARGET_UNCAPPED)
                {
                    slot.bulkTarget = 0;
                }
            }
            ++slot.increases;
        }

        /// The buckets one wake-up of the scheduler announces (E6a, I109: one post per completion).
        using WakeList = std::vector<std::shared_ptr<Bucket>>;

        /// I79 (sender.hpp): for every node usable now, takes its pinnedWaiting list and tells each bucket that is
        /// still alive (Bucket::pinnedNodeUsable); those that ask for the scheduler are appended to `wake`, which the
        /// caller posts once. The sender's mutex is only held to take the lists: the buckets are called without it.
        void takePinned(const std::shared_ptr<SenderShared>& shared, WakeList& wake)
        {
            const auto now = std::chrono::steady_clock::now();
            std::vector<std::pair<std::size_t, std::vector<std::weak_ptr<Bucket>>>> taken;
            {
                std::lock_guard<std::mutex> lock(shared->mutex);
                if (shared->stopped)
                {
                    return;
                }
                for (std::size_t node = 0; node < shared->pinnedWaiting.size(); ++node)
                {
                    if (!shared->pinnedWaiting[node].empty() && usableLocked(*shared, node, now))
                    {
                        taken.emplace_back(node, std::exchange(shared->pinnedWaiting[node], {}));
                    }
                }
            }
            for (const auto& [node, buckets] : taken)
            {
                for (const auto& weak : buckets)
                {
                    auto bucket = weak.lock();
                    if (bucket && bucket->pinnedNodeUsable(node, now))
                    {
                        wake.push_back(std::move(bucket));
                    }
                }
            }
        }

        /// takePinned() alone (dispatch's pinned re-check): one Scheduler::notifyAll(buckets) when a bucket asked.
        void wakePinned(const std::shared_ptr<SenderShared>& shared)
        {
            WakeList wake;
            takePinned(shared, wake);
            if (wake.empty())
            {
                return;
            }
            auto path = shared->path.lock();
            if (auto scheduler = path ? path->scheduler() : nullptr)
            {
                scheduler->notifyAll(wake);
            }
        }

        /// Records `bucket` as waiting for `node` (pinned batch, node unusable); deduplicated, expired entries pruned.
        void addPinnedWaiting(SenderShared& shared, std::size_t node, const std::shared_ptr<Bucket>& bucket)
        {
            std::lock_guard<std::mutex> lock(shared.mutex);
            if (node >= shared.pinnedWaiting.size())
            {
                return;
            }
            auto& waiting = shared.pinnedWaiting[node];
            waiting.erase(std::remove_if(waiting.begin(),
                                         waiting.end(),
                                         [](const std::weak_ptr<Bucket>& entry) { return entry.expired(); }),
                          waiting.end());
            const bool known = std::any_of(waiting.begin(),
                                           waiting.end(),
                                           [&bucket](const std::weak_ptr<Bucket>& entry)
                                           { return !entry.owner_before(bucket) && !bucket.owner_before(entry); });
            if (!known)
            {
                waiting.push_back(bucket);
            }
        }

        /// The scheduler's single wake-up (E6a, I109): the pinned buckets whose node is usable (takePinned) and `wake`
        /// (the buckets a completion's requeues asked for) go in ONE Scheduler::notifyAll(buckets), i.e. one post,
        /// instead of a notify per requeue and per pinned bucket plus WritePath::sinkReady(). Deferring a requeue's
        /// notify costs nothing: every pass re-arms the timer of every bucket (a Backoff requeue's due included).
        void
        ready(const std::shared_ptr<SenderShared>& shared, const std::shared_ptr<WritePath>& path, WakeList wake = {})
        {
            takePinned(shared, wake);
            if (auto scheduler = path ? path->scheduler() : nullptr)
            {
                scheduler->notifyAll(wake);
            }
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

        /// Loop 0 only: (re)arms the timer at the earliest notBefore or nextSendAt in force (I98); a later one waits
        /// for the next arm.
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
                    for (const auto at : {slot.notBefore, slot.nextSendAt})
                    {
                        if (at > now && (!earliest || at < *earliest))
                        {
                            earliest = at;
                        }
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
                    ready(shared, shared->path.lock()); // A node whose wait ended may hold pinned batches.
                    armTimer(shared);                   // The next notBefore / nextSendAt still in force, if any.
                });
        }

        /// The NodeSet hook: mirrors every node's Down state from a consistent view (a hook from another thread may
        /// run late; the generation keeps an older view from overwriting a newer one), then wakes the scheduler.
        /// E6a (I109b): also raises each slot's notBefore to the NodeSet's (a 429 with Retry-After from any path) and
        /// arms the notBefore timer, so capacity() is 0 while the node is parked and the timer wakes the scheduler when
        /// it ends (no dispatch spin, no lost wake-up). The max() leaves the I98 pacing state alone: the burst marker
        /// (notBeforeSet) moves with the Throttled branch's pace doubling, not with notBefore.
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
            // Read under the NodeSet's mutex, before the sender's (the order NodeSet -> sender). It is only ever
            // raised, so a value read before another thread's report() merely lags; that report's caller mirrors it.
            std::vector<TimePoint> parked(view.nodes.size());
            for (std::size_t i = 0; i < parked.size(); ++i)
            {
                parked[i] = shared->nodes->notBefore(i);
            }
            bool arm = false;
            bool stale = false;
            {
                std::lock_guard<std::mutex> lock(shared->mutex);
                const auto now = std::chrono::steady_clock::now();
                for (std::size_t i = 0; i < shared->slots.size() && i < parked.size(); ++i)
                {
                    auto& slot = shared->slots[i];
                    if (parked[i] > slot.notBefore)
                    {
                        slot.notBefore = parked[i];
                        arm = arm || parked[i] > now;
                    }
                }
                stale = generation < shared->mirroredGeneration;
                if (!stale)
                {
                    shared->mirroredGeneration = generation;
                    for (std::size_t i = 0; i < shared->slots.size() && i < view.nodes.size(); ++i)
                    {
                        shared->slots[i].down = view.nodes[i].state == HealthView::NodeState::Down;
                    }
                }
            }
            if (arm)
            {
                postArm(shared);
            }
            if (stale || !wake)
            {
                return; // Stale: a newer view was already applied (and woke the scheduler).
            }
            ready(shared, shared->path.lock()); // A node no longer Down may hold pinned batches.
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
        /// No sender lock held. Returns the ops another resolution won first (skipped) plus those handed back closed:
        /// the late results of a completion with an HTTP answer (metrics.hpp LATE RESULTS).
        /// `deferred` (a completion's): the bucket goes there instead of a Scheduler::notify, posted by its ready().
        std::uint64_t requeueOps(SenderShared& shared,
                                 const std::shared_ptr<WritePath>& path,
                                 const std::shared_ptr<Bucket>& bucket,
                                 std::vector<RequeueOp> ops,
                                 const RequeueSpec& spec,
                                 WakeList* deferred = nullptr)
        {
            if (!bucket || ops.empty())
            {
                return 0;
            }
            auto result = bucket->requeue(std::move(ops), spec, std::chrono::steady_clock::now());
            const std::uint64_t late = result.skipped + result.closed.size();
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
                    // I99 (N1): the sweep's cause, so during stop() every resolution is Dropped(Shutdown).
                    const auto cause = bucket->sweepCause().value_or(Cause::Shutdown);
                    for (const auto& op : result.closed)
                    {
                        path->resolve(op, droppedResult(cause));
                    }
                }
                // I80: marked by cancel(tag); cancellation wins over exhaustion and close (bucket.hpp).
                for (const auto& op : result.cancelled)
                {
                    path->resolve(op, droppedResult(Cause::Cancelled));
                }
                if (result.notify)
                {
                    if (deferred)
                    {
                        deferred->push_back(bucket); // E6a (I109): one wake-up per completion, in its ready().
                    }
                    else if (auto scheduler = path->scheduler())
                    {
                        scheduler->notify(bucket);
                    }
                }
            }
            return late;
        }

        /// The whole batch back to the lane with the same last error; returns requeueOps' late results.
        std::uint64_t requeueBatch(SenderShared& shared,
                                   const std::shared_ptr<WritePath>& path,
                                   const Batch& batch,
                                   const LastError& error,
                                   const RequeueSpec& spec,
                                   WakeList* deferred = nullptr)
        {
            std::vector<RequeueOp> ops;
            ops.reserve(batch.ops.size());
            for (const auto& op : batch.ops)
            {
                ops.push_back(RequeueOp {op, error});
            }
            return requeueOps(shared, path, batch.bucket, std::move(ops), spec, deferred);
        }

        RequeueSpec spec(bool countAttempt, RequeueSpec::Delay delay, RequeueSpec::Pin pin = RequeueSpec::Pin::Keep)
        {
            RequeueSpec requeue;
            requeue.countAttempt = countAttempt;
            requeue.delay = delay;
            requeue.pin = pin;
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
            ready(shared, path);
        }

        /// Items verdict: one resolution or requeue per op, item i <-> op i.
        /// An HTTP response: the requeues clear the ambiguous pin (I79; ignored by unordered buckets).
        void applyItems(SenderShared& shared,
                        const std::shared_ptr<WritePath>& path,
                        const Batch& batch,
                        HttpResult& result,
                        WakeList* deferred)
        {
            constexpr auto clear = RequeueSpec::Pin::Clear;
            std::string reason;
            auto items = classifyItems(result.body, batch.ops.size(), &reason);
            // E5c: the ops whose resolution another one won (a sweep) or that come back closed (metrics.hpp).
            std::uint64_t late = 0;
            const auto countLate = [&batch, &late]()
            {
                if (late != 0 && batch.bucket)
                {
                    batch.bucket->countLate(late);
                }
            };
            if (!items)
            {
                late += requeueBatch(shared,
                                     path,
                                     batch,
                                     LastError {Cause::Server5xx,
                                                static_cast<int>(result.status),
                                                {},
                                                truncated(std::move(reason), OpResult::MAX_REASON)},
                                     spec(true, RequeueSpec::Delay::Backoff, clear),
                                     deferred);
                countLate();
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
                        if (path && !path->resolve(op, std::move(ok)))
                        {
                            ++late;
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
                        if (path && !path->resolve(op, std::move(failed)))
                        {
                            ++late;
                        }
                        break;
                    }
                }
            }
            late += requeueOps(
                shared, path, batch.bucket, std::move(retry), spec(true, RequeueSpec::Delay::Backoff, clear), deferred);
            countLate();
        }

        /// A completion that threw after the slot was released: what is still unresolved goes back to the lane with an
        /// attempt (requeue skips the ops already resolved). Never throws.
        void requeueAfterFailure(SenderShared& shared,
                                 const std::shared_ptr<WritePath>& path,
                                 const Batch& batch,
                                 std::string reason,
                                 WakeList* deferred) noexcept
        {
            try
            {
                requeueBatch(shared,
                             path,
                             batch,
                             LastError {Cause::InvalidState, 0, {}, truncated(std::move(reason), OpResult::MAX_REASON)},
                             spec(true, RequeueSpec::Delay::Backoff),
                             deferred);
            }
            catch (...)
            {
                // Nothing left to try: the ops stay delivered and the shutdown sweep resolves them.
            }
        }

        /// I105: the reason of an op failed Ambiguous.
        std::string ambiguousReason(int httpStatus)
        {
            return "ambiguous HTTP " + std::to_string(httpStatus) + " (not resent)";
        }

        /// FailBatch: resolves every op of the batch Failed(`cause`); the ops another resolution won count late (E5c,
        /// metrics.hpp LATE RESULTS). An Ambiguous one counts the ops it did resolve for the bucket's WARN (I105b),
        /// none when every op was late (a shutdown sweep won them all).
        void failBatch(const std::shared_ptr<WritePath>& path,
                       const Batch& batch,
                       Cause cause,
                       int httpStatus,
                       const std::string& reason)
        {
            if (!path)
            {
                return;
            }
            std::uint64_t late = 0;
            for (const auto& op : batch.ops)
            {
                OpResult failed;
                failed.status = Status::Failed;
                failed.cause = cause;
                failed.httpStatus = httpStatus;
                failed.reason = reason;
                if (!path->resolve(op, std::move(failed)))
                {
                    ++late;
                }
            }
            if (!batch.bucket)
            {
                return;
            }
            if (late != 0)
            {
                batch.bucket->countLate(late);
            }
            if (const auto resolved = batch.ops.size() - late; cause == Cause::Ambiguous && resolved != 0)
            {
                batch.bucket->countAmbiguous(httpStatus, resolved);
            }
        }

        /// A completion of an ambiguous 5xx under onAmbiguous5xx = Fail that threw: the batch is never resent, so what
        /// is still unresolved fails Ambiguous here instead of requeueAfterFailure. Never throws; if this fails too,
        /// the ops stay delivered and the shutdown sweep resolves them.
        void
        failAmbiguousAfterFailure(const std::shared_ptr<WritePath>& path, const Batch& batch, int httpStatus) noexcept
        {
            try
            {
                failBatch(path, batch, Cause::Ambiguous, httpStatus, ambiguousReason(httpStatus));
            }
            catch (...)
            {
                // Nothing left to try.
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
                const bool http = result.cause == TransportCause::None;
                const bool success = http && result.status >= 200 && result.status < 300;
                const std::chrono::microseconds latency {std::max<std::int64_t>(0, result.timings.total.count())};
                if (http)
                {
                    // HTTP responses only (429 included): a timeout or a cancellation would skew the latency.
                    ++slot.requests;
                    slot.totalMicros += static_cast<std::uint64_t>(latency.count());
                    slot.latency.observe(static_cast<std::uint64_t>(latency.count()));
                    if (result.status >= 500 && result.status < 600)
                    {
                        ++slot.server5xx;
                    }
                    if (sentAt > slot.lastDecreaseAt)
                    {
                        // Only the regime after the last decrease: a request still in flight when it happened would
                        // refill the emptied ring with the spike's samples and decrease again (G-diff obj. 1).
                        slot.ring[slot.ringNext] = latency;
                        slot.ringNext = (slot.ringNext + 1) % LATENCY_RING;
                        slot.ringSize = std::min(slot.ringSize + 1, LATENCY_RING);
                    }
                }
                else
                {
                    ++slot.failures; // I98: a transport failure is Down (CA-13), never a decrease.
                }
                // I98, in this order: the decrease (once per burst: only a request sent after the last one), then the
                // increase, which a decrease in the same completion excludes. Item rejections never get here.
                bool decreased = false;
                if (outcome.verdict == RequestVerdict::Throttled)
                {
                    // One burst of the window doubles the pace once: only a request that left after the burst marker
                    // (or before there was one) makes it grow.
                    if (!slot.notBeforeEverSet || sentAt > slot.notBeforeSet)
                    {
                        slot.pace = slot.pace.count() == 0 ? shared->paceInitial
                                                           : std::min(slot.pace * 2, shared->retryAfterMax);
                        // The burst marker moves with the doubling, not with notBefore: a park mirrored from a query
                        // or PIT 429 (refreshMirror) may already hold notBefore past now + wait (G-diff E6a obj. 1).
                        slot.notBeforeSet = now;
                        slot.notBeforeEverSet = true;
                    }
                    slot.cleanSends = 0;
                    if (sentAt > slot.lastDecreaseAt)
                    {
                        decreaseLocked(*shared, slot, batch.bytes, now);
                        ++slot.decreases429;
                        decreased = true;
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
                    ++slot.throttled;
                }
                if (http && !decreased && sentAt > slot.lastDecreaseAt)
                {
                    if (const auto p95 = p95Locked(slot); p95 && *p95 > shared->latencyTarget)
                    {
                        decreaseLocked(*shared, slot, batch.bytes, now);
                        slot.ringSize = 0; // A fresh ring: the slow samples cannot decrease twice (G-plan obj. 2).
                        slot.ringNext = 0;
                        ++slot.decreasesLatency;
                        decreased = true;
                    }
                }
                if (success)
                {
                    // I98 pacing: a 2xx of a request sent after the last notBeforeSet is a clean send; paceRelaxAfter
                    // of them halve the pace, 0 below paceInitial. A 2xx never shortens a notBefore or a nextSendAt.
                    if (slot.pace.count() > 0 && slot.notBeforeEverSet && sentAt > slot.notBeforeSet &&
                        ++slot.cleanSends >= shared->paceRelaxAfter)
                    {
                        slot.cleanSends = 0;
                        slot.pace /= 2;
                        if (slot.pace < shared->paceInitial)
                        {
                            slot.pace = Duration {0};
                        }
                        ++slot.paceRelaxed;
                    }
                    if (!decreased && sentAt > slot.lastDecreaseAt && latency < shared->latencyTarget)
                    {
                        increaseLocked(*shared, slot);
                    }
                }
                if (outcome.verdict == RequestVerdict::Split && http && result.status == 413)
                {
                    // I98: the node refused the payload; the next batches stay under half of it (not a decrease).
                    const auto half = std::max<std::uint64_t>(1, batch.bytes / 2);
                    slot.bulkTarget = slot.bulkTarget != 0 ? std::min(slot.bulkTarget, half) : half;
                }
                switch (outcome.verdict)
                {
                    case RequestVerdict::Failover: ++shared->counters.failovers; break;
                    case RequestVerdict::Split: ++shared->counters.splits; break;
                    default: break;
                }
            }
            if (batch.bucket)
            {
                // E5c: the bucket's bulk counters and latency, under its own mutex (never under the sender's).
                const bool http = result.cause == TransportCause::None;
                batch.bucket->countBulk(batch.bytes,
                                        http ? std::optional<std::uint64_t>(static_cast<std::uint64_t>(
                                                   std::max<std::int64_t>(0, result.timings.total.count())))
                                             : std::nullopt,
                                        http && result.status >= 200 && result.status < 300);
            }

            // I79 (sender.hpp): a completion with an HTTP response (a ResponseTooLarge included: the node answered)
            // clears the ambiguous pin; one without keeps it, except a Failover that may have sent, which pins the
            // batch of an ordered bucket to this node for ambiguousRetryWindow. Unordered buckets ignore the pin.
            const bool answered =
                result.cause == TransportCause::None || result.cause == TransportCause::ResponseTooLarge;
            const auto pin = answered ? RequeueSpec::Pin::Clear : RequeueSpec::Pin::Keep;

            auto path = shared->path.lock();
            WakeList wake; // E6a (I109): the requeues' notify, deferred to the single ready() below.
            // I105: the indexer may have applied this bulk; a bucket with onAmbiguous5xx = Fail resolves it
            // Failed(Ambiguous) instead of resending it. 503 stays Retry. Decided before the try (no allocation), so
            // an exception after it resolves instead of requeuing: a Fail batch is never resent (G-diff E6a obj. 4).
            const bool ambiguous = outcome.verdict == RequestVerdict::Retry && result.cause == TransportCause::None &&
                                   (result.status == 500 || result.status == 502 || result.status == 504) &&
                                   batch.bucket && batch.bucket->spec().onAmbiguous5xx == AmbiguousPolicy::Fail;
            // Past the slot release nothing may leave the batch unresolved: an exception (bad_alloc in a requeue or a
            // resolution, or the test seam) sends what is still unresolved back to the lane (G-diff E3b-2 obj. 6).
            try
            {
                seams::beforeCompletion();
                if (ambiguous)
                {
                    // Through the FailBatch block below, which also counts the WARN's ops (those it resolved).
                    outcome.verdict = RequestVerdict::FailBatch;
                    outcome.cause = Cause::Ambiguous;
                    outcome.reason = ambiguousReason(outcome.httpStatus);
                }
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
                                spec(false, RequeueSpec::Delay::Now),
                                &wake);
                        }
                        break;
                    case RequestVerdict::Failover:
                    {
                        shared->nodes->report(node, result);
                        auto failover = spec(outcome.mayHaveSent, RequeueSpec::Delay::Now, pin);
                        if (outcome.mayHaveSent && batch.bucket && batch.bucket->spec().ordered)
                        {
                            // D38: a Tls failure that may have sent pins too (one window per batch on that node).
                            failover.pin = RequeueSpec::Pin::Set;
                            failover.pinNode = node;
                            failover.pinUntil = now + shared->ambiguousRetryWindow;
                        }
                        requeueBatch(*shared, path, batch, error, failover, &wake);
                        break;
                    }
                    case RequestVerdict::Retry:
                        requeueBatch(*shared, path, batch, error, spec(true, RequeueSpec::Delay::Backoff, pin), &wake);
                        break;
                    case RequestVerdict::Throttled:
                        shared->nodes->report(node, result);
                        if (armNeeded)
                        {
                            postArm(shared);
                        }
                        requeueBatch(*shared, path, batch, error, spec(false, RequeueSpec::Delay::Now, pin), &wake);
                        break;
                    case RequestVerdict::Split:
                    {
                        auto split = spec(false, RequeueSpec::Delay::Now, pin);
                        split.toHead = true;
                        split.halve = true;
                        requeueBatch(*shared, path, batch, error, split, &wake);
                        break;
                    }
                    case RequestVerdict::FailBatch:
                        failBatch(path, batch, outcome.cause, outcome.httpStatus, outcome.reason);
                        break;
                    case RequestVerdict::Items: applyItems(*shared, path, batch, result, &wake); break;
                }
            }
            catch (const std::exception& e)
            {
                if (ambiguous)
                {
                    failAmbiguousAfterFailure(path, batch, result.status);
                }
                else
                {
                    requeueAfterFailure(
                        *shared, path, batch, std::string("bulk completion failed: ") + e.what(), &wake);
                }
            }
            catch (...)
            {
                if (ambiguous)
                {
                    failAmbiguousAfterFailure(path, batch, result.status);
                }
                else
                {
                    requeueAfterFailure(*shared, path, batch, "bulk completion failed: unexpected exception", &wake);
                }
            }
            // The slot is free (a bucket pinned to this node may go now): the completion's one wake-up.
            ready(shared, path, std::move(wake));
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
                        // stop() and cancelBucket() cancel it once its id is known.
                        shared->flights.emplace(flight, Flight {0, batch->bucket.get(), false});
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

                // I80 (sender.hpp): the ops cancel(tag) marked leave the batch (ops and bytes, so item i <-> op i
                // still holds) and resolve Dropped(Cancelled); no op of a cancelled tag is sent after cancel().
                // I99 (N5): so do the ops a sweep already resolved (claimed; awaitClosed's drain end), unresolved.
                seams::beforeAssembly();
                if (std::any_of(batch->ops.begin(),
                                batch->ops.end(),
                                [](const std::shared_ptr<OpState>& op)
                                { return op->cancelled.load() || op->claimed.load(); }))
                {
                    std::vector<std::shared_ptr<OpState>> kept;
                    std::vector<std::shared_ptr<OpState>> cancelled;
                    kept.reserve(batch->ops.size());
                    std::uint64_t bytes = 0;
                    for (auto& op : batch->ops)
                    {
                        if (op->claimed.load())
                        {
                            continue; // Resolved by a sweep: never sent.
                        }
                        if (op->cancelled.load())
                        {
                            cancelled.push_back(std::move(op));
                        }
                        else
                        {
                            bytes += op->wire();
                            kept.push_back(std::move(op));
                        }
                    }
                    batch->ops = std::move(kept);
                    batch->bytes = bytes;
                    auto path = shared->path.lock();
                    if (batch->ops.empty())
                    {
                        // Nothing left to send: the slot goes back (the catch must not give it back again).
                        admitted = true;
                        releaseSlot(*shared, node, flight);
                    }
                    if (path)
                    {
                        for (const auto& op : cancelled)
                        {
                            path->resolve(op, droppedResult(Cause::Cancelled));
                        }
                    }
                    if (batch->ops.empty())
                    {
                        ready(shared, path);
                        return;
                    }
                }

                std::uint64_t size = 0;
                for (const auto& op : batch->ops)
                {
                    size += op->wire();
                }
                auto body = std::make_shared<std::string>();
                body->reserve(size);
                for (const auto& op : batch->ops)
                {
                    appendWire(*body, op->headView(), op->body);
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
                        ready(shared, shared->path.lock());
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
                        // stop() or cancelBucket() ran before the id was known.
                        cancelNow = shared->stopped || it->second.cancelRequested;
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
                    [weak](std::size_t index, NodeSet::State /*from*/, NodeSet::State to)
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
                            // I98: a transition to Throttled decreases only when a bulk left after the last decrease
                            // (the bulk 429 that caused it already decreased; a probe or query 429 does here).
                            if (to == NodeSet::State::Throttled && index < shared->slots.size())
                            {
                                auto& slot = shared->slots[index];
                                if (slot.lastSentAt > slot.lastDecreaseAt)
                                {
                                    decreaseLocked(
                                        *shared, slot, slot.lastBatchBytes, std::chrono::steady_clock::now());
                                    ++slot.decreasesThrottled;
                                }
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
                for (std::size_t i = 0; i < m_shared->slots.size(); ++i)
                {
                    if (usableLocked(*m_shared, i, now))
                    {
                        // I98: a paced node takes one send per interval (G-plan obj. 16).
                        const auto& slot = m_shared->slots[i];
                        total += slot.pace.count() > 0 ? 1 : windowSlots(slot) - slot.inFlight;
                    }
                }
                return total;
            }

            std::uint64_t batchLimit() override
            {
                std::lock_guard<std::mutex> lock(m_shared->mutex);
                if (m_shared->stopped)
                {
                    return 0;
                }
                // I98: the smallest capped bulkTarget among the usable nodes; the node is chosen after the slice.
                const auto now = std::chrono::steady_clock::now();
                std::uint64_t limit = 0;
                for (std::size_t i = 0; i < m_shared->slots.size(); ++i)
                {
                    const auto target = m_shared->slots[i].bulkTarget;
                    if (target != 0 && usableLocked(*m_shared, i, now) && (limit == 0 || target < limit))
                    {
                        limit = target;
                    }
                }
                return limit;
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
                // I79 (sender.hpp): the ambiguous pin of an ordered bucket's batch. Every op of a pinned batch carries
                // the same pin (bucket.hpp); the ops are delivered, so only this sender touches it now.
                std::optional<std::size_t> pinNode;
                TimePoint pinUntil {};
                if (held->bucket && held->bucket->spec().ordered)
                {
                    for (const auto& op : held->ops)
                    {
                        if (op->pinNode)
                        {
                            pinNode = op->pinNode;
                            pinUntil = op->pinUntil;
                            break;
                        }
                    }
                }
                const bool pinned = pinNode && pinUntil > now;
                bool paced = false;
                if (!stopped && shared->nodes)
                {
                    // The filter runs under the NodeSet's mutex and takes the sender's (the allowed order); the slot
                    // is taken in the same step, so capacity() sees it at once. A pinned batch admits its node only.
                    // I98: taking the slot also sets the pacing (nextSendAt = now + pace), so the DRR cannot send a
                    // second batch to the node inside the interval before the pool task runs.
                    const auto bytes = held->bytes;
                    node = shared->nodes->choose(
                        [&shared, now, pinned, &pinNode, bytes, &paced](std::size_t index)
                        {
                            std::lock_guard<std::mutex> lock(shared->mutex);
                            if (index >= shared->slots.size() || (pinned && index != *pinNode) || shared->stopped ||
                                !usableLocked(*shared, index, now))
                            {
                                return false;
                            }
                            auto& slot = shared->slots[index];
                            ++slot.inFlight;
                            slot.lastSentAt = now;
                            slot.lastBatchBytes = bytes;
                            if (slot.pace.count() > 0)
                            {
                                slot.nextSendAt = now + slot.pace;
                                paced = true;
                            }
                            return true;
                        });
                }
                if (paced)
                {
                    armTimer(shared); // I98: loop 0; wakes the scheduler when nextSendAt ends.
                }
                if (!node && pinned && !stopped && shared->nodes)
                {
                    // The pinned node cannot take it: back to the lane until pinUntil, pin and last error kept; the
                    // bucket waits in pinnedWaiting[node] for the node to be usable again (mirror or notBefore timer).
                    // Recorded before the requeue and re-checked after it (with a fresh mirror, so a stale "not Down"
                    // cannot spin), so a node that becomes usable in between is never missed.
                    refreshMirror(shared, false);
                    addPinnedWaiting(*shared, *pinNode, held->bucket);
                    auto wait = spec(false, RequeueSpec::Delay::At, RequeueSpec::Pin::Keep);
                    wait.at = pinUntil;
                    requeueBatch(*shared, shared->path.lock(), *held, LastError {}, wait);
                    wakePinned(shared);
                    return;
                }
                if (node && pinNode && !pinned)
                {
                    // The window ended: any node was admitted and the pin is cleared (a batch still pinned keeps it,
                    // so a second ambiguous failure keeps the first `until`). Only a batch that leaves for another node
                    // is an ambiguous failover (BucketStats::orderedAmbiguousFailover).
                    for (const auto& op : held->ops)
                    {
                        op->pinNode.reset();
                        op->pinUntil = TimePoint {};
                    }
                    if (*node != *pinNode)
                    {
                        held->bucket->countAmbiguousFailover(held->ops.size());
                    }
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

            void cancelBucket(const Bucket& bucket) override
            {
                std::vector<std::uint64_t> toCancel;
                {
                    std::lock_guard<std::mutex> lock(m_shared->mutex);
                    if (m_shared->stopped)
                    {
                        return; // stop() cancelled everything already.
                    }
                    for (auto& [flight, state] : m_shared->flights)
                    {
                        if (state.bucket != &bucket)
                        {
                            continue;
                        }
                        if (state.transferId != 0)
                        {
                            toCancel.push_back(state.transferId);
                        }
                        else
                        {
                            state.cancelRequested = true; // The task cancels it right after its submit.
                        }
                    }
                }
                if (m_shared->transport)
                {
                    for (const auto id : toCancel)
                    {
                        m_shared->transport->cancel(id); // The completion is Ignore (Cancelled): the sweep resolved.
                    }
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
                    node.window = slot.window;
                    node.bulkTarget = slot.bulkTarget;
                    if (slot.nextSendAt > now)
                    {
                        node.nextSendAt = slot.nextSendAt;
                    }
                    if (const auto p95 = p95Locked(slot))
                    {
                        node.p95 = std::chrono::duration_cast<Duration>(*p95);
                    }
                    node.decreases429 = slot.decreases429;
                    node.decreasesThrottled = slot.decreasesThrottled;
                    node.decreasesLatency = slot.decreasesLatency;
                    node.increases = slot.increases;
                    node.paceRelaxed = slot.paceRelaxed;
                    node.throttled = slot.throttled;
                    node.server5xx = slot.server5xx;
                    node.latency = slot.latency;
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
