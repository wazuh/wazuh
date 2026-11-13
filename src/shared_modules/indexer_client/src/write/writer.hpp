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

#ifndef _INDEXER_CLIENT_WRITE_WRITER_HPP
#define _INDEXER_CLIENT_WRITE_WRITER_HPP

// The write path of a runtime: admission through the writer, the buckets of every client,
// the global cap, the scheduler, the sink and the single resolution path.
//
// Close. NORMATIVE.
//   requestClose(): marks the client, wakes its queries and blocked producers (ClientClosed) and closes only the
//     ADMISSION of its buckets (Bucket::closeAdmission: flushSeq = nextSeq - 1, so everything pending is eligible now,
//     plus Scheduler::notify). The buckets stay in the DRR ring and keep draining: a requeue retries as usual (only
//     Bucket::close() hands ops back as closed). Never blocks; any thread.
//   submit / post against the close: Bucket::admit reserves and appends under ONE take of the bucket's mutex, so
//     there is no window between the two: an op either was queued before closeAdmission (and drains like any other)
//     or is refused with the close cause (nothing charged, never resolved, no callback); every submit / post that
//     starts after requestClose() returns is refused ClientClosed. The reservation→append window (refused at the
//     append, custody without queuing, resolved Dropped(cause) by the caller alone) exists only for a group, which
//     reserves at add() and appends at commit() (Bucket::enqueueGroup). A post staged in a stripe is admitted
//     by the seal of every close entry before the admission closes (bucket.hpp STAGING), so it drains like any other.
//   awaitClosed(D), consumer threads only, serialized per client (ClientState::closeMutex; a concurrent call waits for
//     the first one; a later one sweeps nothing, waits for the completions until its own D, moves the cutoff to now
//     again and returns the live counters, so callbacksSkipped, callbackOverruns and drained may have grown):
//     left = max(0, D - now);
//     left >= 2 * callbackBudget ⇒ drainEnd = D - 2 * callbackBudget, cutoff = D - callbackBudget; else
//     drainEnd = now + left / 2, cutoff = now + 3 * left / 4. Waits (ClientState::drainDone, notified by every
//     resolution of one of its ops) until Σ retained of its buckets is 0 (pending + lane + delivered) or drainEnd. The
//     drain honours the node pace, notBefore and the bucket backoff. A resolution is counted (drained,
//     dropped*) and its completion is outstanding before it stops being retained (WritePath::resolve), so a drain
//     that ends with Σ retained = 0 leaves no completion behind the second wait. At drainEnd: close(ClientClosed) ⇒
//     pending and lane Dropped(ClientClosed); delivered ⇒ Dropped(Shutdown) and BatchSink::cancelBucket (outside a
//     runtime shutdown, where transport->stop bounds them) — except a delivered op whose answer reaches the requeue
//     between close() and the sweep's resolution of it: the bucket hands it back closed and it ends
//     Dropped(ClientClosed) (first-wins; either way it is counted once, in droppedClientClosed + droppedShutdown).
//     Then waits for the completions until D and sets the client's cutoff to now. The sweep and cancelBucket run
//     outside completionsMutex.
//   CloseReport::drained counts the resolutions after requestClose() that are not Dropped(ClientClosed) or
//     Dropped(Shutdown) (those come only from a sweep, a refused group commit or a requeue into a closed bucket), so
//     drained + droppedClientClosed + droppedShutdown covers every op resolved after requestClose().
//   Callback cutoff: CallbackCompletion::run takes ClientState::completionsMutex, compares now with
//     min(client cutoff, WritePath::callbackCutoff()), marks itself started (or skipped) and releases it before
//     calling; awaitClosed moves the cutoff under the same mutex before reading the started-not-finished count, which
//     is CloseReport::callbacksInFlight. Past the cutoff the ticket is completed, the result is counted in the bucket
//     and the callback is not called (callbacksSkipped + 1): a consumer that needs every result at close keeps its
//     Ticket or reads callbacksSkipped > 0 as "results unknown". Lock order: completionsMutex -> bucket mutex.
//   Every callback is timed: > callbackBudget ⇒ callbackOverruns + 1 and callbackMaxDuration (the metrics publish
//   them). A Client destroyed on a runtime thread (or discarded by move-assignment there) keeps the old behaviour:
//     requestClose() plus the immediate sweep (closeClient(client, true)), so a usage error never loses a result; the
//     consumer name is released only when the ClientState dies (releaseName is awaitClosed's).
//   stop(callbackCutoff): sets WritePath::callbackCutoff first; during stop() every resolution is Dropped(Shutdown)
//     (Bucket::sweepCause()); the admission cause stays ClientClosed for submit.

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <vector>

#include "indexer_client/client.hpp"
#include "indexer_client/runtimeConfig.hpp"
#include "write/bucket.hpp"
#include "write/budget.hpp"
#include "write/encoding.hpp"
#include "write/scheduler.hpp"
#include "write/sink.hpp"

namespace indexer_client::detail
{
    struct ClientState;
    class NodeSet;
    class Transport;
} // namespace indexer_client::detail

namespace indexer_client::detail::write
{
    struct WriteStats final
    {
        std::uint64_t globalCharge {0};
        std::uint64_t globalCap {0};
        std::vector<BucketStats> buckets;
    };

    class WritePath final : public std::enable_shared_from_this<WritePath>
    {
    public:
        /// `postToPool` runs a task on the CPU pool (false once the pool stopped accepting).
        WritePath(std::uint64_t globalCap, std::function<bool(std::function<void()>)> postToPool);

        /// Created after the runtime threads exist (needs loop 0); installs and starts the production sink, the bulk
        /// sender, whose start() registers the NodeSet hook: the runtime calls this before prober->start().
        /// Without a NodeSet or a transport the sink is makeUnavailableSink (defensive; the runtime always has both).
        void start(asio::io_context& loop0,
                   const RuntimeConfig& config,
                   std::shared_ptr<NodeSet> nodes,
                   std::shared_ptr<Transport> transport);

        /// Creates the client's buckets (owned by its ClientState) and registers them weakly for the scheduler.
        void registerClient(const std::shared_ptr<ClientState>& client);

        GlobalBudget& budget() noexcept;
        /// The action lines shared by the ops of this write path (encoding.hpp HeadTable); lives as long as
        /// the write path, which outlives every reader of a line (the runtime joins its pool first).
        HeadTable& heads() noexcept;
        std::shared_ptr<Scheduler> scheduler() const;
        std::shared_ptr<BatchSink> sink() const;
        /// Tests (component suite) install a programmable sink; production never calls it after start().
        void setSink(std::shared_ptr<BatchSink> sink);
        /// The sink has capacity again: the scheduler runs a pass.
        void sinkReady();
        /// Runs `task` on the CPU pool (the bulk sender's assembly and submit). False, without running it, once
        /// stop() finished or the pool refused it.
        bool postToPool(std::function<void()> task);

        /// The single resolution path, first-wins on OpState::claimed. `bucket` is the op's, passed by the
        /// caller, which always holds it strongly (the Batch's, the writer's, the bucket being swept or requeued),
        /// or null for an op whose bucket died (a group committed after its bucket died, D66b/D67b): the op keeps no
        /// reference to its bucket. Then: releases the payload once, counts the status and
        /// posts the completion to the pool (ticket completed, then the callback under a guard that releases the
        /// result reserve even if it throws; without a callback the reserve dies with the last Ticket), counted in the
        /// client's outstandingCompletions before the payload is released (never retained-free yet not
        /// outstanding). An op of a group (OpState::group) has neither: it goes to
        /// resolveInGroup (group.hpp) instead, no pool task, and then drops its GroupState reference. Returns false
        /// when the op was already resolved.
        bool resolve(const std::shared_ptr<Bucket>& bucket, const std::shared_ptr<OpState>& op, OpResult result);

        /// Resolve() for every item of one bulk of `bucket` (each op the bucket's), with ONE take of the
        /// bucket mutex per SETTLE_CHUNK ops and one GlobalBudget::release per chunk instead of two takes and one
        /// release per op. In order: claims every op (first-wins; a lost claim is a late result); an op that is
        /// not of post (a ticket, a callback or a group) or is cancelled is resolved by itself right there, as
        /// resolve() does; then per chunk the client's accounting (droppedClientClosed / droppedShutdown, drained when
        /// closeRequested is set at that point, as resolve() reads it before its release), Bucket::settleBulk, and the
        /// touch of completionsMutex + drainDone. A throw (the seam midBulkSettle, an allocation) still settles every
        /// op claimed for the bulk before it escapes (RAII, noexcept), so none stays claimed and retained. The
        /// afterPayloadReleased seam stays in resolve(). Returns how many ops it won (late = items - won). Items are
        /// left moved-from.
        std::uint64_t resolveBulk(const std::shared_ptr<Bucket>& bucket, std::vector<BulkItem>& items);

        /// requestClose(): closes the ADMISSION of the client's buckets (ClientClosed; blocked producers wake),
        /// makes their pending ops eligible and notifies the scheduler; they keep draining. With `sweep` (a Client
        /// destroyed on a runtime thread) it also closes them and resolves pending and lane Dropped(ClientClosed) at
        /// once; delivered ops keep their course.
        void closeClient(ClientState& client, bool sweep = false);

        /// awaitClosed's sweep at drainEnd: close(ClientClosed) and resolve pending and lane
        /// Dropped(ClientClosed), delivered Dropped(Shutdown), then BatchSink::cancelBucket for the buckets that had
        /// delivered ops when `cancelTransfers` (outside a runtime shutdown). Returns the resolutions it won (none of
        /// them is part of CloseReport::drained). Never called under completionsMutex.
        std::uint64_t sweepClient(ClientState& client, bool cancelTransfers);

        /// Shutdown, in stopAndJoin before the prober: close every bucket (Shutdown; blocked producers wake) → stop the
        /// scheduler → sink.stop() → resolve every unresolved op (pending and delivered) Dropped(Shutdown) while the
        /// pool still accepts. Idempotent. `callbackCutoff` (stopDeadline - callbackBudget) is set first, so the
        /// completions the pool still runs afterwards only complete tickets past it.
        void stop(std::optional<TimePoint> callbackCutoff = std::nullopt);

        /// The runtime-wide callback cutoff set by stop() (TimePoint::max() until then).
        TimePoint callbackCutoff() const
        {
            return TimePoint(TimePoint::duration(m_callbackCutoff.load()));
        }

        WriteStats stats() const;
#ifdef INDEXER_CLIENT_TESTING
        /// Test-only: flushes the stripes of every bucket now and notifies the scheduler, so a case
        /// reads the snapshot right after its posts.
        void flushStaged();
        /// Test-only: the live bucket registered at `raw` (an OpState::owner), or null when none is: never
        /// dereferences `raw`, so a dead owner is not undefined behaviour.
        std::shared_ptr<Bucket> liveBucket(const Bucket* raw) const;
#endif
        /// Σ BucketStats::retainedBytes of the live buckets (MetricsSnapshot::retainedBytes).
        std::uint64_t retainedBytes() const;

    private:
        /// resolve() once the claim is won: `bucket` is the op's (null: it died).
        void resolveWon(const std::shared_ptr<Bucket>& bucket, OpState& op, OpResult result);
        void forEachBucket(const std::function<void(const std::shared_ptr<Bucket>&)>& fn) const;
        /// Closes `bucket` with `cause` (idempotent) and resolves what is still pending Dropped(cause).
        void sweepClosed(const std::shared_ptr<Bucket>& bucket, Cause cause);

        GlobalBudget m_budget;
        HeadTable m_heads;
        std::function<bool(std::function<void()>)> m_postToPool;
        mutable std::mutex m_mutex; ///< Guards the members below (never held while calling into a bucket or the sink).
        std::vector<std::weak_ptr<Bucket>> m_buckets;
        std::shared_ptr<Scheduler> m_scheduler;
        std::shared_ptr<BatchSink> m_sink;
        bool m_stopped {false};
        /// Set at the end of stop(): later completions run inline (the pool may be gone with its runtime).
        std::atomic<bool> m_poolDetached {false};
        /// Stop()'s callback cutoff, as TimePoint ticks (max until stop()).
        std::atomic<TimePoint::rep> m_callbackCutoff {TimePoint::max().time_since_epoch().count()};
    };

    /// The writer bound to one bucket of one client (Client::writer). submit / post: effective conflict policy +
    /// encode (InvalidArgument, Submit::reason / Posted::reason) → the OpState built outside any lock (one clock read)
    /// → Bucket::admit, reserve and append under one take of the bucket's mutex (+ Scheduler::notify) or the
    /// drop/refusal; post creates no Ticket and returns its RESULT_RESERVE at the resolution. group(): a Building group
    /// of this bucket (group.hpp). cancel(tag): Bucket::cancel and the resolution of what it removes (bucket.hpp).
    std::shared_ptr<IWriter>
    makeWriter(std::shared_ptr<ClientState> client, std::shared_ptr<Bucket> bucket, std::shared_ptr<WritePath> path);

    /// The running runtime's write path, or null (internal users and the component suite).
    std::shared_ptr<WritePath> runtimeWritePath();
    /// Snapshot of the running runtime's write counters (empty when no runtime).
    WriteStats writeStats();
} // namespace indexer_client::detail::write

#endif // _INDEXER_CLIENT_WRITE_WRITER_HPP
