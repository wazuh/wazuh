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

#ifndef _INDEXER_CLIENT_WRITE_SENDER_HPP
#define _INDEXER_CLIENT_WRITE_SENDER_HPP

// The bulk sender (stage E3b-2, plan 18 I68): the production BatchSink. NORMATIVE — the plan points here for the
// detail.
//
// State per node, under the sender's mutex: inFlight, notBefore, pace, Down (mirrored from NodeSet::onTransition,
// initially Down), and request/latency counters. Lock order: the NodeSet's mutex may take the sender's (the filter of
// NodeSet::choose); the sender never calls NodeSet, Bucket, WritePath, Scheduler or Transport with its mutex held, and
// never drops OpState/TicketState references under it.
//
// Limiter (stage E5a, plan 18 I98), per node under the same mutex: window (real, [1, nodeWindowMax], starts at
// nodeWindowMax, I96; a Down -> Available transition keeps it), bulkTarget (bytes, 0 = uncapped, the start),
// nextSendAt, cleanSends, lastDecreaseAt, lastSentAt, lastBatchBytes and a ring of the last 32 timings.total of the
// HTTP responses (429 included) of requests sent after lastDecreaseAt (a request in flight at a decrease never refills
// the ring).
//   usable(node, now) = !down ∧ notBefore <= now ∧ nextSendAt <= now ∧ inFlight < ⌊window⌋ — the ONE predicate of
//     capacity(), the choose filter and wakePinned (D47).
//   capacity(): Σ over the usable nodes of ⌊window⌋ − inFlight, or 1 for a node with pace > 0 (one send per interval).
//   batchLimit(): the smallest capped bulkTarget among the usable nodes (0 = none); the scheduler passes it to
//     Bucket::slice as `cap` (never applied to the first op of a batch).
//   Pacing: the choose filter, when it takes the slot, sets lastSentAt = now, lastBatchBytes and, with pace > 0,
//     nextSendAt = now + pace; dispatch() then calls armTimer directly (it is on loop 0). The timer fires at the
//     earliest notBefore / nextSendAt in force.
//   Decrease, once per burst: a request 429, or p95 of the ring (n >= 8, sorted[⌈0.95·n⌉ − 1]) > latencyTarget, of a
//     request with sentAt > lastDecreaseAt; or the NodeSet's transition to Throttled (hook) when lastSentAt >
//     lastDecreaseAt (the bulk 429 that caused it already decreased; a probe or query 429 does). Then
//     window = max(1, window / 2), bulkTarget = max(bulkMinBytes, (bulkTarget ? min(bulkTarget, b) : b) / 2) with b the
//     batch's bytes (lastBatchBytes for the hook), lastDecreaseAt = now; a latency decrease also empties the ring, so
//     a spike costs one halving: the next p95 sees only requests sent after it.
//     Counted per origin (decreases429, decreasesThrottled, decreasesLatency). Never on item rejections nor on
//     transport failures (those are Down, CA-13).
//   Increase: a 2xx with sentAt > lastDecreaseAt, latency < latencyTarget and no decrease in the same completion (the
//     decrease is evaluated first) ⇒ window += 1 / window (cap nodeWindowMax) and, when capped,
//     bulkTarget += max(bulkMinBytes, bulkTarget / 4); reaching BULK_TARGET_UNCAPPED makes it 0 again.
//   413 (Split): besides the split, bulkTarget = min(bulkTarget or ∞, bytes / 2); the window and the decrease counters
//     are untouched.
//   Queries never take a window slot (I95, D50).
//
// dispatch(batch), loop 0: NodeSet::choose(usable) and inFlight++ before
// leaving loop 0; no node ⇒ the Down mirror refreshed from the NodeSet (the hook may still be on its way, and a stale
// mirror would keep capacity() > 0), then Bucket::requeue {countAttempt = false, Now} with lastError {Unavailable,
// "no usable node"} (+ Scheduler::notify when asked) and return.
// Then, on the CPU pool: the lines concatenated into one shared_ptr<const string> (POST {host}/_bulk,
// Content-Type: application/json) and Transport::submit with a callback. EVERY exit of that task without a callback
// gives the slot back (inFlight--, then sinkReady): a refusal for Shutdown (admission, or the pool refusing the task
// after stop()) leaves the ops to the sweep; any other refusal, seams::refuseSubmit(), or an exception ⇒ requeue
// {true, Backoff} with lastError {InvalidState, reason} and stats.submitRefused++; an exception after the transport
// admitted the transfer leaves the slot to its callback. A sender already stopped when it dispatches, or found stopped
// by the task before the submit, requeues the batch {false, Now} with lastError {InvalidState, "sender stopped before
// the submit"}: during a runtime shutdown the bucket is closed, so it comes back `closed` ⇒ Dropped(Shutdown); after a
// setSink it waits in the lane for the new sink. A requeue whose lastError has cause None keeps the op's previous one.
//
// Completion (CPU pool), in this order: inFlight-- and the node's 429 state under the mutex, release it, then
// NodeSet::report / Bucket::requeue / WritePath::resolve / sinkReady. An exception in that second part requeues what
// is still unresolved {true, Backoff} with lastError {InvalidState, reason}, and sinkReady() still runs.
// classifyRequest verdicts:
//   Ignore     Shutdown: nothing (the sweep resolves). Cancelled with the sender already stopped (its stop() cancelled
//              it): requeue {false, Now} with lastError {Cancelled}, no attempt; after a setSink no sweep follows, so
//              the batch waits in the lane for the new sink (a closed bucket hands it back `closed` ⇒ Dropped).
//   Failover   NodeSet::report(node, result) + requeue {mayHaveSent, Now}; stats.failovers++.
//   Retry      requeue {true, Backoff}. stats.retries counts every requeue with a counted attempt (this one, a failover
//              with mayHaveSent, a refused submit, an unreadable 2xx, item Retry).
//   Throttled  NodeSet::report + node notBefore = max(notBefore, now + max(Retry-After or 0, pace)); pace starts at
//              RuntimeConfig.paceInitial and doubles (capped at retryAfterMax) only for a 429 whose request left after
//              the node's current notBefore was set (one burst of the window doubles it once); cleanSends = 0; then
//              requeue {false, Now} (the batch may go to another node); stats.throttled++.
//   Split      requeue {false, Now, toHead, halve}; stats.splits++.
//   FailBatch  every op Failed(cause, httpStatus, reason).
//   Items      classifyItems(body, n, &reason): nullopt ⇒ requeue {true, Backoff} with lastError {Server5xx, the 2xx
//              status, that reason}; per item:
//              Ok / NotFound ⇒ Ok with its outcome; Conflict ⇒ by the op's effective policy (OpState::conflictRetry,
//              E3c-1 I73): Success ⇒ Ok keeping 409 and the type, Retry ⇒ requeue {true, Backoff} with lastError
//              {VersionConflict, 409, type, reason}; item Retry ⇒ requeue {true, Backoff} with the item's error; both
//              kinds of requeue in one call for the batch; Permanent ⇒ Failed(ItemPermanent, status, type, reason).
// A 2xx of a request sent after the node's notBefore was last set counts a clean send; paceRelaxAfter clean sends halve
// the pace (cleanSends = 0) and a pace below paceInitial becomes 0. A 2xx NEVER shortens a notBefore or a nextSendAt in
// force. RequeueResult.exhausted ⇒
// Failed(RetryExhausted) with the op's last error; RequeueResult.closed ⇒ Dropped(sweepCause); RequeueResult.notify ⇒
// Scheduler::notify(bucket). Every completion ⇒ WritePath::sinkReady().
//
// Ordered buckets and cancellation (E3c-2, I79/I80; the bucket side is in bucket.hpp):
//   - Assembly: the pool task first removes from the Batch (ops and bytes) every op whose `cancelled` is set, resolving
//     each Dropped(Cancelled) (seams::beforeAssembly() runs just before this check); an emptied batch gives its slot
//     back (inFlight--, sinkReady) and returns without a submit. No op of a cancelled tag is sent after cancel().
//   - Pin at dispatch: when a batch's ops carry pinNode (they all carry the same pin, bucket.hpp) and pinUntil > now,
//     the choose filter admits pinNode alone; without it the batch is requeued {false, At(pinUntil), Pin::Keep} and the
//     bucket is recorded in pinnedWaiting[pinNode] (weak); when that node becomes usable again (the Down mirror clears,
//     or its notBefore timer fires) the sender calls Bucket::pinnedNodeUsable(node, now) for each recorded bucket and
//     Scheduler::notify when it says so. With pinUntil <= now any node is admitted; the ops' pin is cleared and
//     Bucket::countAmbiguousFailover(ops) runs.
//     [E3c-2 step 4 precisions] The pinned node is "usable" per usable(node, now) of the Limiter block (the choose
//     filter's predicate), so a completion or a released slot also wakes pinnedWaiting (a full window would otherwise
//     wait until pinUntil). The bucket is recorded before the requeue and the node re-checked
//     after it, with the mirror refreshed. A batch sent to its pinned node inside the window keeps its pin (a second
//     ambiguous failure keeps the first `until`); an expired pin is cleared only when some node takes the batch, and
//     countAmbiguousFailover counts only when that node is another one. "With an HTTP response" includes
//     ResponseTooLarge (the node answered).
//   - Pin at completion: Failover with mayHaveSent in an ordered bucket ⇒ requeue {mayHaveSent, Now, Pin::Set, node,
//     now + RuntimeConfig.ambiguousRetryWindow}; a Failover without it and "no usable node" ⇒ Pin::Keep; every
//     completion with an HTTP response ⇒ Pin::Clear. Unordered buckets ignore the pin. A Tls failure with mayHaveSent
//     is a Failover and pins too (D38: a misconfigured mTLS node costs one window per batch before the failover).
//   - RequeueResult::cancelled ⇒ resolve Dropped(Cancelled) (also after an attempt that would have exhausted).
//
// Wake-ups: a loop-0 asio timer at the earliest notBefore / nextSendAt in force, armed by a post from a completion
// (capturing the shared state and checking `stopped`, the Prober's pattern) or directly by dispatch() (loop 0), firing
// sinkReady(); the NodeSet::onTransition hook (registered by start(),
// which the runtime calls BEFORE prober->start()) mirrors Down and calls sinkReady() through a weak_ptr<WritePath>.
//
// stop(): idempotent; sets `stopped`, cancels every transfer in flight (Transport::cancel), drops the timer on loop 0
// (directly when already on loop 0, else post + wait). Results that arrive later are Ignore or lose to the sweep
// (resolution is first-wins). WritePath::setSink stops the sink it replaces: its cancelled transfers come back as
// Cancelled completions and their batches go back to the lane (Ignore above). The destructor counts a usage error only
// if the timer was armed and stop() never ran.

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "indexer_client/runtimeConfig.hpp"
#include "indexer_client/types.hpp"
#include "write/sink.hpp"

namespace asio
{
    class io_context;
} // namespace asio

namespace indexer_client::detail
{
    class NodeSet;
    class Transport;
} // namespace indexer_client::detail

namespace indexer_client::detail::write
{
    /// A bulk target at or above it is uncapped again (I98). The max of bulk_min_bytes stays below it (static_assert in
    /// config/runtimeConfig.cpp).
    constexpr std::uint64_t BULK_TARGET_UNCAPPED = 64ull << 20;
    /// Latency samples per node (I98).
    constexpr std::size_t LATENCY_RING = 32;
    /// Samples needed before the p95 decides (I98).
    constexpr std::size_t LATENCY_MIN_SAMPLES = 8;

    struct SenderNodeStats final
    {
        std::string host;
        bool down {true};
        std::uint32_t inFlight {0};
        std::optional<TimePoint> notBefore; ///< In force (later than now) only.
        Duration pace {Duration {0}};
        std::uint64_t requests {0};    ///< Completed bulk requests with an HTTP response (cause None; any status).
        std::uint64_t totalMicros {0}; ///< Sum of those responses' HttpResult timings.total (E5's AIMD).
        std::uint64_t failures {0};    ///< Completions without a response (timeout, connect, TLS, cancelled...).
        // Limiter (E5a, I98).
        double window {0};                   ///< Real AIMD window; ⌊window⌋ requests may be in flight.
        std::uint64_t bulkTarget {0};        ///< Bytes; 0 = uncapped.
        std::optional<TimePoint> nextSendAt; ///< In force (later than now) only.
        Duration p95 {Duration {0}};         ///< Of the current ring (0 below LATENCY_MIN_SAMPLES).
        std::uint64_t decreases429 {0};
        std::uint64_t decreasesThrottled {0};
        std::uint64_t decreasesLatency {0};
        std::uint64_t increases {0};
        std::uint64_t paceRelaxed {0};
    };

    struct SenderStats final
    {
        std::uint64_t sent {0}; ///< Bulk requests submitted.
        std::uint64_t failovers {0};
        std::uint64_t splits {0};
        std::uint64_t throttled {0}; ///< Request-level 429.
        std::uint64_t retries {0};   ///< Requeues with a counted attempt.
        std::uint64_t submitRefused {0};
        std::uint64_t exhausted {0};
        std::vector<SenderNodeStats> nodes;
    };

    class BulkSink : public BatchSink
    {
    public:
        /// `config` gives the hosts' order, paceInitial, paceRelaxAfter, retryAfterMax, latencyTarget, nodeWindowMax
        /// and bulkMinBytes.
        static std::shared_ptr<BulkSink> create(std::weak_ptr<WritePath> path,
                                                std::shared_ptr<NodeSet> nodes,
                                                std::shared_ptr<Transport> transport,
                                                asio::io_context& loop0,
                                                const RuntimeConfig& config);

        /// Registers the NodeSet::onTransition hook. The runtime calls it before prober->start().
        virtual void start() = 0;

        virtual SenderStats stats() const = 0;
    };

    /// The running runtime's sender statistics (empty when no runtime or when a test replaced the sink).
    SenderStats senderStats();
} // namespace indexer_client::detail::write

#endif // _INDEXER_CLIENT_WRITE_SENDER_HPP
