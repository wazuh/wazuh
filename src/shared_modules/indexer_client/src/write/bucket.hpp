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

#ifndef _INDEXER_CLIENT_WRITE_BUCKET_HPP
#define _INDEXER_CLIENT_WRITE_BUCKET_HPP

// A consumer's bucket (stage E3a, plan 18 I62/I63): quota with the real charge, the overflow policy, the pending queue
// and what the scheduler reads. Its mutex is never held while posting or running callbacks, while dropping a
// TicketState, or while taking any other lock, with one exception: GlobalBudget's waiter registry (add/removeWaiter),
// itself a leaf that is never held while a bucket mutex is taken. Normative contract:
// anexos/e2a-1/contrato-transport.md § Escritura.
//
// ORDERED BUCKETS (stage E3c-2, plan 18 I36/I75/I79; NORMATIVE). With BucketSpec::ordered:
//   - Keys: an op of a kind with `_id` carries keyHash = 64-bit hash of index + '\0' + _id (a collision only blocks too
//     much, never too little); ops without `_id` have no key and are never blocked. The retry lane keeps a multiset of
//     its ops' keys, updated on every insert/remove.
//   - One bulk in flight: while the delivered set is not empty the bucket is not eligible and nextDue is nullopt (the
//     completion wakes the scheduler through sinkReady; shutdown through the sweep).
//   - Blocked keys: those of the lane, those already taken into the batch being built, and those of pending ops
//     skipped earlier in the same scan. An op is TAKEABLE if it is the due lane head, or a pending op whose key is not
//     blocked. eligible() needs some takeable op (thresholds and maxAge measured as for any bucket); with nothing
//     takeable nextDue is the lane head's notBefore; the committed-group TimePoint::min() applies only when that head
//     is takeable. headBytes() = the first takeable op.
//   - slice(): the due lane first; then the pending queue in order, scanning at most bulk.maxDocs ops: blocked ones are
//     skipped (they keep their place), and the scan STOPS at the first takeable op that does not fit (credit, maxBytes,
//     maxDocs, batchCap).
//   - Ambiguous pin: requeue with RequeueSpec::Pin::Set gives every op of the batch the same {node, until} (a batch
//     whose ops are already pinned keeps their `until`, even an expired one: the sender clears an expired pin at
//     dispatch) and counts orderedAmbiguous per op; Pin::Keep leaves it; Pin::Clear removes it. So the window bounds
//     the time pinned from the FIRST ambiguous failure: with request_timeout >= window, a second timeout of the batch
//     on its node is an immediate failover, counted in orderedAmbiguousFailover. While
//     some lane op has pinUntil > now ("pinned"): eligible ⇔ the pinned ops are due, slice() takes exactly them
//     (nothing else joins), nextDue = their notBefore. pinnedNodeUsable(node, now) makes the ops pinned to `node` due
//     now.
// CANCELLATION (I25, I76–I78, I80; NORMATIVE): cancel(tag) removes the pending and lane ops with the tag (the caller
// resolves them Dropped(Cancelled)), sets `cancelled` on the delivered ones and registers one waiter {tag, remaining,
// ticket} if any is delivered. A requeue never puts a cancelled op back: it returns in RequeueResult::cancelled (also
// when it would be exhausted or closed: cancellation wins). The single decrement point is releasePayload: every waiter
// of the op's tag loses one, and those that reach 0 complete (success) after the mutex is dropped. A second cancel of a
// tag adds a second waiter. A bucket destroyed with waiters fails them ClientClosed. Groups still Building are out of
// reach (I76). Ops resolved Dropped(Cancelled) count in `cancelled` and in resolvedDropped.

#include <array>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "indexer_client/metrics.hpp"
#include "indexer_client/types.hpp"

namespace indexer_client::detail
{
    struct TicketState;
    struct GroupState;
    struct CancelState;
} // namespace indexer_client::detail

namespace indexer_client::detail::write
{
    class Bucket;
    class GlobalBudget;
    class WritePath;

    /// Fixed per-operation result reserve (I62): internal Op state, ticket state, callback slot and an OpResult with
    /// its strings at their caps. Fixed by measurement (ResultReserveMeasured, its regression guard), x 1.25 rounded up
    /// to a multiple of 64: E3a step 5 measured 1308.5 heap bytes per op besides its lines (1664); E3b-2 step 4b, with
    /// the retry state of E3b-1 in OpState, 1404.1 (a resolved op whose completion waits on the pool with a capped
    /// OpResult, its batch still held; an op requeued into the retry lane with its LastError at its caps keeps 1138.6;
    /// G-diff E3b-2, an op requeued with that LastError, re-sliced and then resolved like the first keeps 1396.7, since
    /// the resolution frees OpState::last*; 1992.7 without that) => 1755.1 => 1792; E3c-2 step 6b, with the tag, key
    /// and pin of E3c-2 in OpState, 1555.2 (an op of an ordered bucket with a 256-byte tag, pinned in the retry lane; a
    /// queued completion keeps 1516.0, since the resolution also frees OpState::tag) => 1944.0 => 1984. Registration
    /// requires bulk.maxBytes + RESULT_RESERVE <= quotaBytes.
    constexpr std::uint64_t RESULT_RESERVE = 1984;

    /// I79: the key of an op of an ordered bucket (OpState::keyHash), computed by whoever builds the OpState: 64-bit
    /// FNV-1a over `index`, one '\0' byte and `id`. Stable across runs, builds and platforms; a collision only blocks
    /// too much, never too little.
    std::uint64_t orderedKeyHash(std::string_view index, std::string_view id) noexcept;

    /// One admitted write. Created by the writer, owned by the bucket's queue, then by a Batch, then by its resolution.
    struct OpState final
    {
        std::string lines;           ///< Encoded NDJSON (encoding.hpp); its size is the wire size.
        std::uint64_t payload {0};   ///< Charged payload = lines.size(); released once, at resolution.
        bool reserveCharged {false}; ///< RESULT_RESERVE charged (released after the callback / last Ticket).
        /// The payload is in the bucket's custody: set by Bucket::enqueue, cleared when the payload is released
        /// (resolution or DropOldest eviction). Guarded by the bucket's mutex; makes releasePayload once-only.
        bool payloadCharged {false};
        std::shared_ptr<TicketState> ticket;
        Callback callback;
        std::atomic<bool> claimed {false}; ///< Resolution is first-wins (sink, sweep, eviction).
        std::uint32_t attempts {0};        ///< Counted retries (E3b-1 I66).
        TimePoint firstSubmit {};
        TimePoint firstAttempt {};  ///< Set by the first slice(): maxDuration counts from the first send (I66).
        TimePoint notBefore {};     ///< In the retry lane: not sent before this.
        std::uint64_t batchCap {0}; ///< After a split (413): a batch holding this op stays under it; 0 = no cap.
        /// The last error, for Failed(RetryExhausted) (I66). Written by Bucket::requeue under the bucket's mutex; the
        /// strings are freed when the op resolves (Bucket::releasePayload), so a resolved op whose completion waits on
        /// the pool does not keep them (RESULT_RESERVE).
        Cause lastCause {Cause::None};
        int lastHttpStatus {0};
        std::string lastItemErrorType;
        std::string lastReason;
        std::weak_ptr<Bucket> bucket;
        /// The effective ConflictPolicy is Retry (I73): a 409 item goes back to the retry lane. Set before enqueue,
        /// immutable afterwards (read lock-free by the sender).
        bool conflictRetry {false};
        /// The group this op belongs to (I74, group.hpp): strong, so its result slot exists at resolution; null for a
        /// plain submit. `groupIndex` = its add position.
        std::shared_ptr<GroupState> group;
        std::uint32_t groupIndex {0};
        /// Set by enqueue/enqueueGroup (per-bucket, monotonic): eligible() compares the pending head with flushSeq.
        std::uint64_t seq {0};
        /// Op::tag (E3c-2 I80), moved in by submit / Group::add; empty = none.
        std::string tag;
        /// Ordered buckets only (I79): the key's 64-bit hash; `hasKey` false for kinds without `_id` (never blocked).
        std::uint64_t keyHash {0};
        bool hasKey {false};
        /// I80: set under the bucket mutex by cancel(); read lock-free by the sender before it assembles a bulk.
        std::atomic<bool> cancelled {false};
        /// I79: the ambiguous pin, written under the bucket mutex by requeue and read by the sender once the op is in a
        /// batch (and cleared by it when the pin has expired at dispatch).
        std::optional<std::size_t> pinNode;
        TimePoint pinUntil {};
    };

    /// The error an op is requeued after (copied into OpState::last*; `cause == None` keeps the op's previous one).
    struct LastError final
    {
        Cause cause {Cause::None};
        int httpStatus {0};
        std::string itemErrorType;
        std::string reason;
    };

    struct RequeueOp final
    {
        std::shared_ptr<OpState> op;
        LastError lastError;
    };

    /// How a batch's ops go back to the retry lane (E3b-1 I66). E3b-2's uses: failover {mayHaveSent, Now}; request 429
    /// {false, Now} (the node waits; the batch may go to another node, I68); retryable error {true, Backoff}; split
    /// {false, Now, toHead, halve}.
    struct RequeueSpec final
    {
        enum class Delay
        {
            Backoff, ///< The bucket's RetryPolicy backoff for the op's (new) attempt count.
            At,      ///< `at`.
            Now
        };
        bool countAttempt {true};
        Delay delay {Delay::Backoff};
        TimePoint at {};
        bool toHead {false}; ///< Before every other lane op (a split's halves); implies Now (notBefore = now).
        bool halve {false};  ///< Sets batchCap = ceil(batch bytes / 2) on the requeued ops (413, ResponseTooLarge).
        /// I79 (ordered buckets; ignored otherwise): Keep leaves each op's pin; Set pins them all to `pinNode` until
        /// `pinUntil` (an op already pinned keeps its `until`; orderedAmbiguous += ops); Clear removes it. The sender
        /// uses Set for a Failover with mayHaveSent, Keep for any other completion without an HTTP response (and "no
        /// usable node"), Clear for every completion with one.
        enum class Pin
        {
            Keep,
            Set,
            Clear
        };
        Pin pin {Pin::Keep};
        std::size_t pinNode {0};
        TimePoint pinUntil {};
    };

    struct RequeueResult final
    {
        bool notify {false}; ///< The lane was empty or its head moved earlier: the caller notifies the scheduler.
        /// Retry budget spent: the caller resolves them Failed(RetryExhausted) with their last error. Still in the
        /// delivered set until resolved.
        std::vector<std::shared_ptr<OpState>> exhausted;
        /// exhaustedErrors[i] = exhausted[i]'s last error, copied under the bucket's mutex: a concurrent resolution
        /// (the shutdown sweep) frees OpState::last* under that mutex, so the caller never reads them unlocked.
        std::vector<LastError> exhaustedErrors;
        /// The bucket is closed (swept): the caller resolves them Dropped(sweepCause()). Still in the delivered set.
        std::vector<std::shared_ptr<OpState>> closed;
        /// Marked by cancel(tag) (I80): the caller resolves them Dropped(Cancelled). Still in the delivered set.
        std::vector<std::shared_ptr<OpState>> cancelled;
        /// E5c: ops skipped because they were already claimed or no longer delivered (another resolution won them):
        /// with `closed`, what a completion with an HTTP answer counts as late results (metrics.hpp LATE RESULTS).
        std::uint64_t skipped {0};
    };

    /// Outcome of Bucket::cancel (I80).
    struct CancelResult final
    {
        std::vector<std::shared_ptr<OpState>> removed; ///< Pending and lane ops of the tag: resolve Dropped(Cancelled).
        bool waiting {false}; ///< Some delivered op carries the tag: the ticket completes at the last resolution.
    };

    /// What the scheduler hands to the sink.
    struct Batch final
    {
        std::shared_ptr<Bucket> bucket;
        std::vector<std::shared_ptr<OpState>> ops;
        std::uint64_t bytes {0}; ///< Sum of the ops' wire sizes.
    };

    /// Outcome of Bucket::reserve.
    struct Reservation final
    {
        /// None = reserved (payload + reserve). QueueFull, SubmitTimeout, Reentrancy, ClientClosed, Shutdown,
        /// PayloadTooLarge = refused, nothing charged.
        Cause cause {Cause::None};
        /// DropNewest: the op is accepted but never enters; only the result reserve was charged when `withCallback`
        /// (nothing otherwise). The caller resolves it Dropped(QueueFull).
        bool dropNewest {false};
        /// DropOldest: pending ops evicted to make room (payload already released, RESULT_RESERVE still charged); the
        /// caller resolves each one Dropped(QueueFull) outside the bucket mutex. Evictions happen only when they make
        /// room for the new op; otherwise none is evicted and the op falls back to the DropNewest treatment.
        std::vector<std::shared_ptr<OpState>> evicted;
    };

    /// Per-bucket counters (I62, I74). Invariants: submitted = accepted + rejected* (+ invalidArgument); accepted =
    /// resolved + retained + groupBuilding. reserve() counts submitted and its outcome; countInvalidArgument() counts
    /// submitted too. A DropNewest drop and each DropOldest eviction are accepted (and droppedNewest / droppedOldest)
    /// and become resolved when the caller resolves them (countResolved); they are never retained. `retained` = ops
    /// enqueued whose payload is still charged (pending, delivered, or handed back by close() and not yet resolved).
    struct BucketStats final
    {
        std::string consumer;
        std::string bucket;
        std::uint64_t submitted {0};
        std::uint64_t accepted {0};
        std::uint64_t rejectedQueueFull {0};
        std::uint64_t rejectedClosed {0};
        std::uint64_t submitTimeout {0};
        std::uint64_t reentrancy {0};
        std::uint64_t payloadTooLarge {0};
        std::uint64_t invalidArgument {0};
        std::uint64_t droppedNewest {0};
        std::uint64_t droppedOldest {0};
        std::uint64_t rejectedGroupTooLarge {0}; ///< Group adds refused GroupTooLarge (E3c-1 I74; under `submitted`).
        std::uint64_t groupBuilding {0};         ///< Ops reserved by groups not committed yet (accepted, not retained).
        std::uint64_t groupAbandoned {0};        ///< Ops of abandoned groups (also counted resolvedDropped).
        std::uint64_t cancelled {0};             ///< Ops resolved Dropped(Cancelled) (also resolvedDropped; I80).
        std::uint64_t orderedAmbiguous {0};      ///< Ops pinned after an ambiguous failure (I79; per op and pin).
        std::uint64_t orderedAmbiguousFailover {
            0}; ///< Pinned ops sent to another node once the window ended (counted at dispatch).
        std::uint64_t resolvedOk {0};
        std::uint64_t resolvedFailed {0};
        std::uint64_t resolvedDropped {0};
        std::uint64_t retained {0}; ///< Pending + delivered to the sink, not yet resolved.
        std::uint64_t charge {0};   ///< Payload + reserves currently charged.
        std::uint64_t peakCharge {0};
        // E5c (metrics.hpp). rejectedShutdown is the Shutdown part of rejectedClosed; the arrays count resolutions
        // (countResolved) and requeues with a counted attempt (requeue) by cause.
        std::uint64_t rejectedShutdown {0};
        std::array<std::uint64_t, static_cast<std::size_t>(DropCause::Count)> dropped {};
        std::array<std::uint64_t, static_cast<std::size_t>(FailCause::Count)> failed {};
        std::array<std::uint64_t, static_cast<std::size_t>(RetryCause::Count)> retries {};
        std::uint64_t lateResults {0};
        std::uint64_t retainedBytes {0}; ///< Payload of the ops in custody (pending, lane, delivered).
        std::uint64_t bulkRequests {0};  ///< Completions of bulk requests of this bucket (any outcome).
        std::uint64_t bulkBytes {0};     ///< Their batches' bytes.
        LatencyHistogram latency;        ///< timings.total of those with an HTTP answer.
    };

    /// E5c (runtime/logSummary.hpp PERIODIC SUMMARY): what one bucket did in one summary interval, swapped out by
    /// Bucket::takeLogInterval().
    struct LogInterval final
    {
        /// One (cause, itemErrorType) of the unsuccessful resolutions (Failed and Dropped), first-come.
        struct Key final
        {
            Cause cause {Cause::None};
            std::string itemErrorType;
            std::uint64_t count {0};
        };
        std::vector<Key> keys;   ///< At most logging::SUMMARY_KEYS.
        std::uint64_t other {0}; ///< Unsuccessful resolutions whose key did not fit.
        std::uint64_t accepted {0};
        std::uint64_t ok {0};
        std::uint64_t failed {0};
        std::uint64_t dropped {0};
        /// The first non-empty reason of an unsuccessful resolution, truncated to logging::SAMPLE_REASON_MAX bytes
        /// (DEBUG only), with its key.
        std::string sampleReason;
        Cause sampleCause {Cause::None};
        std::string sampleItemErrorType;

        bool active() const noexcept
        {
            return accepted != 0 || ok != 0 || failed != 0 || dropped != 0 || !keys.empty();
        }
    };

    class Bucket final : public std::enable_shared_from_this<Bucket>
    {
    public:
        /// `owner`: the write path that owns `budget` (WritePath::registerClient); the ~Bucket net (I99, N6) returns
        /// charge only while it is alive. Empty for a bucket built directly (tests).
        Bucket(std::string consumer, BucketSpec spec, GlobalBudget& budget, std::weak_ptr<WritePath> owner = {});
        /// Fails the cancel(tag) waiters still registered with ClientClosed (I80). I99 (N6): asserts (debug) that
        /// nothing is queued; in release completes what is (tickets / group slots, Dropped(ClientClosed), no callback),
        /// returns its charge under `owner` and counts a usage error.
        ~Bucket();
        Bucket(const Bucket&) = delete;
        Bucket& operator=(const Bucket&) = delete;

        const BucketSpec& spec() const noexcept;
        const std::string& consumer() const noexcept;

        // ---- admission (producer threads; a Group uses reserveForGroup, then enqueueGroup or cancelGroupReservation)

        /// Charges `payload` + RESULT_RESERVE against the quota and the global cap with the bucket's policy (I62). For
        /// a DropNewest drop only RESULT_RESERVE is charged, and only when `withCallback` (QueueFull if even that does
        /// not fit; without a callback nothing is charged, so there is no reserve to release). Block waits until room,
        /// close/shutdown or `blockUntil`; from a runtime thread a submit that would wait returns Reentrancy instead. A
        /// charge that can never fit (payload > bulk.maxBytes, charge > quotaBytes or > the global cap) is
        /// PayloadTooLarge. A closed bucket refuses with its close cause. Counts its outcome. The global cap is
        /// reserved with GlobalBudget::tryReserve (lock-free) under the bucket mutex; anything that releases or wakes
        /// runs after it is dropped.
        Reservation reserve(std::uint64_t payload, bool withCallback, TimePoint blockUntil);

        /// Appends an op already reserved; returns true when the scheduler must be told (the bucket went from empty to
        /// non-empty or crossed bulk.maxBytes / bulk.maxDocs, with >=) and the dedup flag was clear. Sets
        /// `payloadCharged`, `bucket` (when unset) and `firstSubmit` (when unset, to now).
        /// E5b (I99, N2): with the ADMISSION closed it refuses instead — takes custody without queuing (payloadCharged,
        /// retained, seq) and sets `*closed` (the sweep's cause if close() ran, else the admission's); the caller
        /// resolves only that op through WritePath::resolve, never close(). Every caller passes `closed`.
        bool enqueue(std::shared_ptr<OpState> op, std::optional<Cause>* closed = nullptr);

        /// Group::add (I74, group.hpp): charges `payload` + RESULT_RESERVE for an op of a Building group that already
        /// holds `groupReserved`. In order: closed ⇒ its cause (rejectedClosed); payload > bulk.maxBytes or the charge
        /// alone above the quota or the global cap ⇒ PayloadTooLarge; groupReserved + charge above the quota or the
        /// global cap ⇒ GroupTooLarge (rejectedGroupTooLarge); fits ⇒ charged; otherwise Reject, DropNewest and
        /// DropOldest ⇒ QueueFull with nothing evicted (I70), and Block ⇒ Reentrancy from a runtime thread, QueueFull
        /// at once when charge + building (this bucket's) > quotaBytes or charge + GlobalBudget::building() > the cap
        /// (the room is held by Building groups: never wait on one, 03 §4.13), else waits like reserve() re-checking
        /// that condition on every wake-up (SubmitTimeout at blockUntil). A charged op adds to `building` (bucket and
        /// global) and to groupBuilding, and wakes the bucket's blocked producers and, after the mutex is dropped, the
        /// global waiters (their building condition may now hold). Counts submitted and its outcome. Never returns
        /// dropNewest/evicted.
        Reservation reserveForGroup(std::uint64_t payload, std::uint64_t groupReserved, TimePoint blockUntil);
        /// Group commit (I74): appends `ops` (reserved by reserveForGroup, `reserved` bytes in all) under one lock like
        /// enqueue, takes `reserved` out of `building` (bucket and global) and groupBuilding, gives each op the next
        /// seq and sets flushSeq to the last; returns true when the scheduler must be told: ALWAYS unless the dedup
        /// flag was already set (the group leaves now, whatever the thresholds); false for an empty `ops` (nothing to
        /// flush; the `reserved` bytes still leave `building`). Closed: as enqueue (`closed`).
        bool enqueueGroup(std::vector<std::shared_ptr<OpState>> ops,
                          std::uint64_t reserved,
                          std::optional<Cause>* closed = nullptr);
        /// Group abandonment (I74): returns `reserved` bytes (payload + reserves of `ops` Building ops) to the charge,
        /// `building` (bucket and global) and the global cap, counts them groupAbandoned and resolvedDropped (out of
        /// groupBuilding) and wakes the blocked producers (the global ones after the mutex is dropped).
        void cancelGroupReservation(std::uint64_t reserved, std::uint32_t ops);

        // ---- ordered buckets and cancellation (E3c-2; see the header comment)

        /// cancel(tag): `ticket` is registered as a waiter when `waiting`; otherwise the caller completes it at once.
        /// The caller notifies the scheduler when something was removed (an ordered bucket's gate or keys may have
        /// lifted).
        CancelResult cancel(const std::string& tag, const std::shared_ptr<CancelState>& ticket);
        /// The sender saw `node` usable again: the lane ops pinned to it become due now. True when the caller must
        /// notify the scheduler (some op changed).
        bool pinnedNodeUsable(std::size_t node, TimePoint now);
        /// `ops` pinned ops went to another node once their window ended. Counted at dispatch, before the pool task: a
        /// batch dropped there (refused, cancelled-empty) still counts.
        void countAmbiguousFailover(std::uint64_t ops);
        /// Counts `ops` resolutions Dropped(Cancelled) (the caller resolves them through WritePath::resolve).
        void countCancelled(std::uint64_t ops);

        // ---- scheduler (loop 0 only)

        /// Some threshold reached at `now`: the retry-lane head is due (notBefore <= now), pending bytes >= maxBytes,
        /// pending docs >= maxDocs, the oldest pending op older than maxAge, or the pending head committed by a group
        /// (seq <= flushSeq, I74).
        bool eligible(TimePoint now) const;
        /// Wire size of the next op a slice at `now` would take (due lane head first, else the pending head); 0 if
        /// none.
        std::uint64_t headBytes(TimePoint now) const;
        /// No pending op and an empty retry lane.
        bool empty() const;
        /// When this bucket next needs a pass: min(oldest pending + maxAge, retry-lane head notBefore), or "now" while
        /// the pending head is a committed group's (seq <= flushSeq) — returned as TimePoint::min(), which every `now`
        /// reaches (Scheduler::armTimer arms no timer and reports it due); nullopt if empty.
        std::optional<TimePoint> nextDue(TimePoint now) const;
        /// Takes whole ops, the due retry lane first and then the pending queue (one batch may mix both), while their
        /// wire bytes fit in `credit`, bulk.maxBytes, bulk.maxDocs, `cap` (the sink's batchLimit, 0 = none; I98) and
        /// the smallest batchCap of the ops taken; at least one op if `credit >= headBytes(now)` (`cap` never refuses
        /// the first op). Sets firstAttempt (when unset) to `now`. The ops move to the delivered set (counted as
        /// retained).
        Batch slice(std::uint64_t credit, TimePoint now, std::uint64_t cap = 0);

        // ---- retry lane (E3b-1 I66; any thread, one lock per call)

        /// Moves delivered ops back to the retry lane (ahead of the pending queue, ordered by notBefore) per `spec`, or
        /// returns them as exhausted / closed; skips ops already claimed and ops not in the delivered set. Every op
        /// handled takes `lastError` into OpState::last* (one with `cause == None` keeps the op's previous last error).
        /// Charge unchanged (RF-12). Exhausted: attempts >= maxAttempts or now - firstAttempt >= maxDuration (an unset
        /// bound never exhausts). A Backoff jitter is drawn once per call, so the ops of one batch stay together.
        RequeueResult requeue(std::vector<RequeueOp> ops, const RequeueSpec& spec, TimePoint now);
        /// Clears the dedup flag set by enqueue (the scheduler consumed the notification).
        void clearNotified() noexcept;

        // ---- resolution and close (any thread)

        /// Releases an op's payload (once per op) and wakes blocked producers; an op still in the retry lane leaves it.
        /// Also frees the op's last-error strings (under the mutex Bucket::requeue writes them with). Called by the
        /// resolution path, after it won the op's claim.
        void releasePayload(OpState& op);
        /// Releases `count` RESULT_RESERVEs (after the callback ran, when the last Ticket died, or when a committed
        /// group's GroupState died).
        void releaseReserve(std::uint32_t count = 1);
        /// Stops admission with `cause` (ClientClosed or Shutdown; the first close fixes the cause), wakes every
        /// blocked producer and returns the retry lane and then the pending ops (not those delivered to the sink) for
        /// the caller to resolve Dropped(cause). Callable again: each call hands back what is queued then. Their
        /// payload stays charged until the resolution releases it.
        std::vector<std::shared_ptr<OpState>> close(Cause cause);
        /// E5b (I99): closes only the admission with `cause` (reserve / reserveForGroup / enqueue / enqueueGroup refuse
        /// with it; blocked producers wake), sets flushSeq = nextSeq - 1 so every pending op is eligible now, and keeps
        /// the bucket draining: requeue retries as usual. Idempotent (the first cause stays). close() also sets it.
        void closeAdmission(Cause cause);
        /// The admission cause (closeAdmission or close), or nullopt while the bucket admits (what submit reports).
        std::optional<Cause> closedCause() const;
        /// The cause close() fixed (the sweep), or nullopt: RequeueResult::closed ops are resolved Dropped(sweepCause).
        std::optional<Cause> sweepCause() const;
        /// BucketStats::retained alone (awaitClosed's drain predicate, I99 N4).
        std::uint64_t retained() const;
        /// Snapshot of the ops delivered to the sink and not yet resolved (the shutdown sweep resolves them).
        std::vector<std::shared_ptr<OpState>> delivered() const;
        /// Wakes the producers blocked in this bucket (called by GlobalBudget::wakeWaiters, holding no other lock).
        void wakeWaiters();

        /// One resolution (WritePath::resolve; the writer's DropNewest without callback): resolved* and, by `cause`,
        /// failed[] / dropped[] (metrics.hpp; an unlisted Failed cause counts in invalid_state, Failed(PayloadTooLarge)
        /// — a single-op 413 — in client_4xx). E5c: an unsuccessful one also counts in the interval's
        /// (cause, itemErrorType) keys, and the first `reason` of the interval is kept as its DEBUG sample.
        void
        countResolved(Status status, Cause cause, std::string_view itemErrorType = {}, std::string_view reason = {});
        void countInvalidArgument();
        /// E5c: `ops` ops of a completion with an HTTP answer resolved late (metrics.hpp LATE RESULTS).
        void countLate(std::uint64_t ops);
        /// E5c: one completed bulk request of this bucket (`bytes` of batch); `latencyMicros` only with an HTTP answer.
        /// `success` (a 2xx answer) re-arms the ambiguous edge (I105).
        void countBulk(std::uint64_t bytes, std::optional<std::uint64_t> latencyMicros, bool success);
        /// I105: a bulk answered `httpStatus` (500/502/504) that the sender fails Ambiguous without resending
        /// (onAmbiguous5xx = Fail); `ops` is how many of its ops it resolved Failed(Ambiguous) (never 0: the late ones,
        /// won by another resolution, are not counted and a bulk whose ops were all late is not reported). The first
        /// one after a 2xx bulk of this bucket (or since its creation) logs one WARN; the next 2xx re-arms it
        /// (countBulk). Called with no lock held; emits the line itself.
        void countAmbiguous(int httpStatus, std::uint64_t ops);
        BucketStats stats() const;
        /// The metrics of this bucket (metrics.hpp BucketMetrics), read under the bucket mutex.
        BucketMetrics metrics() const;
        /// BucketStats::retainedBytes alone (RuntimeRef::snapshot()'s sum).
        std::uint64_t retainedBytes() const;

        // ---- E5c logs (runtime/logSummary.hpp)

        /// The interval since the previous call (keys, totals, sample), reset under the bucket mutex.
        LogInterval takeLogInterval();
        /// Emits the quota-edge lines decided under the bucket mutex, then the global cap's
        /// (GlobalBudget::emitPendingLogs). Never called with a bucket mutex held: reserve() and reserveForGroup()
        /// call it once theirs is dropped, the log summary's timer drains it too. One atomic load when nothing waits.
        void emitPendingLogs() noexcept;

    private:
        /// What tryChargeLocked did: charged, or which cap refused (the bucket's quota is checked first).
        enum class Charge : std::uint8_t
        {
            Ok,
            BucketFull,
            GlobalFull
        };
        /// Charges `charge` locally and globally if both fit; m_mutex held.
        Charge tryChargeLocked(std::uint64_t charge);
        /// The DropNewest treatment of a new op (also DropOldest's fallback); m_mutex held.
        void dropNewestLocked(bool withCallback, Reservation& reservation);
        /// DropOldest: evicts the fewest oldest pending ops that make room; false (nothing evicted) if none do.
        /// `globalSurplus` = evicted payload not reused by the new op, to release after the mutex is dropped.
        bool evictOldestLocked(std::uint64_t charge, Reservation& reservation, std::uint64_t& globalSurplus);
        void addChargeLocked(std::uint64_t bytes) noexcept;
        /// E5c quota edges, m_mutex held: the 80 % edge when the charge reaches it armed, the re-arm when the charge
        /// crosses 70 % downwards from `before` (chargeMovedLocked), and the full edge on an overflow (overflowLocked)
        /// only when this bucket's quota refused (`refused` == BucketFull): a global-cap refusal is the global edge's
        /// (GlobalBudget::tryReserve). A line is only queued (m_edgeLines); emitPendingLogs() writes it.
        void chargeMovedLocked(std::uint64_t before);
        void overflowLocked(Charge refused);
        /// The retry-lane head is due at `now`; m_mutex held.
        bool laneDueLocked(TimePoint now) const;
        /// min(oldest pending + maxAge, retry-lane head notBefore), TimePoint::min() for a committed group's head;
        /// the ordered rules of the header comment when spec().ordered; m_mutex held.
        std::optional<TimePoint> nextDueLocked(TimePoint now) const;
        /// Takes `op` into the bucket's custody (firstSubmit, bucket, payloadCharged, seq, retained); m_mutex held.
        void takeCustodyLocked(OpState& op, TimePoint now);
        /// What a refused enqueue reports: the sweep's cause if close() ran, else the admission's; m_mutex held.
        std::optional<Cause> refusalCauseLocked() const;
        /// Inserts a non-toHead op into the retry lane by notBefore (stable); m_mutex held.
        void insertLaneLocked(std::shared_ptr<OpState> op);

        // Ordered buckets (I79); m_mutex held. Every op entering the lane goes through laneAddedLocked and every op
        // leaving it through laneRemovedLocked (cancel() and pinnedNodeUsable() too), which keep m_laneKeys and
        // m_lanePinned.
        void laneAddedLocked(const OpState& op);
        void laneRemovedLocked(const OpState& op);
        /// The key of `op` is in the lane.
        bool laneBlocksLocked(const OpState& op) const;
        /// The lane's pinned ops at `now` (pinNode set and pinUntil > now).
        struct PinScan
        {
            bool pinned {false};    ///< Some lane op is pinned: the pin gate governs the bucket.
            bool due {false};       ///< Some pinned op has notBefore <= now.
            TimePoint next {};      ///< min(notBefore, pinUntil) over the pinned ops.
            std::uint64_t head {0}; ///< Wire size of the first due pinned op (lane order).
        };
        PinScan pinScanLocked(TimePoint now) const;
        /// Index of the first takeable pending op (key not in the lane) among the first bulk.maxDocs ones.
        std::optional<std::size_t> firstTakeablePendingLocked() const;
        bool orderedEligibleLocked(TimePoint now) const;
        std::uint64_t orderedHeadBytesLocked(TimePoint now) const;
        std::optional<TimePoint> orderedNextDueLocked(TimePoint now) const;

        const std::string m_consumer;
        const BucketSpec m_spec;
        GlobalBudget& m_budget;
        const std::weak_ptr<WritePath> m_owner; ///< Keeps m_budget alive for the ~Bucket net (N6).

        mutable std::mutex m_mutex;
        std::condition_variable m_room;
        std::deque<std::shared_ptr<OpState>> m_pending;
        std::deque<std::shared_ptr<OpState>> m_lane; ///< Retry lane, ordered by notBefore (toHead ops first).
        std::unordered_map<const OpState*, std::shared_ptr<OpState>> m_delivered; ///< Removed by releasePayload.
        std::uint64_t m_pendingBytes {0};
        std::uint64_t m_charge {0};
        std::uint64_t m_building {0}; ///< Charge held by Building groups (I74).
        std::uint64_t m_nextSeq {1};
        std::uint64_t m_flushSeq {0}; ///< The last op of the last committed group (I74).
        std::uint32_t m_waiting {0};
        std::optional<Cause> m_closed;    ///< close(): the sweep (requeue hands ops back as closed).
        std::optional<Cause> m_admission; ///< closeAdmission() or close(): submit refuses (E5b, I99).
        std::atomic<bool> m_notified {false};
        /// Ordered buckets (I79): multiset of the lane ops' keys (hash -> count; ops without a key are not in it).
        std::unordered_map<std::uint64_t, std::uint32_t> m_laneKeys;
        std::size_t m_lanePinned {0}; ///< Ordered buckets: lane ops with pinNode set (expired pins included).
        /// I80: one per cancel(tag) that found delivered ops of its tag. It counts the ops of `tag` that were delivered
        /// at registration (all with seq < seqLimit, all marked); releasePayload decrements it for a marked op of
        /// `tag` with seq < seqLimit (ops of the tag enqueued after the cancel have a later seq and never count).
        struct CancelWaiter
        {
            std::string tag;
            std::uint64_t seqLimit {0};
            std::uint64_t remaining {0};
            std::shared_ptr<CancelState> ticket;
        };
        std::vector<CancelWaiter> m_cancelWaiters;
        BucketStats m_stats;

        // E5c logs (runtime/logSummary.hpp), guarded by m_mutex except m_edgePending (set under it, read without it).
        enum class Edge : std::uint8_t
        {
            Quota80,
            Full,
            Ambiguous ///< I105: `charge` holds the ops of the bulk, `httpStatus` its status.
        };
        struct EdgeLine final
        {
            Edge edge {Edge::Quota80};
            std::uint64_t charge {0};
            int httpStatus {0};
        };
        const std::uint64_t m_threshold80; ///< 80 % and 70 % of quotaBytes, rounded down.
        const std::uint64_t m_threshold70;
        bool m_armed80 {true};
        bool m_armedFull {true};
        bool m_armedAmbiguous {true}; ///< I105: cleared by countAmbiguous, set by a 2xx bulk (countBulk).
        std::vector<EdgeLine> m_edgeLines;
        std::atomic<bool> m_edgePending {false};
        LogInterval m_interval; ///< Keys and sample of the current interval (totals come from m_logMark).
        struct LogMark final
        {
            std::uint64_t accepted {0};
            std::uint64_t ok {0};
            std::uint64_t failed {0};
            std::uint64_t dropped {0};
        };
        LogMark m_logMark; ///< The totals at the previous takeLogInterval().
    };
} // namespace indexer_client::detail::write

#endif // _INDEXER_CLIENT_WRITE_BUCKET_HPP
