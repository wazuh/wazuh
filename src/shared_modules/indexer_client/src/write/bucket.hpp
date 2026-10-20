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

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "indexer_client/types.hpp"

namespace indexer_client::detail
{
    struct TicketState;
} // namespace indexer_client::detail

namespace indexer_client::detail::write
{
    class Bucket;
    class GlobalBudget;

    /// Fixed per-operation result reserve (I62): internal Op state, ticket state, callback slot and an OpResult with
    /// its strings at their caps. Fixed by the measurement of E3a step 5: at most 1308.5 heap bytes per op besides its
    /// lines (a resolved op whose completion waits on the pool with a capped OpResult, its batch still held), x 1.25 =
    /// 1636, rounded up to a multiple of 64. ResultReserveMeasured is its regression guard; re-measured in E3b when
    /// OpState grows. Registration requires bulk.maxBytes + RESULT_RESERVE <= quotaBytes.
    constexpr std::uint64_t RESULT_RESERVE = 1664;

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
        std::uint32_t attempts {0};        ///< E3b.
        TimePoint firstSubmit {};
        std::weak_ptr<Bucket> bucket;
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

    /// Per-bucket counters (I62). Invariants: submitted = accepted + rejected* (+ invalidArgument); accepted = resolved
    /// + retained. reserve() counts submitted and its outcome; countInvalidArgument() counts submitted too. A
    /// DropNewest drop and each DropOldest eviction are accepted (and droppedNewest / droppedOldest) and become
    /// resolved when the caller resolves them (countResolved); they are never retained. `retained` = ops enqueued whose
    /// payload is still charged (pending, delivered, or handed back by close() and not yet resolved).
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
        std::uint64_t resolvedOk {0};
        std::uint64_t resolvedFailed {0};
        std::uint64_t resolvedDropped {0};
        std::uint64_t retained {0}; ///< Pending + delivered to the sink, not yet resolved.
        std::uint64_t charge {0};   ///< Payload + reserves currently charged.
        std::uint64_t peakCharge {0};
    };

    class Bucket final : public std::enable_shared_from_this<Bucket>
    {
    public:
        Bucket(std::string consumer, BucketSpec spec, GlobalBudget& budget);

        const BucketSpec& spec() const noexcept;
        const std::string& consumer() const noexcept;

        // ---- admission (producer threads; E3c's Group uses reserve and enqueue separately)

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
        /// `payloadCharged`, `bucket` (when unset) and `firstSubmit` (when unset, to now). A closed bucket still takes
        /// the op (it is charged and must not be lost): the caller checks the close cause (`closed`, read under the
        /// same lock, or closedCause()) and, if closed, calls close() again to take it back and resolve it.
        bool enqueue(std::shared_ptr<OpState> op, std::optional<Cause>* closed = nullptr);

        // ---- scheduler (loop 0 only)

        /// Some threshold reached at `now`: pending bytes >= maxBytes, pending docs >= maxDocs, or the oldest pending
        /// op older than maxAge. E3b extends it (retry lane, backoff).
        bool eligible(TimePoint now) const;
        std::optional<TimePoint> oldestPending() const;
        std::uint64_t headBytes() const; ///< Wire size of the next pending op; 0 when empty.
        bool empty() const;
        /// Takes whole ops from the head while their wire bytes fit in `credit`, bulk.maxBytes and bulk.maxDocs; at
        /// least one op if `credit >= headBytes()`. The ops move to the delivered set (counted as retained).
        Batch slice(std::uint64_t credit);
        /// Clears the dedup flag set by enqueue (the scheduler consumed the notification).
        void clearNotified() noexcept;

        // ---- resolution and close (any thread)

        /// Releases an op's payload (once per op) and wakes blocked producers. Called by the resolution path.
        void releasePayload(OpState& op);
        /// Releases one RESULT_RESERVE (after the callback ran, or when the last Ticket died).
        void releaseReserve();
        /// Stops admission with `cause` (ClientClosed or Shutdown; the first close fixes the cause), wakes every
        /// blocked producer and returns the pending ops (not those delivered to the sink) for the caller to resolve
        /// Dropped(cause). Callable again: each call hands back what is pending then. Their payload stays charged
        /// until the resolution releases it.
        std::vector<std::shared_ptr<OpState>> close(Cause cause);
        /// The close cause, or nullopt while the bucket admits.
        std::optional<Cause> closedCause() const;
        /// Snapshot of the ops delivered to the sink and not yet resolved (the shutdown sweep resolves them).
        std::vector<std::shared_ptr<OpState>> delivered() const;
        /// Wakes the producers blocked in this bucket (called by GlobalBudget::wakeWaiters, holding no other lock).
        void wakeWaiters();

        void countResolved(Status status);
        void countInvalidArgument();
        BucketStats stats() const;

    private:
        /// Charges `charge` locally and globally if both fit; m_mutex held.
        bool tryChargeLocked(std::uint64_t charge);
        /// The DropNewest treatment of a new op (also DropOldest's fallback); m_mutex held.
        void dropNewestLocked(bool withCallback, Reservation& reservation);
        /// DropOldest: evicts the fewest oldest pending ops that make room; false (nothing evicted) if none do.
        /// `globalSurplus` = evicted payload not reused by the new op, to release after the mutex is dropped.
        bool evictOldestLocked(std::uint64_t charge, Reservation& reservation, std::uint64_t& globalSurplus);
        void addChargeLocked(std::uint64_t bytes) noexcept;

        const std::string m_consumer;
        const BucketSpec m_spec;
        GlobalBudget& m_budget;

        mutable std::mutex m_mutex;
        std::condition_variable m_room;
        std::deque<std::shared_ptr<OpState>> m_pending;
        std::unordered_map<const OpState*, std::shared_ptr<OpState>> m_delivered; ///< Removed by releasePayload.
        std::uint64_t m_pendingBytes {0};
        std::uint64_t m_charge {0};
        std::uint32_t m_waiting {0};
        std::optional<Cause> m_closed;
        std::atomic<bool> m_notified {false};
        BucketStats m_stats;
    };
} // namespace indexer_client::detail::write

#endif // _INDEXER_CLIENT_WRITE_BUCKET_HPP
