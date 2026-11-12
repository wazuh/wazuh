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

#include "write/bucket.hpp"

#include <algorithm>
#include <chrono>
#include <exception>
#include <thread>
#include <unordered_set>
#include <utility>

#include "indexer_client/runtime.hpp"
#include "loggerHelper.h"
#include "runtime/backoff.hpp"
#include "runtime/logSummary.hpp"
#include "runtime/runtimeInternal.hpp"
#include "transport/seams.hpp"
#include "write/budget.hpp"
#include "write/group.hpp"

namespace indexer_client::detail::write
{
    namespace
    {
        constexpr const char* TAG = "indexer-client";

        /// `percent` % of `value`, rounded down, without overflow.
        constexpr std::uint64_t percentOf(std::uint64_t value, std::uint64_t percent) noexcept
        {
            return value / 100 * percent + value % 100 * percent / 100;
        }

        const char* overflowName(Overflow::Kind kind) noexcept
        {
            switch (kind)
            {
                case Overflow::Kind::Reject: return "reject";
                case Overflow::Kind::Block: return "block";
                case Overflow::Kind::DropNewest: return "drop_newest";
                case Overflow::Kind::DropOldest: return "drop_oldest";
            }
            return "unknown";
        }

        /// E5c: emits a bucket's pending edge lines once the bucket mutex (declared after it) is dropped, whatever the
        /// return path.
        struct EmitPendingOnExit final
        {
            Bucket& bucket;
            ~EmitPendingOnExit()
            {
                bucket.emitPendingLogs();
            }
        };

        /// `text` cut to at most `max` bytes, never inside a UTF-8 sequence.
        std::string truncateUtf8(std::string_view text, std::size_t max)
        {
            if (text.size() <= max)
            {
                return std::string(text);
            }
            std::size_t size = max;
            while (size > 0 && (static_cast<unsigned char>(text[size]) & 0xC0U) == 0x80U)
            {
                --size;
            }
            return std::string(text.substr(0, size));
        }

        /// A refusal by a closed admission (E5c: the Shutdown part is kept apart for rejected[shutdown]).
        void countClosedRefusal(BucketStats& stats, Cause cause) noexcept
        {
            ++stats.rejectedClosed;
            if (cause == Cause::Shutdown)
            {
                ++stats.rejectedShutdown;
            }
        }

        template<class E>
        constexpr std::size_t at(E value) noexcept
        {
            return static_cast<std::size_t>(value);
        }

        /// E6e (B): K stripes for a bucket that stages (DropNewest, not ordered), 0 otherwise.
        std::size_t stripeCountFor(const BucketSpec& spec) noexcept
        {
            if (spec.overflow.kind != Overflow::Kind::DropNewest || spec.ordered)
            {
                return 0;
            }
            if (const auto fixed = seams::stripeCount(); fixed)
            {
                return *fixed; // A test build's K (INDEXER_CLIENT_TEST_STRIPES, 1-64).
            }
            const std::size_t threads = std::thread::hardware_concurrency(); // 0 when unknown.
            return std::max<std::size_t>(1, std::min<std::size_t>(64, 2 * threads));
        }

        /// E6e (B): the calling thread's stripe slot, taken in turn on its first post (any bucket: slot % K).
        std::size_t stripeSlot() noexcept
        {
            static std::atomic<std::size_t> next {0};
            thread_local const std::size_t slot = next.fetch_add(1, std::memory_order_relaxed);
            return slot;
        }

        /// The retries[] slot of an op's last error (metrics.hpp RetryCause; None and the rest count in other).
        RetryCause retryCause(Cause cause) noexcept
        {
            switch (cause)
            {
                case Cause::ItemRetryable: return RetryCause::ItemRetryable;
                case Cause::VersionConflict: return RetryCause::VersionConflict;
                case Cause::Server5xx: return RetryCause::Server5xx;
                case Cause::TransportTimeout:
                case Cause::TransportConnect:
                case Cause::TransportTls: return RetryCause::Transport;
                default: return RetryCause::Other;
            }
        }
    } // namespace

    std::uint64_t orderedKeyHash(std::string_view index, std::string_view id) noexcept
    {
        constexpr std::uint64_t OFFSET = 14695981039346656037ULL;
        constexpr std::uint64_t PRIME = 1099511628211ULL;
        std::uint64_t hash = OFFSET;
        const auto mix = [&hash](unsigned char byte)
        {
            hash ^= byte;
            hash *= PRIME;
        };
        for (const char c : index)
        {
            mix(static_cast<unsigned char>(c));
        }
        mix(0);
        for (const char c : id)
        {
            mix(static_cast<unsigned char>(c));
        }
        return hash;
    }

    Bucket::Bucket(std::string consumer,
                   BucketSpec spec,
                   GlobalBudget& budget,
                   std::weak_ptr<WritePath> owner,
                   std::weak_ptr<ClientState> client)
        : m_consumer(std::move(consumer))
        , m_spec(std::move(spec))
        , m_budget(budget)
        , m_owner(std::move(owner))
        , m_client(std::move(client))
        , m_threshold80(percentOf(m_spec.quotaBytes, 80))
        , m_threshold70(percentOf(m_spec.quotaBytes, 70))
        , m_stripeCount(stripeCountFor(m_spec))
        , m_stageMaxWire(m_spec.bulk.maxBytes)
        , m_stageMaxCharge(std::min<std::uint64_t>(m_spec.quotaBytes, budget.cap()))
        , m_stripeBytes(m_stripeCount == 0
                            ? 0
                            : std::min<std::uint64_t>(m_spec.bulk.maxBytes, m_spec.quotaBytes / (2 * m_stripeCount)))
        , m_stripeAge(std::min(STRIPE_AGE, m_spec.bulk.maxAge))
        , m_stripes(m_stripeCount == 0 ? nullptr : std::make_unique<Stripe[]>(m_stripeCount))
    {
        m_stats.consumer = m_consumer;
        m_stats.bucket = m_spec.name;
    }

    Bucket::~Bucket()
    {
        // No other reference exists, so no lock.
        // I99 (N6), the last net: with the close fixed (admit has no window, a racing enqueueGroup refuses, a Client
        // destroyed on a runtime thread sweeps) nothing is still queued here. If something is, every build (issue 15,
        // D64: no assert, the manager's Release builds keep it live) logs an internal error and completes what is left
        // (ticket or group slot; the callback is not called) and returns its charge to the global cap while the write
        // path, owner of that budget, is alive. Only the ops' own charge: a ticket's armed
        // reserve and a GroupState return theirs; an op with a callback or one of post (no ticket, no group) has nobody
        // else to.
        bool staged = !m_unstaged.empty();
        for (std::size_t i = 0; i < m_stripeCount && !staged; ++i)
        {
            staged = !m_stripes[i].ops.empty();
        }
        // E6e (B): staged (or unstaged) post ops were never charged and have nobody to complete: only the usage error.
        const bool leftovers = !m_pending.empty() || !m_lane.empty() || staged;
        if (leftovers)
        {
            internalError("a bucket destroyed with queued operations; they are completed Dropped(ClientClosed)");
            countUsageError();
            auto owner = m_owner.lock();
            std::uint64_t charge = 0;
            for (auto* queue : {&m_lane, &m_pending})
            {
                for (const auto& op : *queue)
                {
                    if (!op || op->claimed.exchange(true))
                    {
                        continue;
                    }
                    if (op->payloadCharged)
                    {
                        op->payloadCharged = false;
                        charge += op->payload;
                    }
                    if (op->reserveCharged && (op->callback || (!op->ticket && !op->group)))
                    {
                        charge += RESULT_RESERVE; // No callback runs to return it, or a post op's (E6d).
                    }
                    OpResult result;
                    result.status = Status::Dropped;
                    result.cause = Cause::ClientClosed;
                    result.reason = "dropped: the client was closed";
                    if (op->group)
                    {
                        resolveInGroup(*op, std::move(result));
                        op->group.reset();
                    }
                    else if (op->ticket)
                    {
                        op->ticket->complete(Outcome<OpResult>::success(std::move(result)));
                    }
                }
            }
            if (owner)
            {
                m_budget.release(charge);
            }
        }
        // D67: a delivered op whose batch was let go unresolved outlives its bucket. Whenever it resolves, it goes
        // through the branch of WritePath::resolve without a bucket, which returns only a post op's RESULT_RESERVE: its
        // payload charge goes back to the global cap here, once (payloadCharged; nothing else releases it once the
        // bucket is gone), claimed or not.
        if (!m_delivered.empty())
        {
            std::uint64_t delivered = 0;
            for (const auto& entry : m_delivered)
            {
                const auto& op = entry.second;
                if (op && op->payloadCharged)
                {
                    op->payloadCharged = false;
                    delivered += op->payload;
                }
            }
            if (delivered != 0 && m_owner.lock())
            {
                m_budget.release(delivered);
            }
        }
        // The cancel(tag) waiters still registered can never reach 0 (I80).
        for (auto& waiter : m_cancelWaiters)
        {
            if (waiter.ticket)
            {
                waiter.ticket->complete(Outcome<Unit>::failure(
                    Cause::ClientClosed, "the client was closed before the cancelled operations resolved"));
            }
        }
    }

    const BucketSpec& Bucket::spec() const noexcept
    {
        return m_spec;
    }

    const std::string& Bucket::consumer() const noexcept
    {
        return m_consumer;
    }

    const std::weak_ptr<ClientState>& Bucket::client() const noexcept
    {
        return m_client;
    }

    Admission Bucket::admit(const std::shared_ptr<OpState>& op, TimePoint now, TimePoint blockUntil)
    {
        Admission admission;
        std::uint64_t globalSurplus = 0;
        const EmitPendingOnExit emit {*this}; // Destroyed after the lock below: no line under the bucket mutex.
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            reserveLocked(lock,
                          op->wire(),
                          op->payload + RESULT_RESERVE,
                          static_cast<bool>(op->callback),
                          blockUntil,
                          admission,
                          globalSurplus);
            if (admission.cause == Cause::None && !admission.dropNewest)
            {
                // Charged under this same take of the mutex: the admission is open, so the op is queued (I99: no
                // reservation→append window for submit / post; a close after this point finds it pending).
                const bool wasEmpty = m_pending.empty();
                const std::uint64_t bytesBefore = m_pendingBytes;
                const std::size_t docsBefore = m_pending.size();

                takeCustodyLocked(*op, now);
                m_pendingBytes += op->wire();
                m_pending.push_back(op); // The only copy of the op's shared_ptr the bucket takes.

                const auto maxBytes = static_cast<std::uint64_t>(m_spec.bulk.maxBytes);
                const auto maxDocs = m_spec.bulk.maxDocs;
                const bool crossed = wasEmpty || (bytesBefore < maxBytes && m_pendingBytes >= maxBytes) ||
                                     (docsBefore < maxDocs && m_pending.size() >= maxDocs);
                admission.notify = crossed && !m_notified.exchange(true);
            }
        }
        m_budget.release(globalSurplus);
        return admission;
    }

    bool Bucket::stages() const noexcept
    {
        return m_stripeCount != 0;
    }

    StageResult Bucket::stage(std::shared_ptr<OpState>& op)
    {
        StageResult result;
        if (m_stripeCount == 0 || m_closing.load(std::memory_order_relaxed))
        {
            return result; // Closing: admit() refuses with the admission's cause and counts it, as today.
        }
        // Posted is decided here only as `accepted`: an op that can never fit goes through admit() (PayloadTooLarge
        // with its counters). spec and cap are immutable.
        const std::uint64_t charge = op->payload + RESULT_RESERVE;
        // The three conditions of admit(), from this bucket's read-only fields (spec and cap are immutable).
        if (op->wire() > m_stageMaxWire || charge > m_stageMaxCharge)
        {
            return result;
        }
        seams::beforeStagePush(); // PostRacingSeal: after the relaxed pre-check, before the stripe's mutex.
        auto& stripe = m_stripes[stripeSlot() % m_stripeCount];
        bool flushed = false;
        {
            std::lock_guard<std::mutex> lock(stripe.mutex);
            if (m_closing.load(std::memory_order_relaxed))
            {
                // The seal stored `closing` before it took this mutex: it flushed this stripe already (or this op
                // would reach a sealed stripe): not staged, admitted by admit() (refused once the admission closed).
                return result;
            }
            const bool first = stripe.ops.empty();
            const auto firstSubmit = op->firstSubmit.time_since_epoch().count();
            stripe.payload += op->payload;
            stripe.ops.push_back(std::move(op));
            result.staged = true;
            if (first)
            {
                // seq_cst: Dekker pair with invalidateArmedDue (see the notify below).
                stripe.oldest.store(firstSubmit);
            }
            if (stripe.ops.size() >= STRIPE_OPS || stripe.payload >= m_stripeBytes)
            {
                flushed = true;
                try
                {
                    result.notify = flushStripeLocked(stripe);
                }
                catch (...)
                {
                    // The ops stay staged: the deadline flush retries them. A producer is never told.
                    countUsageError();
                    result.notify = true;
                }
            }
            // A stripe that stays non-empty needs its deadline armed (nextDue reads `oldest`). D116: it asks loop 0
            // only when no timer is known to fire by this stripe's deadline; otherwise the pass at the armed deadline
            // (or the one running now) reads this stripe and re-arms. m_armedDue is NO_OLDEST when none is armed and
            // while a pass runs (invalidateArmedDue), so then it always asks.
            //
            // Memory (Dekker pair, every access seq_cst): here `store oldest; load m_armedDue`, in the pass
            // `store m_armedDue = NO_OLDEST; load oldest` (stripeDueLocked, from armTimer). In the single total order
            // at least one of the two loads sees the other side's store: either this load sees the invalidation (or
            // the deadline published after it) or that pass reads this `oldest` and arms the timer by it. A relaxed or
            // acquire load here, or a release store of `oldest`, would let both miss (store-load reordering).
            if (first && !stripe.ops.empty())
            {
                seams::beforeArmedDueLoad(); // StageRacingPassArmsDeadline: a loop-0 pass here.
                const auto deadline =
                    (TimePoint(TimePoint::duration(firstSubmit)) + m_stripeAge).time_since_epoch().count();
                result.notify = result.notify || deadline < m_armedDue.load();
            }
        }
        if (flushed)
        {
            emitPendingLogs(); // The flush's edge lines, with no mutex held (README «Logging»).
        }
        return result;
    }

    bool Bucket::flushStripeLocked(Stripe& stripe)
    {
        if (stripe.ops.empty())
        {
            return false;
        }
        const auto now = std::chrono::steady_clock::now();
        bool notify = false;
        std::uint64_t globalSurplus = 0;
        std::size_t done = 0; // stripe.ops[0, done) left the stripe (moved out).
        std::uint64_t donePayload = 0;
        std::exception_ptr error;
        {
            // No line here: the caller writes them once the stripe's mutex is dropped too (emitPendingLogs).
            std::unique_lock<std::mutex> lock(m_mutex);
            const bool wasEmpty = m_pending.empty();
            const std::uint64_t bytesBefore = m_pendingBytes;
            const std::size_t docsBefore = m_pending.size();
            try
            {
                for (; done < stripe.ops.size(); ++done)
                {
                    seams::midAdmitBatch(); // AdmitBatchThrowKeepsRest (m_mutex and the stripe's held: no lock).
                    auto& op = stripe.ops[done];
                    const std::uint64_t payload = op->payload;
                    if (m_admission)
                    {
                        // Unreachable while the seal protocol holds (the seal flushes with the admission open):
                        // kept for close() to hand back (Dropped(cause)), counted there. push_back of a moved
                        // shared_ptr: on a throw neither the vector nor `op` changed.
                        m_unstaged.push_back(std::move(op));
                        donePayload += payload;
                        continue;
                    }
                    // G-diff E6e P3-1: an op is admitted whole or not at all. Its queue slot is the only allocation of
                    // an admitted op, taken before any counter moves (deque::emplace_back: on a throw nothing changed);
                    // a drop's interval keys are undone below if they fail.
                    m_pending.emplace_back();
                    Reservation reservation;
                    try
                    {
                        reserveLocked(lock,
                                      op->wire(),
                                      payload + RESULT_RESERVE,
                                      false,
                                      now,
                                      reservation,
                                      globalSurplus); // DropNewest: never waits, never evicts, never throws.
                    }
                    catch (...)
                    {
                        m_pending.pop_back();
                        m_blockedPrefix = std::min(m_blockedPrefix, m_pending.size());
                        throw;
                    }
                    if (reservation.cause == Cause::None && !reservation.dropNewest)
                    {
                        takeCustodyLocked(*op, now);
                        m_pendingBytes += op->wire();
                        m_pending.back() = std::move(op); // Into the slot taken above: nothing allocates.
                    }
                    else
                    {
                        m_pending.pop_back();
                        m_blockedPrefix = std::min(m_blockedPrefix, m_pending.size());
                        if (reservation.dropNewest)
                        {
                            // A DropNewest drop (accepted, droppedNewest): counted as post counts it, nothing charged.
                            try
                            {
                                seams::midAdmitBatch(); // AdmitBatchDropThrowUndone: stands for the interval keys.
                                countResolvedLocked(Status::Dropped, Cause::QueueFull, {}, {});
                            }
                            catch (...)
                            {
                                // countResolvedLocked allocates before it counts: undo what reserveLocked counted
                                // (dropNewestLocked without a callback charges nothing), so the op stays staged as if
                                // never flushed (the edge line of the overflow stays: it was true).
                                --m_stats.submitted;
                                --m_stats.accepted;
                                --m_stats.droppedNewest;
                                throw;
                            }
                        }
                        // Else a refusal, counted by reserveLocked as admit() counts it. Unreachable: the admission is
                        // open (checked above) and stage() checked the size conditions, which are immutable.
                        op.reset();
                    }
                    donePayload += payload;
                }
            }
            catch (...)
            {
                error = std::current_exception();
            }
            const auto maxBytes = static_cast<std::uint64_t>(m_spec.bulk.maxBytes);
            const auto maxDocs = m_spec.bulk.maxDocs;
            const bool crossed = (wasEmpty && !m_pending.empty()) ||
                                 (bytesBefore < maxBytes && m_pendingBytes >= maxBytes) ||
                                 (docsBefore < maxDocs && m_pending.size() >= maxDocs);
            notify = crossed && !m_notified.exchange(true);
        }
        m_budget.release(globalSurplus);
        // Only the admitted ops leave the stripe (std::move left them null); the rest stays for the next flush.
        stripe.ops.erase(stripe.ops.begin(), stripe.ops.begin() + static_cast<std::ptrdiff_t>(done));
        stripe.payload -= donePayload;
        if (stripe.ops.empty())
        {
            stripe.oldest.store(NO_OLDEST, std::memory_order_release);
        }
        if (error)
        {
            std::rethrow_exception(error);
        }
        return notify;
    }

    bool Bucket::flushDueStripes(TimePoint now)
    {
        bool notify = false;
        for (std::size_t i = 0; i < m_stripeCount; ++i)
        {
            auto& stripe = m_stripes[i];
            const auto oldest = stripe.oldest.load(std::memory_order_acquire);
            if (oldest == NO_OLDEST || TimePoint(TimePoint::duration(oldest)) + m_stripeAge > now)
            {
                continue;
            }
            {
                std::lock_guard<std::mutex> lock(stripe.mutex);
                // G-diff E6e r2 P3-3: re-read under the stripe's mutex (where `oldest` is written): between the read
                // above and this lock a producer may have flushed the stripe and another refilled it, with a later
                // deadline that is not due yet.
                const auto current = stripe.oldest.load(std::memory_order_relaxed);
                if (current == NO_OLDEST || TimePoint(TimePoint::duration(current)) + m_stripeAge > now)
                {
                    continue;
                }
                try
                {
                    notify = flushStripeLocked(stripe) || notify;
                }
                catch (...)
                {
                    countUsageError(); // Never out of loop 0's handler: the next pass retries (its deadline is past).
                }
            }
            emitPendingLogs(); // The flush's edge lines, with no mutex held.
        }
        return notify;
    }

#ifdef INDEXER_CLIENT_TESTING
    bool Bucket::flushStaged()
    {
        bool notify = false;
        for (std::size_t i = 0; i < m_stripeCount; ++i)
        {
            {
                std::lock_guard<std::mutex> lock(m_stripes[i].mutex);
                notify = flushStripeLocked(m_stripes[i]) || notify;
            }
            emitPendingLogs();
        }
        return notify;
    }

    std::size_t Bucket::stagedOps() const
    {
        std::size_t ops = 0;
        for (std::size_t i = 0; i < m_stripeCount; ++i)
        {
            std::lock_guard<std::mutex> lock(m_stripes[i].mutex);
            ops += m_stripes[i].ops.size();
        }
        return ops;
    }
#endif

    std::vector<std::shared_ptr<OpState>> Bucket::sealStripes()
    {
        std::vector<std::shared_ptr<OpState>> leftovers;
        if (m_stripeCount == 0)
        {
            return leftovers;
        }
        // Before any stripe's mutex: a stage() that takes one after this seal flushed it sees `closing`.
        m_closing.store(true);
        for (std::size_t i = 0; i < m_stripeCount; ++i)
        {
            auto& stripe = m_stripes[i];
            std::lock_guard<std::mutex> lock(stripe.mutex);
            try
            {
                flushStripeLocked(stripe); // The admission is still open: every op is admitted (or dropped).
            }
            catch (...)
            {
                countUsageError();
                try
                {
                    leftovers.insert(leftovers.end(),
                                     std::make_move_iterator(stripe.ops.begin()),
                                     std::make_move_iterator(stripe.ops.end()));
                    stripe.ops.clear();
                    stripe.payload = 0;
                    stripe.oldest.store(NO_OLDEST, std::memory_order_release);
                }
                catch (...)
                {
                    // They stay staged: the ~Bucket net counts them.
                }
            }
        }
        emitPendingLogs(); // The flushes' edge lines, with no mutex held (the caller takes the bucket's after this).
        return leftovers;
    }

    std::optional<TimePoint> Bucket::stripeDueLocked() const
    {
        std::optional<TimePoint> due;
        for (std::size_t i = 0; i < m_stripeCount; ++i)
        {
            // seq_cst: the pass's half of stage()'s Dekker pair (after invalidateArmedDue; see stage()).
            const auto oldest = m_stripes[i].oldest.load();
            if (oldest == NO_OLDEST)
            {
                continue;
            }
            const auto at = TimePoint(TimePoint::duration(oldest)) + m_stripeAge;
            if (!due || at < *due)
            {
                due = at;
            }
        }
        return due;
    }

    void Bucket::handBackUnstagedLocked(std::vector<std::shared_ptr<OpState>>& out)
    {
        for (auto& op : m_unstaged)
        {
            // Posted reported them accepted: submitted and accepted now, resolved Dropped(cause) by the caller with
            // nothing charged (no payload, no RESULT_RESERVE).
            ++m_stats.submitted;
            ++m_stats.accepted;
            op->reserveCharged = false;
            out.push_back(std::move(op));
        }
        m_unstaged.clear();
    }

    void Bucket::addChargeLocked(std::uint64_t bytes) noexcept
    {
        m_charge += bytes;
        m_stats.peakCharge = std::max(m_stats.peakCharge, m_charge);
    }

    Bucket::Charge Bucket::tryChargeLocked(std::uint64_t charge)
    {
        if (charge > m_spec.quotaBytes || m_charge > m_spec.quotaBytes - charge)
        {
            return Charge::BucketFull;
        }
        if (!m_budget.tryReserve(charge))
        {
            return Charge::GlobalFull; // The global edge is claimed in tryReserve, not here.
        }
        const auto before = m_charge;
        addChargeLocked(charge);
        chargeMovedLocked(before);
        return Charge::Ok;
    }

    void Bucket::chargeMovedLocked(std::uint64_t before)
    {
        if (m_charge > before)
        {
            if (m_armed80 && m_charge >= m_threshold80)
            {
                m_armed80 = false;
                pushEdgeLocked(EdgeLine {Edge::Quota80, m_charge});
            }
        }
        else if (before >= m_threshold70 && m_charge < m_threshold70)
        {
            // An edge, not a level: a QueueFull storm at a low charge never re-arms.
            m_armed80 = true;
            m_armedFull = true;
        }
    }

    void Bucket::overflowLocked(Charge refused)
    {
        if (refused == Charge::BucketFull && m_armedFull)
        {
            m_armedFull = false;
            pushEdgeLocked(EdgeLine {Edge::Full, m_charge});
        }
    }

    void Bucket::pushEdgeLocked(const EdgeLine& line) noexcept
    {
        // Queued under the mutex, after a charge already moved: a failed allocation loses the line, never the
        // accounting (admit and the stripe flush stay all-or-nothing per op, G-diff E6e P3-1).
        try
        {
            m_edgeLines.push_back(line);
            m_edgePending.store(true);
        }
        catch (...)
        {
        }
    }

    void Bucket::emitPendingLogs() noexcept
    {
        try
        {
            if (m_edgePending.load())
            {
                std::vector<EdgeLine> lines;
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    lines.swap(m_edgeLines);
                    m_edgePending.store(false);
                }
                // m_consumer and m_spec are immutable: read without the mutex.
                for (const auto& line : lines)
                {
                    if (line.edge == Edge::Ambiguous && line.responseTooLarge)
                    {
                        logWarn(TAG,
                                "Indexer client bucket '%s/%s' got a response over max_response_bytes for a bulk of "
                                "%llu operations: they failed without being resent (onAmbiguous5xx = fail); the "
                                "indexer may have applied them.",
                                m_consumer.c_str(),
                                m_spec.name.c_str(),
                                static_cast<unsigned long long>(line.charge));
                    }
                    else if (line.edge == Edge::Ambiguous)
                    {
                        logWarn(TAG,
                                "Indexer client bucket '%s/%s' got an ambiguous HTTP %d for a bulk of %llu operations: "
                                "they failed without being resent (onAmbiguous5xx = fail); the indexer may have "
                                "applied them.",
                                m_consumer.c_str(),
                                m_spec.name.c_str(),
                                line.httpStatus,
                                static_cast<unsigned long long>(line.charge));
                    }
                    else if (line.edge == Edge::Quota80)
                    {
                        logWarn(TAG,
                                "Indexer client bucket '%s/%s' reached 80%% of its quota (%llu of %llu bytes charged).",
                                m_consumer.c_str(),
                                m_spec.name.c_str(),
                                static_cast<unsigned long long>(line.charge),
                                static_cast<unsigned long long>(m_spec.quotaBytes));
                    }
                    else
                    {
                        logWarn(TAG,
                                "Indexer client bucket '%s/%s' has no room for new operations (%llu of %llu bytes "
                                "charged): its overflow policy '%s' applies.",
                                m_consumer.c_str(),
                                m_spec.name.c_str(),
                                static_cast<unsigned long long>(line.charge),
                                static_cast<unsigned long long>(m_spec.quotaBytes),
                                overflowName(m_spec.overflow.kind));
                    }
                }
            }
        }
        catch (...)
        {
            // A log sink must never take a producer or a runtime thread down.
        }
        m_budget.emitPendingLogs();
    }

    void Bucket::dropNewestLocked(bool withCallback, Reservation& reservation)
    {
        if (withCallback && tryChargeLocked(RESULT_RESERVE) != Charge::Ok)
        {
            ++m_stats.rejectedQueueFull;
            reservation.cause = Cause::QueueFull;
            return;
        }
        ++m_stats.accepted;
        ++m_stats.droppedNewest;
        reservation.dropNewest = true;
    }

    bool Bucket::evictOldestLocked(std::uint64_t charge, Reservation& reservation, std::uint64_t& globalSurplus)
    {
        // Count first, evict only on success: the fewest oldest pending ops whose payload, reused by the new op, makes
        // it fit locally and globally. The evicted bytes stay charged globally and pass to the new op (no window in
        // which another bucket could take them); only the surplus is released, after the mutex.
        std::uint64_t freed = 0;
        std::size_t count = 0;
        for (;;)
        {
            if (m_charge - freed + charge <= m_spec.quotaBytes)
            {
                if (charge <= freed)
                {
                    globalSurplus = freed - charge;
                    break;
                }
                if (m_budget.tryReserve(charge - freed))
                {
                    break;
                }
            }
            if (count == m_pending.size())
            {
                return false;
            }
            freed += m_pending[count]->payload;
            ++count;
        }

        const auto before = m_charge;
        reservation.evicted.reserve(count);
        if (count != 0)
        {
            m_blockedPrefix = 0; // The pending queue's head moves.
        }
        for (std::size_t i = 0; i < count; ++i)
        {
            auto op = std::move(m_pending.front());
            m_pending.pop_front();
            m_pendingBytes -= op->wire();
            op->payloadCharged = false;
            --m_stats.retained;
            reservation.evicted.push_back(std::move(op));
        }
        m_charge -= freed;
        m_stats.retainedBytes -= freed;
        addChargeLocked(charge);
        chargeMovedLocked(before);
        ++m_stats.accepted;
        m_stats.droppedOldest += count;
        return true;
    }

    Reservation Bucket::reserve(std::uint64_t payload, bool withCallback, TimePoint blockUntil)
    {
        Reservation reservation;
        std::uint64_t globalSurplus = 0;
        const EmitPendingOnExit emit {*this}; // Destroyed after the lock below: no line under the bucket mutex.
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            reserveLocked(
                lock, payload, payload + RESULT_RESERVE, withCallback, blockUntil, reservation, globalSurplus);
        }
        m_budget.release(globalSurplus);
        return reservation;
    }

    void Bucket::reserveLocked(std::unique_lock<std::mutex>& lock,
                               std::uint64_t wire,
                               std::uint64_t charge,
                               bool withCallback,
                               TimePoint blockUntil,
                               Reservation& reservation,
                               std::uint64_t& globalSurplus)
    {
        ++m_stats.submitted;
        if (m_admission)
        {
            countClosedRefusal(m_stats, *m_admission);
            reservation.cause = *m_admission;
            return;
        }
        if (wire > m_spec.bulk.maxBytes || charge > m_spec.quotaBytes || charge > m_budget.cap())
        {
            ++m_stats.payloadTooLarge;
            reservation.cause = Cause::PayloadTooLarge;
            return;
        }
        const auto refused = tryChargeLocked(charge);
        if (refused == Charge::Ok)
        {
            ++m_stats.accepted;
            return;
        }

        switch (m_spec.overflow.kind)
        {
            case Overflow::Kind::Reject:
                overflowLocked(refused);
                ++m_stats.rejectedQueueFull;
                reservation.cause = Cause::QueueFull;
                break;

            case Overflow::Kind::Block:
            {
                if (indexer_client::detail::testing::onRuntimeThread())
                {
                    // RF-27: a runtime thread never sleeps on a quota it may be the one to free.
                    ++m_stats.reentrancy;
                    reservation.cause = Cause::Reentrancy;
                    break;
                }
                overflowLocked(refused); // A Block that has to wait.
                // Registered before the predicate's first re-check (see GlobalBudget::addWaiter).
                if (m_waiting++ == 0)
                {
                    m_budget.addWaiter(shared_from_this());
                }
                bool charged = false;
                m_room.wait_until(lock,
                                  blockUntil,
                                  [&]
                                  {
                                      if (m_admission)
                                      {
                                          return true;
                                      }
                                      charged = tryChargeLocked(charge) == Charge::Ok;
                                      return charged;
                                  });
                if (--m_waiting == 0)
                {
                    m_budget.removeWaiter(this);
                }
                if (charged)
                {
                    ++m_stats.accepted;
                }
                else if (m_admission)
                {
                    countClosedRefusal(m_stats, *m_admission);
                    reservation.cause = *m_admission;
                }
                else
                {
                    ++m_stats.submitTimeout;
                    reservation.cause = Cause::SubmitTimeout;
                }
                break;
            }

            case Overflow::Kind::DropNewest:
                overflowLocked(refused);
                dropNewestLocked(withCallback, reservation);
                break;

            case Overflow::Kind::DropOldest:
                overflowLocked(refused);
                if (!evictOldestLocked(charge, reservation, globalSurplus))
                {
                    dropNewestLocked(withCallback, reservation);
                }
                break;
        }
    }

    Reservation Bucket::reserveForGroup(std::uint64_t payload,
                                        std::uint64_t wire,
                                        std::uint64_t groupReserved,
                                        TimePoint blockUntil)
    {
        const std::uint64_t charge = payload + RESULT_RESERVE;
        Reservation reservation;
        bool charged = false;
        const EmitPendingOnExit emit {*this}; // Destroyed after the lock below: no line under the bucket mutex.
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            ++m_stats.submitted;
            if (m_admission)
            {
                countClosedRefusal(m_stats, *m_admission);
                reservation.cause = *m_admission;
                return reservation;
            }
            if (wire > m_spec.bulk.maxBytes || charge > m_spec.quotaBytes || charge > m_budget.cap())
            {
                ++m_stats.payloadTooLarge;
                reservation.cause = Cause::PayloadTooLarge;
                return reservation;
            }
            // charge <= quota and <= cap here, so the subtractions cannot wrap.
            if (groupReserved > m_spec.quotaBytes - charge || groupReserved > m_budget.cap() - charge)
            {
                ++m_stats.rejectedGroupTooLarge;
                reservation.cause = Cause::GroupTooLarge;
                return reservation;
            }
            // The room this op lacks is held by Building groups (this bucket's or any bucket's): waiting for it could
            // wait on a group that is never committed (03 §4.13), so it is QueueFull at once. m_mutex held.
            const auto heldByGroups = [&]
            {
                return m_building > m_spec.quotaBytes - charge || m_budget.building() > m_budget.cap() - charge;
            };
            const auto refused = tryChargeLocked(charge);
            charged = refused == Charge::Ok;
            if (!charged)
            {
                if (m_spec.overflow.kind != Overflow::Kind::Block)
                {
                    // Reject, DropNewest and DropOldest alike (I70): nothing is dropped or evicted for a group op.
                    overflowLocked(refused);
                    ++m_stats.rejectedQueueFull;
                    reservation.cause = Cause::QueueFull;
                    return reservation;
                }
                if (indexer_client::detail::testing::onRuntimeThread())
                {
                    ++m_stats.reentrancy; // RF-27, as reserve().
                    reservation.cause = Cause::Reentrancy;
                    return reservation;
                }
                overflowLocked(refused); // QueueFull at once or a Block that has to wait.
                if (heldByGroups())
                {
                    ++m_stats.rejectedQueueFull;
                    reservation.cause = Cause::QueueFull;
                    return reservation;
                }
                // Registered before the predicate's first re-check (see GlobalBudget::addWaiter), as reserve().
                if (m_waiting++ == 0)
                {
                    m_budget.addWaiter(shared_from_this());
                }
                bool held = false;
                m_room.wait_until(lock,
                                  blockUntil,
                                  [&]
                                  {
                                      if (m_admission)
                                      {
                                          return true;
                                      }
                                      charged = tryChargeLocked(charge) == Charge::Ok;
                                      if (charged)
                                      {
                                          return true;
                                      }
                                      held = heldByGroups();
                                      return held;
                                  });
                if (--m_waiting == 0)
                {
                    m_budget.removeWaiter(this);
                }
                if (!charged)
                {
                    if (m_admission)
                    {
                        countClosedRefusal(m_stats, *m_admission);
                        reservation.cause = *m_admission;
                    }
                    else if (held)
                    {
                        ++m_stats.rejectedQueueFull;
                        reservation.cause = Cause::QueueFull;
                    }
                    else
                    {
                        ++m_stats.submitTimeout;
                        reservation.cause = Cause::SubmitTimeout;
                    }
                    return reservation;
                }
            }
            ++m_stats.accepted;
            ++m_stats.groupBuilding;
            m_building += charge;
            m_budget.addBuilding(charge); // Before the wake-ups below: a woken waiter's re-check sees it.
            if (m_waiting != 0)
            {
                m_room.notify_all(); // Their building condition may hold now.
            }
        }
        // Other buckets' group adds may be waiting on a condition that `building` now meets; no bucket mutex held.
        m_budget.wakeWaiters();
        return reservation;
    }

    void Bucket::takeCustodyLocked(OpState& op, TimePoint now)
    {
        if (op.firstSubmit == TimePoint {})
        {
            op.firstSubmit = now;
        }
        if (op.owner == nullptr)
        {
            op.owner = this; // A plain store (E6e D): no reference count of the bucket per op.
        }
        op.payloadCharged = true;
        op.seq = m_nextSeq++;
        ++m_stats.retained;
        m_stats.retainedBytes += op.payload;
    }

    std::optional<Cause> Bucket::refusalCauseLocked() const
    {
        // The sweep's cause when there was one (during stop() everything is Shutdown), else the admission's.
        return m_closed ? m_closed : m_admission;
    }

    bool Bucket::enqueueGroup(std::vector<std::shared_ptr<OpState>> ops,
                              std::uint64_t reserved,
                              std::optional<Cause>* closed)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (closed)
        {
            *closed = m_admission ? refusalCauseLocked() : std::nullopt;
        }
        m_building -= reserved;
        m_budget.removeBuilding(reserved);
        m_stats.groupBuilding -= ops.size();
        if (ops.empty())
        {
            return false; // Nothing to flush (commitGroup never calls it so).
        }
        const auto now = std::chrono::steady_clock::now();
        if (m_admission)
        {
            // I99 (N2): refused, never queued. Each payload passes to the bucket's custody exactly as an accepted op's
            // (payloadCharged, retained), so the caller's WritePath::resolve releases it through releasePayload; the
            // `building` transfer above happened all the same.
            for (auto& op : ops)
            {
                takeCustodyLocked(*op, now);
            }
            return false;
        }
        for (auto& op : ops)
        {
            takeCustodyLocked(*op, now);
            m_pendingBytes += op->wire();
            m_pending.push_back(std::move(op));
        }
        m_flushSeq = m_nextSeq - 1;
        // Whatever the thresholds: the group leaves now (RF-7).
        return !m_notified.exchange(true);
    }

    void Bucket::cancelGroupReservation(std::uint64_t reserved, std::uint32_t ops)
    {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            const auto before = m_charge;
            m_charge -= reserved;
            chargeMovedLocked(before); // Only re-arms.
            m_building -= reserved;
            m_stats.groupBuilding -= ops;
            m_stats.groupAbandoned += ops;
            m_stats.resolvedDropped += ops;
            if (m_waiting != 0)
            {
                m_room.notify_all();
            }
        }
        // `building` first: it is part of the global charge and never exceeds it.
        m_budget.removeBuilding(reserved);
        m_budget.release(reserved); // Wakes the global waiters.
    }

    bool Bucket::laneDueLocked(TimePoint now) const
    {
        return !m_lane.empty() && m_lane.front()->notBefore <= now;
    }

    void Bucket::laneAddedLocked(const OpState& op)
    {
        if (!m_spec.ordered)
        {
            return;
        }
        if (op.hasKey)
        {
            ++m_laneKeys[op.keyHash];
        }
        if (op.pinNode)
        {
            ++m_lanePinned;
        }
    }

    void Bucket::laneRemovedLocked(const OpState& op)
    {
        if (!m_spec.ordered)
        {
            return;
        }
        if (op.hasKey)
        {
            if (const auto it = m_laneKeys.find(op.keyHash); it != m_laneKeys.end() && --it->second == 0)
            {
                m_laneKeys.erase(it);
                m_blockedPrefix = 0; // A pending op of that key is takeable again.
            }
        }
        if (op.pinNode && m_lanePinned != 0)
        {
            --m_lanePinned;
        }
    }

    bool Bucket::laneBlocksLocked(const OpState& op) const
    {
        return op.hasKey && m_laneKeys.find(op.keyHash) != m_laneKeys.end();
    }

    Bucket::PinScan Bucket::pinScanLocked(TimePoint now) const
    {
        PinScan scan;
        if (m_lanePinned == 0)
        {
            return scan;
        }
        for (const auto& op : m_lane)
        {
            if (!op->pinNode || op->pinUntil <= now)
            {
                continue;
            }
            const TimePoint next = std::min(op->notBefore, op->pinUntil);
            if (!scan.pinned || next < scan.next)
            {
                scan.next = next;
            }
            scan.pinned = true;
            if (op->notBefore <= now && !scan.due)
            {
                scan.due = true;
                scan.head = op->wire();
            }
        }
        return scan;
    }

    std::optional<std::size_t> Bucket::firstTakeablePendingLocked() const
    {
        if (m_laneKeys.empty())
        {
            return m_pending.empty() ? std::nullopt : std::optional<std::size_t> {0};
        }
        // Skipped ops are blocked by a lane key, so they add no key of their own: the lane's keys are the whole set.
        // The whole queue, not a window of it: a window of bulk.maxDocs entries stalled every key behind that many
        // blocked ops until the blocked keys' retries ended (never, with unlimited retries). The scan resumes after
        // the prefix found blocked last time, so a pass that changes nothing costs O(1).
        std::size_t index = std::min(m_blockedPrefix, m_pending.size());
        for (; index < m_pending.size(); ++index)
        {
            if (!laneBlocksLocked(*m_pending[index]))
            {
                m_blockedPrefix = index;
                return index;
            }
        }
        m_blockedPrefix = index;
        return std::nullopt;
    }

    bool Bucket::orderedEligibleLocked(TimePoint now) const
    {
        if (!m_delivered.empty())
        {
            return false; // One bulk in flight; its completion wakes the scheduler (sinkReady).
        }
        if (const auto pin = pinScanLocked(now); pin.pinned)
        {
            return pin.due;
        }
        if (laneDueLocked(now))
        {
            return true;
        }
        const auto first = firstTakeablePendingLocked();
        if (!first)
        {
            return false;
        }
        return m_pending[*first]->seq <= m_flushSeq || m_pendingBytes >= m_spec.bulk.maxBytes ||
               m_pending.size() >= m_spec.bulk.maxDocs || now - m_pending.front()->firstSubmit >= m_spec.bulk.maxAge;
    }

    std::uint64_t Bucket::orderedHeadBytesLocked(TimePoint now) const
    {
        if (!m_delivered.empty())
        {
            return 0;
        }
        if (const auto pin = pinScanLocked(now); pin.pinned)
        {
            return pin.head;
        }
        if (laneDueLocked(now))
        {
            return m_lane.front()->wire();
        }
        const auto first = firstTakeablePendingLocked();
        return first ? m_pending[*first]->wire() : 0;
    }

    std::optional<TimePoint> Bucket::orderedNextDueLocked(TimePoint now) const
    {
        if (!m_delivered.empty())
        {
            return std::nullopt; // The completion wakes the scheduler (sinkReady); shutdown through the sweep.
        }
        if (const auto pin = pinScanLocked(now); pin.pinned)
        {
            return pin.next;
        }
        // Never an already-passed time that a pass would not turn into a batch (no idle spin of loop 0): the pending
        // thresholds count only while some pending op is takeable; with none, the lane head (not due, or it would be
        // takeable) is what unblocks it.
        std::optional<TimePoint> due;
        if (const auto first = firstTakeablePendingLocked(); first)
        {
            if (m_pending[*first]->seq <= m_flushSeq)
            {
                return TimePoint::min(); // A takeable committed group's op: due now (see nextDueLocked).
            }
            due = m_pending.front()->firstSubmit + m_spec.bulk.maxAge;
        }
        if (!m_lane.empty() && (!due || m_lane.front()->notBefore < *due))
        {
            due = m_lane.front()->notBefore;
        }
        return due;
    }

    bool Bucket::eligible(TimePoint now) const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_spec.ordered)
        {
            return orderedEligibleLocked(now);
        }
        if (laneDueLocked(now))
        {
            return true;
        }
        if (m_pending.empty())
        {
            return false;
        }
        return m_pending.front()->seq <= m_flushSeq || m_pendingBytes >= m_spec.bulk.maxBytes ||
               m_pending.size() >= m_spec.bulk.maxDocs || now - m_pending.front()->firstSubmit >= m_spec.bulk.maxAge;
    }

    std::optional<TimePoint> Bucket::nextDueLocked(TimePoint now) const
    {
        if (m_spec.ordered)
        {
            return orderedNextDueLocked(now);
        }
        std::optional<TimePoint> due;
        if (!m_pending.empty())
        {
            if (m_pending.front()->seq <= m_flushSeq)
            {
                // A committed group's op heads the queue: due now. TimePoint::min() is <= any `now`, so
                // Scheduler::armTimer arms no timer for it and reports it due (it re-posts a pass when the sink has
                // capacity; otherwise sinkReady() resumes the scheduler). Nothing is earlier, so the lane cannot win.
                return TimePoint::min();
            }
            due = m_pending.front()->firstSubmit + m_spec.bulk.maxAge;
        }
        if (!m_lane.empty() && (!due || m_lane.front()->notBefore < *due))
        {
            due = m_lane.front()->notBefore;
        }
        // E6e (B): the stripes' deadline (atomics only, never a stripe's mutex under this one).
        if (const auto stripes = stripeDueLocked(); stripes && (!due || *stripes < *due))
        {
            due = stripes;
        }
        return due;
    }

    std::uint64_t Bucket::headBytes(TimePoint now) const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_spec.ordered)
        {
            return orderedHeadBytesLocked(now);
        }
        if (laneDueLocked(now))
        {
            return m_lane.front()->wire();
        }
        return m_pending.empty() ? 0 : m_pending.front()->wire();
    }

    bool Bucket::empty() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_pending.empty() && m_lane.empty();
    }

    std::optional<TimePoint> Bucket::nextDue(TimePoint now) const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return nextDueLocked(now);
    }

    std::optional<TimePoint> Bucket::stripeDue() const
    {
        return stripeDueLocked(); // Reads only the stripes' atomics and immutable fields: no mutex needed.
    }

    Batch Bucket::slice(TimePoint now, std::uint64_t cap)
    {
        Batch batch;
        std::lock_guard<std::mutex> lock(m_mutex);
        const auto maxBytes = static_cast<std::uint64_t>(m_spec.bulk.maxBytes);
        const auto maxDocs = m_spec.bulk.maxDocs;
        std::uint64_t opsCap = 0; // Smallest batchCap of the ops taken (0 = none): split halves never merge again.
        // Whether `op` joins the batch; a document is never split: the head always goes (I118: the DRR credit decides
        // whether the turn emits, not how large the batch is; `cap`, the sink's batch limit, never refuses it either).
        const auto fits = [&](const OpState& op)
        {
            const std::uint64_t size = op.wire();
            if (batch.ops.empty())
            {
                return true;
            }
            const std::uint64_t opCap =
                op.batchCap == 0 ? opsCap : (opsCap == 0 ? op.batchCap : std::min(opsCap, op.batchCap));
            return batch.bytes + size <= maxBytes && batch.ops.size() < maxDocs &&
                   (opCap == 0 || batch.bytes + size <= opCap) && (cap == 0 || batch.bytes + size <= cap);
        };
        const auto take = [&](std::shared_ptr<OpState> op)
        {
            if (op->batchCap != 0)
            {
                opsCap = opsCap == 0 ? op->batchCap : std::min(opsCap, op->batchCap);
            }
            if (op->firstAttempt == TimePoint {})
            {
                op->firstAttempt = now;
            }
            batch.bytes += op->wire();
            m_delivered.emplace(op.get(), op);
            batch.ops.push_back(std::move(op));
        };
        if (m_spec.ordered)
        {
            if (!m_delivered.empty())
            {
                return batch; // One bulk in flight (eligible() is false meanwhile).
            }
            if (pinScanLocked(now).pinned)
            {
                // The pin gate: exactly the due pinned ops (they share one pin), nothing else joins.
                std::deque<std::shared_ptr<OpState>> rest;
                bool stop = false;
                for (auto& op : m_lane)
                {
                    const bool candidate = op->pinNode && op->pinUntil > now && op->notBefore <= now;
                    if (stop || !candidate || !fits(*op))
                    {
                        stop = stop || candidate;
                        rest.push_back(std::move(op));
                        continue;
                    }
                    laneRemovedLocked(*op);
                    take(std::move(op));
                }
                m_lane.swap(rest);
            }
            else
            {
                std::unordered_set<std::uint64_t> taken; // Keys in this batch: a key at most once per bulk.
                const auto blocked = [&](const OpState& op)
                {
                    return op.hasKey && (laneBlocksLocked(op) || taken.count(op.keyHash) != 0);
                };
                bool full = false;
                while (laneDueLocked(now))
                {
                    if (!fits(*m_lane.front()) || (m_lane.front()->hasKey && taken.count(m_lane.front()->keyHash) != 0))
                    {
                        full = true;
                        break;
                    }
                    auto op = std::move(m_lane.front());
                    m_lane.pop_front();
                    laneRemovedLocked(*op);
                    if (op->hasKey)
                    {
                        taken.insert(op->keyHash);
                    }
                    take(std::move(op));
                }
                // The pending queue in order: blocked ones are skipped and keep their place. The scan is bounded by
                // what it emits, not by what it visits (a window of bulk.maxDocs entries stalled every key behind that
                // many blocked ops): it stops once the batch holds bulk.maxDocs ops, at the first takeable op that
                // does not fit, or at the end of the queue. The prefix found blocked by a lane key (m_blockedPrefix,
                // still valid: the lane above only drops keys, which resets it) is not visited nor moved.
                const std::size_t from = std::min(m_blockedPrefix, m_pending.size());
                std::vector<std::shared_ptr<OpState>> skipped;
                std::size_t visited = from;
                for (; !full && visited < m_pending.size() && batch.ops.size() < maxDocs; ++visited)
                {
                    auto& op = m_pending[visited];
                    if (blocked(*op))
                    {
                        skipped.push_back(std::move(op));
                        continue;
                    }
                    if (!fits(*op))
                    {
                        break;
                    }
                    m_pendingBytes -= op->wire();
                    if (op->hasKey)
                    {
                        taken.insert(op->keyHash);
                    }
                    take(std::move(op));
                }
                const auto at = m_pending.begin() + static_cast<std::ptrdiff_t>(from);
                m_pending.erase(at, m_pending.begin() + static_cast<std::ptrdiff_t>(visited));
                m_pending.insert(m_pending.begin() + static_cast<std::ptrdiff_t>(from),
                                 std::make_move_iterator(skipped.begin()),
                                 std::make_move_iterator(skipped.end()));
                // [0, from) is untouched and still blocked by the lane; what follows changed.
                m_blockedPrefix = from;
            }
            if (!batch.ops.empty())
            {
                batch.bucket = shared_from_this();
            }
            return batch;
        }
        // The due retry lane first, then the pending queue: one batch may mix both.
        bool full = false;
        while (laneDueLocked(now))
        {
            if (!fits(*m_lane.front()))
            {
                full = true;
                break;
            }
            auto op = std::move(m_lane.front());
            m_lane.pop_front();
            take(std::move(op));
        }
        while (!full && !m_pending.empty())
        {
            if (!fits(*m_pending.front()))
            {
                break;
            }
            auto op = std::move(m_pending.front());
            m_pending.pop_front();
            m_blockedPrefix = 0;
            m_pendingBytes -= op->wire();
            take(std::move(op));
        }
        if (!batch.ops.empty())
        {
            batch.bucket = shared_from_this();
        }
        return batch;
    }

    void Bucket::clearNotified() noexcept
    {
        m_notified.store(false);
    }

    void Bucket::invalidateArmedDue() noexcept
    {
        // seq_cst: the pass's store of the Dekker pair with stage(); its load is stripeDueLocked's of `oldest`.
        m_armedDue.store(NO_OLDEST);
    }

    void Bucket::publishArmedDue(std::optional<TimePoint> due) const noexcept
    {
        m_armedDue.store(due ? due->time_since_epoch().count() : NO_OLDEST);
    }

    std::uint64_t Bucket::releasePayloadLocked(OpState& op,
                                               bool withReserve,
                                               std::shared_ptr<OpState>& keep,
                                               std::vector<std::shared_ptr<CancelState>>& cancelDone)
    {
        std::uint64_t released = 0;
        // The resolution won the claim, so no requeue writes them again: a resolved op whose completion waits on
        // the pool keeps no last-error strings (RESULT_RESERVE, G-diff E3b-2 obj. 1).
        std::string().swap(op.lastReason);
        std::string().swap(op.lastItemErrorType);
        if (const auto it = m_delivered.find(&op); it != m_delivered.end())
        {
            keep = std::move(it->second);
            m_delivered.erase(it);
        }
        else if (op.payloadCharged)
        {
            // Resolved while in the retry lane (claimed by a sweep after its requeue): it leaves the lane too.
            const auto lane = std::find_if(m_lane.begin(),
                                           m_lane.end(),
                                           [&op](const std::shared_ptr<OpState>& entry) { return entry.get() == &op; });
            if (lane != m_lane.end())
            {
                laneRemovedLocked(op);
                keep = std::move(*lane);
                m_lane.erase(lane);
            }
        }
        if (withReserve)
        {
            // E6d: a post op's RESULT_RESERVE, in this same take of the mutex.
            released = RESULT_RESERVE;
            m_charge -= RESULT_RESERVE;
        }
        if (op.payloadCharged)
        {
            op.payloadCharged = false;
            released += op.payload;
            m_charge -= op.payload;
            --m_stats.retained;
            m_stats.retainedBytes -= op.payload;
            // I80: the single decrement point, once per op (payloadCharged); only a marked op counted at its
            // waiter's registration (seq < seqLimit) decrements it.
            if (!m_cancelWaiters.empty() && op.cancelled.load() && !op.tag.empty())
            {
                for (auto it = m_cancelWaiters.begin(); it != m_cancelWaiters.end();)
                {
                    if (it->tag == op.tag && op.seq < it->seqLimit && it->remaining != 0 && --it->remaining == 0)
                    {
                        cancelDone.push_back(std::move(it->ticket));
                        it = m_cancelWaiters.erase(it);
                    }
                    else
                    {
                        ++it;
                    }
                }
            }
        }
        // The tag is only read while the op is queued or delivered (cancel, the decrement above): a resolved op
        // whose completion waits on the pool does not keep it, whether its payload was still charged or not (an
        // op evicted by DropOldest) (RESULT_RESERVE).
        std::string().swap(op.tag);
        return released;
    }

    void Bucket::releasePayload(OpState& op, bool withReserve)
    {
        std::shared_ptr<OpState> keep; // Dropped after the mutex: the op (and its TicketState) never dies under it.
        std::uint64_t released = 0;
        std::vector<std::shared_ptr<CancelState>> cancelDone; // Completed after the mutex (I80).
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            const auto before = m_charge;
            released = releasePayloadLocked(op, withReserve, keep, cancelDone);
            if (released != 0)
            {
                chargeMovedLocked(before); // Only re-arms: a release never queues a line.
                if (m_waiting != 0)
                {
                    m_room.notify_all();
                }
            }
        }
        m_budget.release(released);
        for (const auto& ticket : cancelDone)
        {
            if (ticket)
            {
                ticket->complete(Outcome<Unit>::success(Unit {}));
            }
        }
    }

    void Bucket::settleBulk(BulkItem* items, std::size_t count, std::size_t& settled)
    {
        // Dropped after the mutex: the bucket's copies of the ops (the caller's batch holds them too).
        std::vector<std::shared_ptr<OpState>> keep;
        keep.reserve(count); // Before the mutex: a throw here settles nothing.
        std::vector<std::shared_ptr<CancelState>> cancelDone;
        std::uint64_t released = 0;
        std::exception_ptr error;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            const auto before = m_charge;
            try
            {
                // Each waiter completes at most once: with this capacity the decrement never allocates, so an op is
                // either fully settled or not at all (only countResolvedLocked's interval keys may throw, first).
                cancelDone.reserve(m_cancelWaiters.size());
                for (std::size_t i = 0; i < count; ++i)
                {
                    auto& item = items[i];
                    // E6e (D), G-diff P3-5: the caller's bucket must be the op's, as WritePath::resolveWon checks.
                    // Issue 15 (D64): no assert; logged, counted and settled here all the same.
                    if (item.op->owner != nullptr && item.op->owner != this)
                    {
                        internalError("settleBulk: an operation settled by a bucket other than its own");
                    }
                    seams::inSettleBulk(); // SettleThrowsTwiceFallsBackPerOp: stands for the interval keys' throw.
                    countResolvedLocked(
                        item.result.status, item.result.cause, item.result.itemErrorType, item.result.reason);
                    if (item.result.status == Status::Dropped && item.result.cause == Cause::Cancelled)
                    {
                        ++m_stats.cancelled; // I80: also under resolvedDropped (countCancelled).
                    }
                    std::shared_ptr<OpState> one;
                    released += releasePayloadLocked(*item.op, true, one, cancelDone);
                    if (one)
                    {
                        keep.push_back(std::move(one)); // Within the capacity reserved above.
                    }
                    ++settled;
                }
            }
            catch (...)
            {
                error = std::current_exception(); // What was settled is released below all the same.
            }
            if (released != 0)
            {
                chargeMovedLocked(before); // Only re-arms: a release never queues a line.
                if (m_waiting != 0)
                {
                    m_room.notify_all();
                }
            }
        }
        m_budget.release(released); // One release per chunk (E6e A), not one per op.
        for (const auto& ticket : cancelDone)
        {
            if (ticket)
            {
                ticket->complete(Outcome<Unit>::success(Unit {}));
            }
        }
        if (error)
        {
            std::rethrow_exception(error);
        }
    }

    void Bucket::releaseReserve(std::uint32_t count)
    {
        const std::uint64_t bytes = RESULT_RESERVE * count;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            const auto before = m_charge;
            m_charge -= bytes;
            chargeMovedLocked(before); // Only re-arms.
            if (m_waiting != 0)
            {
                m_room.notify_all();
            }
        }
        m_budget.release(bytes);
    }

    std::vector<std::shared_ptr<OpState>> Bucket::close(Cause cause)
    {
        // E6e (B): the seal first (stripes flushed while the admission is open), then the bucket mutex.
        auto leftovers = sealStripes();
        std::vector<std::shared_ptr<OpState>> pending; // Lane first, then pending (then what the stripes left).
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto& op : leftovers)
        {
            m_unstaged.push_back(std::move(op));
        }
        if (!m_closed)
        {
            m_closed = cause;
        }
        if (!m_admission)
        {
            m_admission = cause; // One call closes both (registerClient after stop(), the runtime sweep).
        }
        pending.reserve(m_lane.size() + m_pending.size());
        for (auto& op : m_lane)
        {
            pending.push_back(std::move(op));
        }
        m_lane.clear();
        m_laneKeys.clear();
        m_lanePinned = 0;
        m_blockedPrefix = 0;
        for (auto& op : m_pending)
        {
            pending.push_back(std::move(op));
        }
        m_pending.clear();
        m_pendingBytes = 0;
        handBackUnstagedLocked(pending);
        m_room.notify_all();
        return pending;
    }

    void Bucket::closeAdmission(Cause cause)
    {
        // E6e (B): the seal first, so the flushed ops are below the flushSeq set here and drain at once.
        auto leftovers = sealStripes();
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto& op : leftovers)
        {
            m_unstaged.push_back(std::move(op));
        }
        if (!m_admission)
        {
            m_admission = cause;
        }
        // Everything pending is eligible now, as a committed group's ops (nextDue = TimePoint::min()); nothing is
        // enqueued afterwards, so the drain never waits for maxAge.
        if (m_nextSeq > 1)
        {
            m_flushSeq = m_nextSeq - 1;
        }
        m_room.notify_all(); // Blocked producers see the admission closed.
    }

    std::uint64_t Bucket::retained() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_stats.retained;
    }

    std::optional<Cause> Bucket::closedCause() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_admission; // close() sets it too: m_closed without m_admission does not exist.
    }

    std::optional<Cause> Bucket::sweepCause() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_closed;
    }

    std::vector<std::shared_ptr<OpState>> Bucket::delivered() const
    {
        std::vector<std::shared_ptr<OpState>> ops;
        std::lock_guard<std::mutex> lock(m_mutex);
        ops.reserve(m_delivered.size());
        for (const auto& entry : m_delivered)
        {
            ops.push_back(entry.second);
        }
        return ops;
    }

    void Bucket::wakeWaiters()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_room.notify_all();
    }

    void Bucket::countResolved(Status status, Cause cause, std::string_view itemErrorType, std::string_view reason)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        countResolvedLocked(status, cause, itemErrorType, reason);
    }

    void
    Bucket::countResolvedLocked(Status status, Cause cause, std::string_view itemErrorType, std::string_view reason)
    {
        if (status != Status::Ok)
        {
            // E5c: the interval's (cause, itemErrorType) keys, first-come, at most SUMMARY_KEYS; the rest is `other`.
            auto& keys = m_interval.keys;
            const auto key = std::find_if(keys.begin(),
                                          keys.end(),
                                          [&](const LogInterval::Key& k)
                                          { return k.cause == cause && k.itemErrorType == itemErrorType; });
            if (key != keys.end())
            {
                ++key->count;
            }
            else if (keys.size() < logging::SUMMARY_KEYS)
            {
                keys.push_back(LogInterval::Key {cause, std::string(itemErrorType), 1});
            }
            else
            {
                ++m_interval.other;
            }
            if (m_interval.sampleReason.empty() && !reason.empty())
            {
                m_interval.sampleReason = truncateUtf8(reason, logging::SAMPLE_REASON_MAX);
                m_interval.sampleCause = cause;
                m_interval.sampleItemErrorType = std::string(itemErrorType);
            }
        }
        switch (status)
        {
            case Status::Ok: ++m_stats.resolvedOk; break;
            case Status::Failed:
            {
                ++m_stats.resolvedFailed;
                FailCause slot = FailCause::InvalidState;
                switch (cause)
                {
                    case Cause::ItemPermanent: slot = FailCause::ItemPermanent; break;
                    case Cause::RetryExhausted: slot = FailCause::RetryExhausted; break;
                    case Cause::Client4xx:
                    case Cause::PayloadTooLarge: slot = FailCause::Client4xx; break; // A single-op 413.
                    case Cause::Server5xx: slot = FailCause::Server5xx; break;
                    case Cause::Unavailable: slot = FailCause::Unavailable; break;
                    case Cause::Ambiguous: slot = FailCause::Ambiguous; break;
                    default: break;
                }
                ++m_stats.failed[at(slot)];
                break;
            }
            case Status::Dropped:
                ++m_stats.resolvedDropped;
                switch (cause)
                {
                    case Cause::QueueFull: ++m_stats.dropped[at(DropCause::QueueFull)]; break;
                    case Cause::ClientClosed: ++m_stats.dropped[at(DropCause::ClientClosed)]; break;
                    case Cause::Shutdown: ++m_stats.dropped[at(DropCause::Shutdown)]; break;
                    case Cause::Cancelled: ++m_stats.dropped[at(DropCause::Cancelled)]; break;
                    default: break; // None reaches here (an abandoned group counts in cancelGroupReservation).
                }
                break;
        }
    }

    void Bucket::countLate(std::uint64_t ops)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_stats.lateResults += ops;
    }

    void Bucket::countBulk(std::uint64_t bytes, std::optional<std::uint64_t> latencyMicros, bool success)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        ++m_stats.bulkRequests;
        m_stats.bulkBytes += bytes;
        if (latencyMicros)
        {
            m_stats.latency.observe(*latencyMicros);
        }
        if (success)
        {
            m_armedAmbiguous = true;
        }
    }

    void Bucket::countAmbiguous(int httpStatus, std::uint64_t ops, bool responseTooLarge)
    {
        EmitPendingOnExit emit {*this}; // Declared before the lock: the line is written once the mutex is dropped.
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_armedAmbiguous)
        {
            m_armedAmbiguous = false;
            m_edgeLines.push_back(EdgeLine {Edge::Ambiguous, ops, httpStatus, responseTooLarge});
            m_edgePending.store(true);
        }
    }

    CancelResult Bucket::cancel(const std::string& tag, const std::shared_ptr<CancelState>& ticket)
    {
        CancelResult result;
        if (tag.empty())
        {
            return result; // "No tag" (OpState::tag): never matches; the writer refuses it before.
        }
        std::lock_guard<std::mutex> lock(m_mutex);
        // The removed ops stay charged (payloadCharged, retained) until the caller resolves them, as close().
        const auto drain = [&](std::deque<std::shared_ptr<OpState>>& queue, bool lane)
        {
            auto out = queue.begin();
            for (auto it = queue.begin(); it != queue.end(); ++it)
            {
                if ((*it)->tag != tag)
                {
                    if (out != it)
                    {
                        *out = std::move(*it);
                    }
                    ++out;
                    continue;
                }
                if (lane)
                {
                    laneRemovedLocked(**it);
                }
                else
                {
                    m_pendingBytes -= (*it)->wire();
                }
                result.removed.push_back(std::move(*it));
            }
            queue.erase(out, queue.end());
        };
        drain(m_lane, true);
        drain(m_pending, false);
        m_blockedPrefix = 0; // Both queues may have lost ops anywhere.

        std::uint64_t remaining = 0;
        for (const auto& entry : m_delivered)
        {
            if (entry.second->tag == tag)
            {
                entry.second->cancelled.store(true);
                ++remaining;
            }
        }
        if (remaining != 0)
        {
            m_cancelWaiters.push_back(CancelWaiter {tag, m_nextSeq, remaining, ticket});
            result.waiting = true;
        }
        return result;
    }

    bool Bucket::pinnedNodeUsable(std::size_t node, TimePoint now)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_spec.ordered || m_lanePinned == 0)
        {
            return false;
        }
        // The ops made due now leave the lane and re-enter it by their new notBefore (insertLaneLocked: after every op
        // due no later, in their previous relative order), so the lane stays ordered by notBefore.
        std::vector<std::shared_ptr<OpState>> moved;
        auto out = m_lane.begin();
        for (auto it = m_lane.begin(); it != m_lane.end(); ++it)
        {
            auto& op = *it;
            if (op->pinNode && *op->pinNode == node && op->pinUntil > now && op->notBefore > now)
            {
                laneRemovedLocked(*op);
                op->notBefore = now;
                moved.push_back(std::move(op));
                continue;
            }
            if (out != it)
            {
                *out = std::move(op);
            }
            ++out;
        }
        m_lane.erase(out, m_lane.end());
        for (auto& op : moved)
        {
            insertLaneLocked(std::move(op));
        }
        return !moved.empty();
    }

    void Bucket::countAmbiguousFailover(std::uint64_t ops)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_stats.orderedAmbiguousFailover += ops;
    }

    void Bucket::countCancelled(std::uint64_t ops)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_stats.cancelled += ops;
    }

    void Bucket::countInvalidArgument()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        ++m_stats.submitted;
        ++m_stats.invalidArgument;
    }

    BucketStats Bucket::stats() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        BucketStats stats = m_stats;
        stats.charge = m_charge;
        return stats;
    }

    BucketMetrics Bucket::metrics() const
    {
        BucketMetrics metrics;
        metrics.consumer = m_consumer;
        metrics.bucket = m_spec.name;
        metrics.quotaBytes = m_spec.quotaBytes;
        std::lock_guard<std::mutex> lock(m_mutex);
        const auto& s = m_stats;
        metrics.accepted = s.accepted;
        metrics.rejected[at(RejectCause::QueueFull)] = s.rejectedQueueFull;
        metrics.rejected[at(RejectCause::ClientClosed)] = s.rejectedClosed - s.rejectedShutdown;
        metrics.rejected[at(RejectCause::Shutdown)] = s.rejectedShutdown;
        metrics.rejected[at(RejectCause::SubmitTimeout)] = s.submitTimeout;
        metrics.rejected[at(RejectCause::Reentrancy)] = s.reentrancy;
        metrics.rejected[at(RejectCause::PayloadTooLarge)] = s.payloadTooLarge;
        metrics.rejected[at(RejectCause::GroupTooLarge)] = s.rejectedGroupTooLarge;
        metrics.rejected[at(RejectCause::InvalidArgument)] = s.invalidArgument;
        metrics.dropped = s.dropped;
        metrics.ok = s.resolvedOk;
        metrics.failed = s.failed;
        metrics.retries = s.retries;
        metrics.lateResults = s.lateResults;
        metrics.retainedBytes = s.retainedBytes;
        metrics.charge = m_charge;
        metrics.bulkRequests = s.bulkRequests;
        metrics.bulkBytes = s.bulkBytes;
        metrics.latency = s.latency;
        return metrics;
    }

    std::uint64_t Bucket::retainedBytes() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_stats.retainedBytes;
    }

    LogInterval Bucket::takeLogInterval()
    {
        LogInterval interval;
        std::lock_guard<std::mutex> lock(m_mutex);
        interval = std::move(m_interval);
        m_interval = LogInterval {};
        interval.accepted = m_stats.accepted - m_logMark.accepted;
        interval.ok = m_stats.resolvedOk - m_logMark.ok;
        interval.failed = m_stats.resolvedFailed - m_logMark.failed;
        interval.dropped = m_stats.resolvedDropped - m_logMark.dropped;
        m_logMark = LogMark {m_stats.accepted, m_stats.resolvedOk, m_stats.resolvedFailed, m_stats.resolvedDropped};
        return interval;
    }

    void Bucket::insertLaneLocked(std::shared_ptr<OpState> op)
    {
        // After the last lane op due no later than this one (stable for ties). A toHead prefix with a later notBefore
        // is skipped over only by an op due earlier than it, which is due before it anyway.
        auto it = m_lane.end();
        while (it != m_lane.begin() && (*std::prev(it))->notBefore > op->notBefore)
        {
            --it;
        }
        laneAddedLocked(*op);
        m_lane.insert(it, std::move(op));
    }

    RequeueResult Bucket::requeue(std::vector<RequeueOp> ops, const RequeueSpec& spec, TimePoint now)
    {
        RequeueResult result;
        const double u = spec.delay == RequeueSpec::Delay::Backoff ? jitterDraw() : 0.0;
        std::uint64_t batchBytes = 0;
        for (const auto& entry : ops)
        {
            if (entry.op)
            {
                batchBytes += entry.op->wire();
            }
        }
        const std::uint64_t halfCap = (batchBytes + 1) / 2;

        std::vector<std::shared_ptr<OpState>> toHead;
        std::lock_guard<std::mutex> lock(m_mutex);
        // I79: one pin for the whole batch; an op already pinned keeps its `until` (so does the batch: it was sliced
        // under the pin gate, so its pinned ops share it).
        const bool setPin = m_spec.ordered && spec.pin == RequeueSpec::Pin::Set;
        TimePoint pinUntil = spec.pinUntil;
        if (setPin)
        {
            for (const auto& entry : ops)
            {
                if (entry.op && entry.op->pinNode && m_delivered.count(entry.op.get()) != 0)
                {
                    pinUntil = entry.op->pinUntil;
                    break;
                }
            }
        }
        const std::optional<TimePoint> headBefore =
            m_lane.empty() ? std::nullopt : std::optional<TimePoint> {m_lane.front()->notBefore};
        for (auto& entry : ops)
        {
            auto& op = entry.op;
            if (!op)
            {
                continue;
            }
            if (op->claimed.load())
            {
                ++result.skipped;
                continue; // Resolved (or being resolved) by someone else.
            }
            const auto delivered = m_delivered.find(op.get());
            if (delivered == m_delivered.end())
            {
                ++result.skipped;
                continue; // Not delivered by this bucket (already resolved): nothing to requeue.
            }
            if (op->cancelled.load())
            {
                // I80: never back to the lane; cancellation wins over exhaustion and close. Stays delivered until
                // the caller resolves it Dropped(Cancelled) (releasePayload decrements the waiters).
                result.cancelled.push_back(std::move(op));
                continue;
            }
            if (entry.lastError.cause != Cause::None)
            {
                op->lastCause = entry.lastError.cause;
                op->lastHttpStatus = entry.lastError.httpStatus;
                op->lastItemErrorType = std::move(entry.lastError.itemErrorType);
                op->lastReason = std::move(entry.lastError.reason);
            }
            if (m_closed)
            {
                result.closed.push_back(std::move(op)); // Stays delivered: the caller (or the sweep) resolves it.
                continue;
            }
            if (spec.countAttempt)
            {
                ++op->attempts;
            }
            const auto& retry = m_spec.retry;
            const bool attemptsSpent = retry.maxAttempts && op->attempts >= *retry.maxAttempts;
            const bool durationSpent =
                retry.maxDuration && op->firstAttempt != TimePoint {} && now - op->firstAttempt >= *retry.maxDuration;
            if (attemptsSpent || durationSpent)
            {
                result.exhaustedErrors.push_back(
                    LastError {op->lastCause, op->lastHttpStatus, op->lastItemErrorType, op->lastReason});
                result.exhausted.push_back(std::move(op)); // Stays delivered until resolved.
                continue;
            }
            switch (spec.delay)
            {
                case RequeueSpec::Delay::Backoff:
                    op->notBefore = now + backoffDelay(retry, std::max<std::uint32_t>(op->attempts, 1), u);
                    break;
                case RequeueSpec::Delay::At: op->notBefore = spec.at; break;
                case RequeueSpec::Delay::Now: op->notBefore = now; break;
            }
            if (spec.toHead)
            {
                // A head op is due now by construction, so the lane head stays its minimum notBefore (G-diff E3b-1
                // obj. 3): eligible/headBytes/nextDue read only the front.
                op->notBefore = now;
            }
            if (spec.halve)
            {
                op->batchCap = halfCap;
            }
            if (setPin)
            {
                op->pinNode = spec.pinNode;
                op->pinUntil = pinUntil;
                ++m_stats.orderedAmbiguous;
            }
            else if (m_spec.ordered && spec.pin == RequeueSpec::Pin::Clear)
            {
                op->pinNode.reset();
                op->pinUntil = TimePoint {};
            }
            if (spec.countAttempt)
            {
                ++m_stats.retries[at(retryCause(op->lastCause))]; // E5c: back to the lane with a counted attempt.
            }
            m_delivered.erase(delivered);
            if (spec.toHead)
            {
                toHead.push_back(std::move(op));
            }
            else
            {
                insertLaneLocked(std::move(op));
            }
        }
        for (const auto& op : toHead)
        {
            laneAddedLocked(*op);
        }
        m_lane.insert(m_lane.begin(), std::make_move_iterator(toHead.begin()), std::make_move_iterator(toHead.end()));
        result.notify = !m_lane.empty() && (!headBefore || m_lane.front()->notBefore < *headBefore);
        return result;
    }
} // namespace indexer_client::detail::write
