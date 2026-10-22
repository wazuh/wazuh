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
#include <cassert>
#include <chrono>
#include <unordered_set>
#include <utility>

#include "indexer_client/runtime.hpp"
#include "runtime/backoff.hpp"
#include "runtime/runtimeInternal.hpp"
#include "write/budget.hpp"
#include "write/group.hpp"

namespace indexer_client::detail::write
{
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

    Bucket::Bucket(std::string consumer, BucketSpec spec, GlobalBudget& budget, std::weak_ptr<WritePath> owner)
        : m_consumer(std::move(consumer))
        , m_spec(std::move(spec))
        , m_budget(budget)
        , m_owner(std::move(owner))
    {
        m_stats.consumer = m_consumer;
        m_stats.bucket = m_spec.name;
    }

    Bucket::~Bucket()
    {
        // No other reference exists, so no lock.
        // I99 (N6), the last net: with the close fixed (the racing enqueue refuses, a Client destroyed on a runtime
        // thread sweeps) nothing is still queued here. A debug build asserts it; a release build completes what is
        // left (ticket or group slot; the callback is not called) and returns its charge to the global cap while the
        // write path, owner of that budget, is alive. Only the ops' own charge: a ticket's reserve handle and a
        // GroupState return theirs.
        const bool leftovers = !m_pending.empty() || !m_lane.empty();
        assert(!leftovers && "a bucket destroyed with queued operations");
        if (leftovers)
        {
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
                    if (op->callback && op->reserveCharged)
                    {
                        charge += RESULT_RESERVE; // No callback runs to return it.
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

    void Bucket::addChargeLocked(std::uint64_t bytes) noexcept
    {
        m_charge += bytes;
        m_stats.peakCharge = std::max(m_stats.peakCharge, m_charge);
    }

    bool Bucket::tryChargeLocked(std::uint64_t charge)
    {
        if (charge > m_spec.quotaBytes || m_charge > m_spec.quotaBytes - charge)
        {
            return false;
        }
        if (!m_budget.tryReserve(charge))
        {
            return false;
        }
        addChargeLocked(charge);
        return true;
    }

    void Bucket::dropNewestLocked(bool withCallback, Reservation& reservation)
    {
        if (withCallback && !tryChargeLocked(RESULT_RESERVE))
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

        reservation.evicted.reserve(count);
        for (std::size_t i = 0; i < count; ++i)
        {
            auto op = std::move(m_pending.front());
            m_pending.pop_front();
            m_pendingBytes -= op->lines.size();
            op->payloadCharged = false;
            --m_stats.retained;
            reservation.evicted.push_back(std::move(op));
        }
        m_charge -= freed;
        addChargeLocked(charge);
        ++m_stats.accepted;
        m_stats.droppedOldest += count;
        return true;
    }

    Reservation Bucket::reserve(std::uint64_t payload, bool withCallback, TimePoint blockUntil)
    {
        const std::uint64_t charge = payload + RESULT_RESERVE;
        Reservation reservation;
        std::uint64_t globalSurplus = 0;
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            ++m_stats.submitted;
            if (m_admission)
            {
                ++m_stats.rejectedClosed;
                reservation.cause = *m_admission;
                return reservation;
            }
            if (payload > m_spec.bulk.maxBytes || charge > m_spec.quotaBytes || charge > m_budget.cap())
            {
                ++m_stats.payloadTooLarge;
                reservation.cause = Cause::PayloadTooLarge;
                return reservation;
            }
            if (tryChargeLocked(charge))
            {
                ++m_stats.accepted;
                return reservation;
            }

            switch (m_spec.overflow.kind)
            {
                case Overflow::Kind::Reject:
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
                                          charged = tryChargeLocked(charge);
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
                        ++m_stats.rejectedClosed;
                        reservation.cause = *m_admission;
                    }
                    else
                    {
                        ++m_stats.submitTimeout;
                        reservation.cause = Cause::SubmitTimeout;
                    }
                    break;
                }

                case Overflow::Kind::DropNewest: dropNewestLocked(withCallback, reservation); break;

                case Overflow::Kind::DropOldest:
                    if (!evictOldestLocked(charge, reservation, globalSurplus))
                    {
                        dropNewestLocked(withCallback, reservation);
                    }
                    break;
            }
        }
        m_budget.release(globalSurplus);
        return reservation;
    }

    Reservation Bucket::reserveForGroup(std::uint64_t payload, std::uint64_t groupReserved, TimePoint blockUntil)
    {
        const std::uint64_t charge = payload + RESULT_RESERVE;
        Reservation reservation;
        bool charged = false;
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            ++m_stats.submitted;
            if (m_admission)
            {
                ++m_stats.rejectedClosed;
                reservation.cause = *m_admission;
                return reservation;
            }
            if (payload > m_spec.bulk.maxBytes || charge > m_spec.quotaBytes || charge > m_budget.cap())
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
            charged = tryChargeLocked(charge);
            if (!charged)
            {
                if (m_spec.overflow.kind != Overflow::Kind::Block)
                {
                    // Reject, DropNewest and DropOldest alike (I70): nothing is dropped or evicted for a group op.
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
                                      charged = tryChargeLocked(charge);
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
                        ++m_stats.rejectedClosed;
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
        if (op.bucket.expired())
        {
            op.bucket = weak_from_this();
        }
        op.payloadCharged = true;
        op.seq = m_nextSeq++;
        ++m_stats.retained;
    }

    std::optional<Cause> Bucket::refusalCauseLocked() const
    {
        // The sweep's cause when there was one (during stop() everything is Shutdown), else the admission's.
        return m_closed ? m_closed : m_admission;
    }

    bool Bucket::enqueue(std::shared_ptr<OpState> op, std::optional<Cause>* closed)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        const auto now = std::chrono::steady_clock::now();
        if (m_admission)
        {
            // I99 (N2): refused, never queued. The payload passes to the bucket's custody exactly as an accepted op's
            // (payloadCharged, retained), so the caller's WritePath::resolve releases it through releasePayload.
            takeCustodyLocked(*op, now);
            if (closed)
            {
                *closed = refusalCauseLocked();
            }
            return false;
        }
        if (closed)
        {
            closed->reset();
        }
        const bool wasEmpty = m_pending.empty();
        const std::uint64_t bytesBefore = m_pendingBytes;
        const std::size_t docsBefore = m_pending.size();

        takeCustodyLocked(*op, now);
        m_pendingBytes += op->lines.size();
        m_pending.push_back(std::move(op));

        const auto maxBytes = static_cast<std::uint64_t>(m_spec.bulk.maxBytes);
        const auto maxDocs = m_spec.bulk.maxDocs;
        const bool crossed = wasEmpty || (bytesBefore < maxBytes && m_pendingBytes >= maxBytes) ||
                             (docsBefore < maxDocs && m_pending.size() >= maxDocs);
        return crossed && !m_notified.exchange(true);
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
            // I99 (N2): as enqueue, custody without queuing; the `building` transfer above happened all the same.
            for (auto& op : ops)
            {
                takeCustodyLocked(*op, now);
            }
            return false;
        }
        for (auto& op : ops)
        {
            takeCustodyLocked(*op, now);
            m_pendingBytes += op->lines.size();
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
            m_charge -= reserved;
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
                scan.head = op->lines.size();
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
        const std::size_t limit = std::min<std::size_t>(m_pending.size(), m_spec.bulk.maxDocs);
        for (std::size_t i = 0; i < limit; ++i)
        {
            if (!laneBlocksLocked(*m_pending[i]))
            {
                return i;
            }
        }
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
            return m_lane.front()->lines.size();
        }
        const auto first = firstTakeablePendingLocked();
        return first ? m_pending[*first]->lines.size() : 0;
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
            return m_lane.front()->lines.size();
        }
        return m_pending.empty() ? 0 : m_pending.front()->lines.size();
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

    Batch Bucket::slice(std::uint64_t credit, TimePoint now, std::uint64_t cap)
    {
        Batch batch;
        std::lock_guard<std::mutex> lock(m_mutex);
        const auto maxBytes = static_cast<std::uint64_t>(m_spec.bulk.maxBytes);
        const auto maxDocs = m_spec.bulk.maxDocs;
        std::uint64_t opsCap = 0; // Smallest batchCap of the ops taken (0 = none): split halves never merge again.
        // Whether `op` joins the batch; a document is never split: the head goes alone whenever the credit covers it
        // (`cap`, the sink's batch limit, never refuses the first op).
        const auto fits = [&](const OpState& op)
        {
            const std::uint64_t size = op.lines.size();
            if (batch.ops.empty())
            {
                return size <= credit;
            }
            const std::uint64_t opCap =
                op.batchCap == 0 ? opsCap : (opsCap == 0 ? op.batchCap : std::min(opsCap, op.batchCap));
            return batch.bytes + size <= credit && batch.bytes + size <= maxBytes && batch.ops.size() < maxDocs &&
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
            batch.bytes += op->lines.size();
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
                // The pending queue in order, at most bulk.maxDocs ops visited: blocked ones are skipped and keep
                // their place; the scan stops at the first takeable op that does not fit.
                std::vector<std::shared_ptr<OpState>> skipped;
                std::size_t visited = 0;
                const std::size_t limit = full ? 0 : std::min<std::size_t>(m_pending.size(), maxDocs);
                for (; visited < limit; ++visited)
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
                    m_pendingBytes -= op->lines.size();
                    if (op->hasKey)
                    {
                        taken.insert(op->keyHash);
                    }
                    take(std::move(op));
                }
                m_pending.erase(m_pending.begin(), m_pending.begin() + static_cast<std::ptrdiff_t>(visited));
                m_pending.insert(m_pending.begin(),
                                 std::make_move_iterator(skipped.begin()),
                                 std::make_move_iterator(skipped.end()));
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
            m_pendingBytes -= op->lines.size();
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

    void Bucket::releasePayload(OpState& op)
    {
        std::shared_ptr<OpState> keep; // Dropped after the mutex: the op (and its TicketState) never dies under it.
        std::uint64_t released = 0;
        std::vector<std::shared_ptr<CancelState>> cancelDone; // Completed after the mutex (I80).
        {
            std::lock_guard<std::mutex> lock(m_mutex);
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
                const auto lane =
                    std::find_if(m_lane.begin(),
                                 m_lane.end(),
                                 [&op](const std::shared_ptr<OpState>& entry) { return entry.get() == &op; });
                if (lane != m_lane.end())
                {
                    laneRemovedLocked(op);
                    keep = std::move(*lane);
                    m_lane.erase(lane);
                }
            }
            if (op.payloadCharged)
            {
                op.payloadCharged = false;
                released = op.payload;
                m_charge -= released;
                --m_stats.retained;
                if (m_waiting != 0)
                {
                    m_room.notify_all();
                }
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

    void Bucket::releaseReserve(std::uint32_t count)
    {
        const std::uint64_t bytes = RESULT_RESERVE * count;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_charge -= bytes;
            if (m_waiting != 0)
            {
                m_room.notify_all();
            }
        }
        m_budget.release(bytes);
    }

    std::vector<std::shared_ptr<OpState>> Bucket::close(Cause cause)
    {
        std::vector<std::shared_ptr<OpState>> pending; // Lane first, then pending.
        std::lock_guard<std::mutex> lock(m_mutex);
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
        for (auto& op : m_pending)
        {
            pending.push_back(std::move(op));
        }
        m_pending.clear();
        m_pendingBytes = 0;
        m_room.notify_all();
        return pending;
    }

    void Bucket::closeAdmission(Cause cause)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
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

    void Bucket::countResolved(Status status)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        switch (status)
        {
            case Status::Ok: ++m_stats.resolvedOk; break;
            case Status::Failed: ++m_stats.resolvedFailed; break;
            case Status::Dropped: ++m_stats.resolvedDropped; break;
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
                    m_pendingBytes -= (*it)->lines.size();
                }
                result.removed.push_back(std::move(*it));
            }
            queue.erase(out, queue.end());
        };
        drain(m_lane, true);
        drain(m_pending, false);

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
                batchBytes += entry.op->lines.size();
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
            if (!op || op->claimed.load())
            {
                continue; // Resolved (or being resolved) by someone else.
            }
            const auto delivered = m_delivered.find(op.get());
            if (delivered == m_delivered.end())
            {
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
