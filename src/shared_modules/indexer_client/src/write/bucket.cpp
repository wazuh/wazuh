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
#include <random>
#include <utility>

#include "indexer_client/runtime.hpp"
#include "write/budget.hpp"

namespace indexer_client::detail::write
{
    namespace
    {
        /// Uniform in [-1, 1], one draw per requeue (the ops of one batch keep travelling together).
        double jitterDraw()
        {
            thread_local std::mt19937_64 engine {std::random_device {}()};
            return std::uniform_real_distribution<double>(-1.0, 1.0)(engine);
        }

        /// I66: d = min(cap, base * 2^(attempts - 1)) with the exponent bounded (d = cap as soon as doubling reaches
        /// it, so an unlimited policy never overflows), then d * (1 + jitter * u), clamped to [0, cap].
        Duration backoffDelay(const RetryPolicy& retry, std::uint32_t attempts, double u)
        {
            using Rep = Duration::rep;
            const Rep cap = std::max<Rep>(retry.cap.count(), 0);
            Rep d = std::min<Rep>(std::max<Rep>(retry.base.count(), 0), cap);
            for (std::uint32_t k = 1; k < attempts && d < cap; ++k)
            {
                d = d > cap / 2 ? cap : d * 2;
            }
            const double scaled = static_cast<double>(d) * (1.0 + retry.jitter * u);
            if (!(scaled > 0.0)) // Also NaN.
            {
                return Duration::zero();
            }
            return scaled >= static_cast<double>(cap) ? Duration {cap} : Duration {static_cast<Rep>(scaled)};
        }
    } // namespace

    Bucket::Bucket(std::string consumer, BucketSpec spec, GlobalBudget& budget)
        : m_consumer(std::move(consumer))
        , m_spec(std::move(spec))
        , m_budget(budget)
    {
        m_stats.consumer = m_consumer;
        m_stats.bucket = m_spec.name;
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
            if (m_closed)
            {
                ++m_stats.rejectedClosed;
                reservation.cause = *m_closed;
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
                                          if (m_closed)
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
                    else if (m_closed)
                    {
                        ++m_stats.rejectedClosed;
                        reservation.cause = *m_closed;
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

    bool Bucket::enqueue(std::shared_ptr<OpState> op, std::optional<Cause>* closed)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (closed)
        {
            *closed = m_closed;
        }
        const bool wasEmpty = m_pending.empty();
        const std::uint64_t bytesBefore = m_pendingBytes;
        const std::size_t docsBefore = m_pending.size();

        if (op->firstSubmit == TimePoint {})
        {
            op->firstSubmit = std::chrono::steady_clock::now();
        }
        if (op->bucket.expired())
        {
            op->bucket = weak_from_this();
        }
        op->payloadCharged = true;
        ++m_stats.retained;
        m_pendingBytes += op->lines.size();
        m_pending.push_back(std::move(op));

        const auto maxBytes = static_cast<std::uint64_t>(m_spec.bulk.maxBytes);
        const auto maxDocs = m_spec.bulk.maxDocs;
        const bool crossed = wasEmpty || (bytesBefore < maxBytes && m_pendingBytes >= maxBytes) ||
                             (docsBefore < maxDocs && m_pending.size() >= maxDocs);
        return crossed && !m_notified.exchange(true);
    }

    bool Bucket::laneDueLocked(TimePoint now) const
    {
        return !m_lane.empty() && m_lane.front()->notBefore <= now;
    }

    bool Bucket::eligible(TimePoint now) const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (laneDueLocked(now))
        {
            return true;
        }
        if (m_pending.empty())
        {
            return false;
        }
        return m_pendingBytes >= m_spec.bulk.maxBytes || m_pending.size() >= m_spec.bulk.maxDocs ||
               now - m_pending.front()->firstSubmit >= m_spec.bulk.maxAge;
    }

    std::optional<TimePoint> Bucket::nextDueLocked() const
    {
        std::optional<TimePoint> due;
        if (!m_pending.empty())
        {
            due = m_pending.front()->firstSubmit + m_spec.bulk.maxAge;
        }
        if (!m_lane.empty() && (!due || m_lane.front()->notBefore < *due))
        {
            due = m_lane.front()->notBefore;
        }
        return due;
    }

    std::optional<TimePoint> Bucket::oldestPending() const
    {
        // The scheduler arms its timer at oldestPending() + maxAge: the lane head is reported shifted back by maxAge
        // so that the timer fires at its notBefore (I66).
        std::lock_guard<std::mutex> lock(m_mutex);
        const auto due = nextDueLocked();
        if (!due)
        {
            return std::nullopt;
        }
        return *due - m_spec.bulk.maxAge;
    }

    std::uint64_t Bucket::headBytes(TimePoint now) const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
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

    std::optional<TimePoint> Bucket::nextDue(TimePoint /*now*/) const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return nextDueLocked();
    }

    Batch Bucket::slice(std::uint64_t credit, TimePoint now)
    {
        Batch batch;
        std::lock_guard<std::mutex> lock(m_mutex);
        const auto maxBytes = static_cast<std::uint64_t>(m_spec.bulk.maxBytes);
        const auto maxDocs = m_spec.bulk.maxDocs;
        std::uint64_t cap = 0; // Smallest batchCap of the ops taken (0 = none): split halves never merge again.
        // Whether `op` joins the batch; a document is never split: the head goes alone whenever the credit covers it.
        const auto fits = [&](const OpState& op)
        {
            const std::uint64_t size = op.lines.size();
            if (batch.ops.empty())
            {
                return size <= credit;
            }
            const std::uint64_t opCap = op.batchCap == 0 ? cap : (cap == 0 ? op.batchCap : std::min(cap, op.batchCap));
            return batch.bytes + size <= credit && batch.bytes + size <= maxBytes && batch.ops.size() < maxDocs &&
                   (opCap == 0 || batch.bytes + size <= opCap);
        };
        const auto take = [&](std::shared_ptr<OpState> op)
        {
            if (op->batchCap != 0)
            {
                cap = cap == 0 ? op->batchCap : std::min(cap, op->batchCap);
            }
            if (op->firstAttempt == TimePoint {})
            {
                op->firstAttempt = now;
            }
            batch.bytes += op->lines.size();
            m_delivered.emplace(op.get(), op);
            batch.ops.push_back(std::move(op));
        };
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
        {
            std::lock_guard<std::mutex> lock(m_mutex);
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
            }
        }
        m_budget.release(released);
    }

    void Bucket::releaseReserve()
    {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_charge -= RESULT_RESERVE;
            if (m_waiting != 0)
            {
                m_room.notify_all();
            }
        }
        m_budget.release(RESULT_RESERVE);
    }

    std::vector<std::shared_ptr<OpState>> Bucket::close(Cause cause)
    {
        std::vector<std::shared_ptr<OpState>> pending; // Lane first, then pending.
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_closed)
        {
            m_closed = cause;
        }
        pending.reserve(m_lane.size() + m_pending.size());
        for (auto& op : m_lane)
        {
            pending.push_back(std::move(op));
        }
        m_lane.clear();
        for (auto& op : m_pending)
        {
            pending.push_back(std::move(op));
        }
        m_pending.clear();
        m_pendingBytes = 0;
        m_room.notify_all();
        return pending;
    }

    std::optional<Cause> Bucket::closedCause() const
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
            op->lastCause = entry.lastError.cause;
            op->lastHttpStatus = entry.lastError.httpStatus;
            op->lastItemErrorType = std::move(entry.lastError.itemErrorType);
            op->lastReason = std::move(entry.lastError.reason);
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
        m_lane.insert(m_lane.begin(), std::make_move_iterator(toHead.begin()), std::make_move_iterator(toHead.end()));
        result.notify = !m_lane.empty() && (!headBefore || m_lane.front()->notBefore < *headBefore);
        return result;
    }
} // namespace indexer_client::detail::write
