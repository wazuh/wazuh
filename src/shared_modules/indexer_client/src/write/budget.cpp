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

#include "write/budget.hpp"

#include <algorithm>

#include "loggerHelper.h"
#include "write/bucket.hpp"

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
    } // namespace

    GlobalBudget::GlobalBudget(std::uint64_t cap)
        : m_cap(cap)
        , m_threshold80(percentOf(cap, 80))
        , m_threshold70(percentOf(cap, 70))
    {
    }

    bool GlobalBudget::tryReserve(std::uint64_t bytes) noexcept
    {
        // E5c: no line here (it runs under a bucket mutex); an edge is only claimed, emitPendingLogs() writes it.
        const auto refuse = [this](std::uint64_t charge)
        {
            if (m_armedFull.load(std::memory_order_relaxed) && m_armedFull.exchange(false))
            {
                m_pendingFullCharge.store(charge);
                m_pendingFull.store(true);
            }
            return false;
        };
        if (bytes > m_cap)
        {
            return false; // Never fits (PayloadTooLarge, checked by the bucket before): not an overflow.
        }
        auto current = m_charge.load();
        do
        {
            if (current > m_cap - bytes)
            {
                return refuse(current);
            }
        } while (!m_charge.compare_exchange_weak(current, current + bytes));
        if (current + bytes >= m_threshold80 && m_armed80.load(std::memory_order_relaxed) && m_armed80.exchange(false))
        {
            m_pending80Charge.store(current + bytes);
            m_pending80.store(true);
        }
        return true;
    }

    void GlobalBudget::emitPendingLogs() noexcept
    {
        try
        {
            if (m_pending80.load(std::memory_order_relaxed) && m_pending80.exchange(false))
            {
                logWarn(TAG,
                        "Indexer client global quota reached 80%% (%llu of %llu bytes charged).",
                        static_cast<unsigned long long>(m_pending80Charge.load()),
                        static_cast<unsigned long long>(m_cap));
            }
            if (m_pendingFull.load(std::memory_order_relaxed) && m_pendingFull.exchange(false))
            {
                logWarn(TAG,
                        "Indexer client global quota is full (%llu of %llu bytes charged): every bucket applies its "
                        "overflow policy.",
                        static_cast<unsigned long long>(m_pendingFullCharge.load()),
                        static_cast<unsigned long long>(m_cap));
            }
        }
        catch (...)
        {
            // A log sink must never take a producer or a runtime thread down.
        }
    }

    void GlobalBudget::release(std::uint64_t bytes)
    {
        if (bytes == 0)
        {
            return;
        }
        // seq_cst on both sides (here and in addWaiter + the CAS of a waiter's re-check): either this load sees the
        // waiter registered, or the waiter's re-check sees the released bytes.
        const auto before = m_charge.fetch_sub(bytes);
        if (before >= m_threshold70 && before - bytes < m_threshold70)
        {
            // E5c: crossing 70 % downwards re-arms both edges (an edge, not a level).
            m_armed80.store(true);
            m_armedFull.store(true);
        }
        if (m_waiterCount.load() != 0)
        {
            wakeWaiters();
        }
    }

    std::uint64_t GlobalBudget::charge() const noexcept
    {
        return m_charge.load();
    }

    std::uint64_t GlobalBudget::cap() const noexcept
    {
        return m_cap;
    }

    void GlobalBudget::addBuilding(std::uint64_t bytes) noexcept
    {
        m_building.fetch_add(bytes);
    }

    void GlobalBudget::removeBuilding(std::uint64_t bytes) noexcept
    {
        m_building.fetch_sub(bytes);
    }

    std::uint64_t GlobalBudget::building() const noexcept
    {
        return m_building.load();
    }

    void GlobalBudget::addWaiter(const std::shared_ptr<Bucket>& bucket)
    {
        std::lock_guard<std::mutex> lock(m_waitersMutex);
        const auto* key = bucket.get();
        if (std::none_of(m_waiters.begin(), m_waiters.end(), [key](const Waiter& w) { return w.key == key; }))
        {
            m_waiters.push_back(Waiter {key, bucket});
            m_waiterCount.store(m_waiters.size());
        }
    }

    void GlobalBudget::removeWaiter(const Bucket* bucket)
    {
        std::lock_guard<std::mutex> lock(m_waitersMutex);
        // The weak_ptr is dropped here, under the registry mutex: it never owns the bucket, so nothing is destroyed.
        m_waiters.erase(
            std::remove_if(m_waiters.begin(), m_waiters.end(), [bucket](const Waiter& w) { return w.key == bucket; }),
            m_waiters.end());
        m_waiterCount.store(m_waiters.size());
    }

    void GlobalBudget::wakeWaiters()
    {
        // seq_cst, as in release(): a waiter registers (m_waiterCount) before its predicate re-reads charge() and
        // building(), so either this load sees it or its re-check sees what the caller changed before calling.
        if (m_waiterCount.load() == 0)
        {
            return;
        }
        std::vector<std::weak_ptr<Bucket>> copy;
        {
            std::lock_guard<std::mutex> lock(m_waitersMutex);
            copy.reserve(m_waiters.size());
            for (const auto& waiter : m_waiters)
            {
                copy.push_back(waiter.bucket);
            }
        }
        for (const auto& weak : copy)
        {
            // Each bucket alone, with no other lock held; the temporary owner may be the last one, which is fine here.
            if (const auto bucket = weak.lock())
            {
                bucket->wakeWaiters();
            }
        }
    }
} // namespace indexer_client::detail::write
