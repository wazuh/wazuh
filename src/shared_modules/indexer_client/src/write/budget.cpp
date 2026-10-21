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

#include "write/bucket.hpp"

namespace indexer_client::detail::write
{
    GlobalBudget::GlobalBudget(std::uint64_t cap)
        : m_cap(cap)
    {
    }

    bool GlobalBudget::tryReserve(std::uint64_t bytes) noexcept
    {
        if (bytes > m_cap)
        {
            return false;
        }
        auto current = m_charge.load();
        do
        {
            if (current > m_cap - bytes)
            {
                return false;
            }
        } while (!m_charge.compare_exchange_weak(current, current + bytes));
        return true;
    }

    void GlobalBudget::release(std::uint64_t bytes)
    {
        if (bytes == 0)
        {
            return;
        }
        // seq_cst on both sides (here and in addWaiter + the CAS of a waiter's re-check): either this load sees the
        // waiter registered, or the waiter's re-check sees the released bytes.
        m_charge.fetch_sub(bytes);
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
