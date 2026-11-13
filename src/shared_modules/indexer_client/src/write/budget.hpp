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

#ifndef _INDEXER_CLIENT_WRITE_BUDGET_HPP
#define _INDEXER_CLIENT_WRITE_BUDGET_HPP

// The runtime-wide cap of retained bytes and the set of buckets with blocked producers.

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <vector>

namespace indexer_client::detail::write
{
    class Bucket;

    /// The global cap (RuntimeConfig.globalQuotaBytes). Lock-free: reservations are a CAS loop, never fetch_add plus
    /// rollback (a transient over-reservation would refuse other buckets spuriously).
    class GlobalBudget final
    {
    public:
        explicit GlobalBudget(std::uint64_t cap);

        /// True and charged when `bytes` fit under the cap; false and nothing charged otherwise.
        bool tryReserve(std::uint64_t bytes) noexcept;
        /// Returns `bytes`; then wakes the blocked producers through the registry (see Waiters). A charge that
        /// crosses 70 % of the cap downwards re-arms both quota edges (runtime/logSummary.hpp).
        void release(std::uint64_t bytes);

        /// (runtime/logSummary.hpp QUOTA EDGES) Emits the global cap's edge lines claimed by tryReserve (a CAS
        /// that reached 80 % of the cap, a refusal) while armed. Never called under a bucket mutex: Bucket::reserve and
        /// reserveForGroup call it after theirs is dropped, and the log summary's timer drains it too.
        void emitPendingLogs() noexcept;

        std::uint64_t charge() const noexcept;
        std::uint64_t cap() const noexcept;

        /// Charge held by Building groups of every bucket: a group add that cannot fit without other
        /// Building groups' room never waits. Also part of charge(). addBuilding never wakes (the caller wakes the
        /// waiters with wakeWaiters(), holding no bucket mutex).
        void addBuilding(std::uint64_t bytes) noexcept;
        void removeBuilding(std::uint64_t bytes) noexcept;
        std::uint64_t building() const noexcept;

        /// Buckets with at least one producer waiting in a Block submit. A bucket enters and leaves under its own
        /// mutex (the registry mutex is the only lock ever taken inside a bucket's, and it is a leaf); a release copies
        /// the set under the registry mutex, drops it, and then takes each bucket's mutex (alone) to notify_all: the
        /// registry is never held while a bucket mutex is taken, no lost wake-up. A bucket registers before it checks
        /// the cap, so a release either sees it registered or happened before that check.
        void addWaiter(const std::shared_ptr<Bucket>& bucket);
        void removeWaiter(const Bucket* bucket);
        void wakeWaiters();

    private:
        struct Waiter final
        {
            const Bucket* key {nullptr}; ///< Identity only (removeWaiter); never dereferenced.
            std::weak_ptr<Bucket> bucket;
        };

        const std::uint64_t m_cap;
        const std::uint64_t m_threshold80; ///< 80 % and 70 % of m_cap, rounded down (the quota edges).
        const std::uint64_t m_threshold70;
        std::atomic<std::uint64_t> m_charge {0};
        // Quota edges: armed flags claimed with exchange (one line per crossing under concurrency), the claimed
        // lines waiting for emitPendingLogs(), and the charge each one saw.
        std::atomic<bool> m_armed80 {true};
        std::atomic<bool> m_armedFull {true};
        std::atomic<bool> m_pending80 {false};
        std::atomic<bool> m_pendingFull {false};
        std::atomic<std::uint64_t> m_pending80Charge {0};
        std::atomic<std::uint64_t> m_pendingFullCharge {0};
        std::atomic<std::uint64_t> m_building {0};
        /// Size of m_waiters, readable without the registry mutex: a release with no waiter takes no lock.
        std::atomic<std::size_t> m_waiterCount {0};
        std::mutex m_waitersMutex;
        std::vector<Waiter> m_waiters;
    };
} // namespace indexer_client::detail::write

#endif // _INDEXER_CLIENT_WRITE_BUDGET_HPP
