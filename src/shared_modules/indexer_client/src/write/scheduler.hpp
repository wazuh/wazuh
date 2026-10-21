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

#ifndef _INDEXER_CLIENT_WRITE_SCHEDULER_HPP
#define _INDEXER_CLIENT_WRITE_SCHEDULER_HPP

// The DRR scheduler (stage E3a, plan 18 I63/I23). One per runtime, on network loop 0: its state, its maxAge timers and
// its ring are touched only from loop 0 (the Prober's pattern). No asio type in this header.

#include <cstddef>
#include <cstdint>
#include <memory>

#include "write/bucket.hpp"

namespace asio
{
    class io_context;
} // namespace asio

namespace indexer_client::detail::write
{
    class WritePath;

    /// Batches per unit of weight a bucket may emit in one DRR turn while another bucket of the ring is eligible
    /// (I97b): with the 1 MiB quantum, small batches would otherwise hold the turn for hundreds of batches. Scaled by
    /// the weight so that a heavier bucket keeps its share (RF-3): the cap is weight x DRR_MAX_BATCHES_PER_TURN.
    constexpr std::size_t DRR_MAX_BATCHES_PER_TURN = 8;

    struct SchedulerStats final
    {
        std::uint64_t runs {0};         ///< Scheduling passes (coalesced notifications count once).
        std::uint64_t batches {0};      ///< Batches dispatched.
        std::uint64_t timerFires {0};   ///< maxAge timers that fired.
        std::uint64_t fastForwards {0}; ///< Idle DRR cycles skipped at once (quantum small against the documents).
    };

    class Scheduler
    {
    public:
        virtual ~Scheduler() = default;

        /// A bucket needs attention (first op into an empty bucket, a threshold crossed, the sink ready again). Any
        /// thread; posts to loop 0; notifications posted while a pass is pending coalesce into one pass.
        virtual void notify(const std::shared_ptr<Bucket>& bucket) = 0;
        virtual void notifyAll() = 0;
        /// Flag + post + wait (as Prober::stop); afterwards no dispatch happens and no timer is armed. Idempotent.
        virtual void stop() = 0;
        virtual SchedulerStats stats() const = 0;

        /// DRR (I63): ring of eligible buckets with a persistent cursor; a turn adds weight x quantum to the bucket's
        /// credit and emits batches (Bucket::slice, each at most the credit) while credit >= headBytes() and
        /// capacity() > 0; the turn ends when the credit does not cover the head (credit kept), the bucket empties
        /// (credit = 0), capacity is exhausted (cursor stays on the bucket) or, after weight x DRR_MAX_BATCHES_PER_TURN
        /// batches, when another bucket of the ring is eligible (I97b: the cursor moves on, the leftover credit is kept
        /// capped at weight x quantum, and the next turn adds its quantum as usual; with no other eligible bucket the
        /// turn goes on). A maxAge timer per bucket is armed from its oldest pending op and re-armed after each batch.
        static std::shared_ptr<Scheduler>
        create(std::weak_ptr<WritePath> path, asio::io_context& loop0, std::uint64_t quantumBytes);
    };
} // namespace indexer_client::detail::write

#endif // _INDEXER_CLIENT_WRITE_SCHEDULER_HPP
