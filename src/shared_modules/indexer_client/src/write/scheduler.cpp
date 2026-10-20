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

#include "write/scheduler.hpp"

#include <atomic>
#include <chrono>
#include <future>
#include <map>
#include <mutex>
#include <optional>
#include <system_error>
#include <utility>
#include <vector>

#include <asio/io_context.hpp>
#include <asio/post.hpp>
#include <asio/steady_timer.hpp>

#include "runtime/runtimeInternal.hpp"
#include "write/sink.hpp"
#include "write/writer.hpp"

// The DRR scheduler (plan 18, I63/I23). Everything below "loop 0 only" is created, read, changed and destroyed only by
// handlers running on network loop 0 (the Prober's pattern): the ring, the cursor, the credits and the maxAge timers.
// Other threads only append to the notification list and post a pass; posts capture the shared state, never `this`.

namespace indexer_client::detail::write
{
    namespace
    {
        using BucketKey = std::weak_ptr<Bucket>;
        using KeyLess = std::owner_less<BucketKey>;

        /// Loop 0 only: the scheduler's view of one bucket.
        struct Entry final
        {
            BucketKey bucket;
            std::uint64_t credit {0}; ///< DRR deficit; kept across turns, 0 when the bucket empties.
            bool inTurn {false};      ///< The turn was cut by the sink's capacity: resume it without new credit.
            bool inRing {false};
            std::unique_ptr<asio::steady_timer> timer; ///< maxAge timer, armed from the oldest pending op.
            std::optional<TimePoint> due;              ///< Expiry the timer is armed for (none when idle).
        };

        struct SchedulerShared final
        {
            SchedulerShared(std::weak_ptr<WritePath> writePath, asio::io_context& loop, std::uint64_t quantumBytes)
                : path(std::move(writePath))
                , loop0(loop)
                , quantum(quantumBytes)
            {
            }

            const std::weak_ptr<WritePath> path;
            asio::io_context& loop0;
            const std::uint64_t quantum;

            std::atomic<std::uint64_t> runs {0};
            std::atomic<std::uint64_t> batches {0};
            std::atomic<std::uint64_t> timerFires {0};
            std::atomic<std::uint64_t> fastForwards {0};

            std::mutex mutex; ///< Guards the three members below.
            bool stopped {false};
            bool passPosted {false};         ///< A pass is queued on loop 0: later notifications coalesce into it.
            std::vector<BucketKey> notified; ///< Buckets announced since the last pass.

            // ---- loop 0 only
            std::map<BucketKey, Entry, KeyLess> entries;
            std::vector<BucketKey> ring; ///< Eligible buckets, in DRR order.
            std::size_t cursor {0};      ///< Persistent across passes.
        };

        void runPass(const std::shared_ptr<SchedulerShared>& shared);

        bool isStopped(SchedulerShared& shared)
        {
            std::lock_guard<std::mutex> lock(shared.mutex);
            return shared.stopped;
        }

        /// Any thread: queues one pass unless one is already queued. False once stopped.
        bool postPass(const std::shared_ptr<SchedulerShared>& shared)
        {
            std::lock_guard<std::mutex> lock(shared->mutex);
            if (shared->stopped)
            {
                return false;
            }
            if (!shared->passPosted)
            {
                shared->passPosted = true;
                // Posted under the mutex: stop() either sees this pass queued ahead of its own handler or has already
                // set `stopped`, which the pass checks first.
                asio::post(shared->loop0, [shared]() { runPass(shared); });
            }
            return true;
        }

        /// Loop 0 only: arms (or re-arms) `entry`'s maxAge timer to the expiry of its bucket's oldest pending op. An
        /// already-due expiry is not armed (arming it would spin while the sink has no capacity, which
        /// WritePath::sinkReady() ends) and is reported: an op that expired during the pass was not eligible when the
        /// pass read the buckets, so the caller runs another pass for it.
        bool armTimer(const std::shared_ptr<SchedulerShared>& shared, Entry& entry, const Bucket& bucket, TimePoint now)
        {
            std::optional<TimePoint> due;
            bool dueNow = false;
            if (const auto oldest = bucket.oldestPending(); oldest)
            {
                due = *oldest + bucket.spec().bulk.maxAge;
                if (*due <= now)
                {
                    due.reset();
                    dueNow = true;
                }
            }
            if (due == entry.due)
            {
                return dueNow;
            }
            entry.due = due;
            if (!due)
            {
                if (entry.timer)
                {
                    entry.timer->cancel();
                }
                return dueNow;
            }
            if (!entry.timer)
            {
                entry.timer = std::make_unique<asio::steady_timer>(shared->loop0);
            }
            entry.timer->expires_at(*due); // Cancels a pending wait (operation_aborted).
            entry.timer->async_wait(
                [shared, key = entry.bucket](const std::error_code& error)
                {
                    if (error || isStopped(*shared))
                    {
                        return;
                    }
                    shared->timerFires.fetch_add(1);
                    if (auto it = shared->entries.find(key); it != shared->entries.end())
                    {
                        it->second.due.reset(); // Fired: the pass re-arms it from the new oldest op.
                    }
                    runPass(shared);
                });
            return false;
        }

        void removeFromRing(SchedulerShared& shared, std::size_t index)
        {
            if (auto it = shared.entries.find(shared.ring[index]); it != shared.entries.end())
            {
                it->second.inRing = false;
                it->second.inTurn = false;
            }
            shared.ring.erase(shared.ring.begin() + static_cast<std::ptrdiff_t>(index));
            if (shared.cursor > index)
            {
                --shared.cursor; // The cursor keeps pointing at the same bucket.
            }
            if (shared.cursor >= shared.ring.size())
            {
                shared.cursor = 0;
            }
        }

        /// Loop 0 only. DRR over the ring (I63): returns when the ring is exhausted (nothing eligible can be covered)
        /// or when the sink has no capacity (the cursor stays on the bucket whose turn was cut).
        /// Loop 0 only: every bucket in the ring had a turn and none could cover its head (a quantum small against the
        /// documents). Adds at once the credit of the k - 1 empty rounds classic DRR would still spin through, k being
        /// the fewest rounds after which some bucket covers its head; the next turn adds the k-th. Same outcome, no
        /// spin.
        void fastForward(SchedulerShared& shared, TimePoint now)
        {
            std::uint64_t rounds = 0;
            for (const auto& key : shared.ring)
            {
                auto it = shared.entries.find(key);
                auto bucket = it != shared.entries.end() ? it->second.bucket.lock() : nullptr;
                if (!bucket)
                {
                    continue;
                }
                const auto head = bucket->headBytes(now);
                const auto perRound = static_cast<std::uint64_t>(bucket->spec().weight) * shared.quantum;
                if (head <= it->second.credit || perRound == 0)
                {
                    return; // Some bucket can already emit: nothing to skip.
                }
                const auto needed = (head - it->second.credit + perRound - 1) / perRound;
                rounds = rounds == 0 ? needed : std::min(rounds, needed);
            }
            if (rounds <= 1)
            {
                return;
            }
            for (const auto& key : shared.ring)
            {
                if (auto it = shared.entries.find(key); it != shared.entries.end())
                {
                    if (auto bucket = it->second.bucket.lock())
                    {
                        it->second.credit +=
                            (rounds - 1) * static_cast<std::uint64_t>(bucket->spec().weight) * shared.quantum;
                    }
                }
            }
            shared.fastForwards.fetch_add(1);
        }

        void drr(const std::shared_ptr<SchedulerShared>& shared, BatchSink& sink, TimePoint now)
        {
            std::size_t idleTurns = 0; ///< Consecutive complete turns that emitted nothing.
            while (!shared->ring.empty())
            {
                if (shared->cursor >= shared->ring.size())
                {
                    shared->cursor = 0;
                }
                const auto index = shared->cursor;
                auto it = shared->entries.find(shared->ring[index]);
                auto bucket = it != shared->entries.end() ? it->second.bucket.lock() : nullptr;
                if (!bucket || bucket->empty() || !bucket->eligible(now))
                {
                    if (bucket && bucket->empty() && it != shared->entries.end())
                    {
                        it->second.credit = 0;
                    }
                    removeFromRing(*shared, index);
                    continue;
                }
                auto& entry = it->second;
                if (sink.capacity() == 0)
                {
                    return; // The cursor does not advance; sinkReady() resumes this turn.
                }
                if (!entry.inTurn)
                {
                    entry.inTurn = true;
                    entry.credit += static_cast<std::uint64_t>(bucket->spec().weight) * shared->quantum;
                }
                bool capacityExhausted = false;
                bool stuck = false;
                const auto batchesBefore = shared->batches.load();
                for (;;)
                {
                    const auto head = bucket->headBytes(now);
                    if (head == 0 || entry.credit < head || !bucket->eligible(now))
                    {
                        break;
                    }
                    if (sink.capacity() == 0)
                    {
                        capacityExhausted = true;
                        break;
                    }
                    auto batch = bucket->slice(entry.credit, now);
                    if (batch.ops.empty())
                    {
                        stuck = true; // Never expected (slice takes the head when the credit covers it).
                        break;
                    }
                    entry.credit -= std::min(entry.credit, batch.bytes);
                    shared->batches.fetch_add(1);
                    sink.dispatch(std::move(batch));
                    if (isStopped(*shared))
                    {
                        return;
                    }
                }
                if (capacityExhausted)
                {
                    return; // Turn cut: credit and cursor kept, inTurn stays set.
                }
                entry.inTurn = false;
                if (bucket->empty())
                {
                    entry.credit = 0;
                    removeFromRing(*shared, index);
                }
                else if (stuck || !bucket->eligible(now))
                {
                    removeFromRing(*shared, index); // Below every threshold again: its maxAge timer brings it back.
                }
                else
                {
                    shared->cursor = index + 1; // The credit does not cover the head: next bucket, credit kept.
                    if (shared->batches.load() != batchesBefore)
                    {
                        idleTurns = 0;
                    }
                    else if (++idleTurns >= shared->ring.size())
                    {
                        fastForward(*shared, now);
                        idleTurns = 0;
                    }
                }
            }
        }

        /// Loop 0 only: one scheduling pass. Notifications queued meanwhile coalesce into the next one.
        void runPass(const std::shared_ptr<SchedulerShared>& shared)
        {
            std::vector<BucketKey> notified;
            {
                std::lock_guard<std::mutex> lock(shared->mutex);
                shared->passPosted = false;
                if (shared->stopped)
                {
                    return;
                }
                notified.swap(shared->notified);
            }
            shared->runs.fetch_add(1);
            for (auto& key : notified)
            {
                if (key.expired())
                {
                    continue;
                }
                auto& entry = shared->entries[key];
                if (entry.bucket.expired())
                {
                    entry.bucket = key;
                }
            }
            // Clear every dedup flag before reading the buckets: an enqueue that lands after this point notifies
            // again, one that landed before is seen by this pass.
            for (auto it = shared->entries.begin(); it != shared->entries.end();)
            {
                if (auto bucket = it->second.bucket.lock())
                {
                    bucket->clearNotified();
                    ++it;
                }
                else
                {
                    // A dead bucket (its client is gone): drop its timer here; drr() drops its ring slot.
                    if (it->second.timer)
                    {
                        it->second.timer->cancel();
                    }
                    it = shared->entries.erase(it);
                }
            }

            auto path = shared->path.lock();
            auto sink = path ? path->sink() : nullptr;
            const auto now = std::chrono::steady_clock::now();
            if (sink)
            {
                for (auto& [key, entry] : shared->entries)
                {
                    auto bucket = entry.bucket.lock();
                    if (!entry.inRing && bucket && !bucket->empty() && bucket->eligible(now))
                    {
                        entry.inRing = true;
                        shared->ring.push_back(key);
                    }
                }
                drr(shared, *sink, now);
            }
            if (isStopped(*shared))
            {
                return;
            }
            const auto after = std::chrono::steady_clock::now();
            bool dueDuringPass = false;
            for (auto& [key, entry] : shared->entries)
            {
                if (auto bucket = entry.bucket.lock())
                {
                    dueDuringPass = armTimer(shared, entry, *bucket, after) || dueDuringPass;
                }
            }
            // An op whose maxAge expired while this pass ran was not eligible when the pass read the buckets and now
            // has no timer: run another pass for it (without capacity, sinkReady() is what resumes the scheduler).
            if (dueDuringPass && sink && sink->capacity() > 0)
            {
                postPass(shared);
            }
        }

        class DrrScheduler final : public Scheduler
        {
        public:
            explicit DrrScheduler(std::shared_ptr<SchedulerShared> shared)
                : m_shared(std::move(shared))
            {
            }

            ~DrrScheduler() override
            {
                std::lock_guard<std::mutex> lock(m_shared->mutex);
                if (!m_shared->stopped)
                {
                    countUsageError(); // Its timers would die off loop 0; the runtime always stops it first.
                }
            }

            DrrScheduler(const DrrScheduler&) = delete;
            DrrScheduler& operator=(const DrrScheduler&) = delete;

            void notify(const std::shared_ptr<Bucket>& bucket) override
            {
                if (!bucket)
                {
                    return;
                }
                {
                    std::lock_guard<std::mutex> lock(m_shared->mutex);
                    if (m_shared->stopped)
                    {
                        return;
                    }
                    m_shared->notified.push_back(bucket);
                }
                postPass(m_shared);
            }

            void notifyAll() override
            {
                postPass(m_shared); // Every pass reconsiders every known bucket.
            }

            void stop() override
            {
                std::lock_guard<std::mutex> stopLock(m_stopMutex); // Concurrent callers wait for the first one.
                {
                    std::lock_guard<std::mutex> lock(m_shared->mutex);
                    if (m_shared->stopped)
                    {
                        return;
                    }
                    m_shared->stopped = true;
                    m_shared->notified.clear();
                }
                const auto dropState = [](SchedulerShared& shared)
                {
                    for (auto& [key, entry] : shared.entries)
                    {
                        if (entry.timer)
                        {
                            entry.timer->cancel();
                            entry.timer.reset();
                        }
                    }
                    shared.entries.clear();
                    shared.ring.clear();
                    shared.cursor = 0;
                };
                if (m_shared->loop0.get_executor().running_in_this_thread())
                {
                    dropState(*m_shared);
                    return;
                }
                auto done = std::make_shared<std::promise<void>>();
                auto future = done->get_future();
                asio::post(m_shared->loop0,
                           [shared = m_shared, done, dropState]()
                           {
                               dropState(*shared);
                               done->set_value();
                           });
                future.wait();
            }

            SchedulerStats stats() const override
            {
                SchedulerStats stats;
                stats.runs = m_shared->runs.load();
                stats.batches = m_shared->batches.load();
                stats.timerFires = m_shared->timerFires.load();
                stats.fastForwards = m_shared->fastForwards.load();
                return stats;
            }

        private:
            std::shared_ptr<SchedulerShared> m_shared;
            std::mutex m_stopMutex;
        };
    } // namespace

    std::shared_ptr<Scheduler>
    Scheduler::create(std::weak_ptr<WritePath> path, asio::io_context& loop0, std::uint64_t quantumBytes)
    {
        return std::make_shared<DrrScheduler>(std::make_shared<SchedulerShared>(std::move(path), loop0, quantumBytes));
    }
} // namespace indexer_client::detail::write
