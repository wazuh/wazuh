/*
 * Wazuh Syscheckd — staging buffer between the eBPF drain and the container
 * reconcile consumer (#37532 / #37396).
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Two threads meet here, and the shape of this class is dictated by three
 * measured facts rather than by taste:
 *
 * 1. The drain thread must never block. An 8 MiB ring buffer holds ~675
 *    12,416-byte records — about 2.4 seconds of a burst measured at 8,400
 *    events/s. Anything slow on the drain path overflows the kernel ring, and
 *    every kernel-side drop escalates a container to a full re-walk. So the
 *    drain does nothing here but a hash insert under a short lock.
 *
 * 2. The consumer must not touch `file_entry` until the baseline walk has
 *    committed. A single-row upsert racing the same container's open scoped
 *    transaction silently lost 502 of 504 rows on a real node. The consumer
 *    therefore starts parked and is released only after the walk (see
 *    12-blocking-decisions.md D5).
 *
 * 3. An event can only name a `(container, path)` pair, plus the pid that
 *    triggered it. `rt_file_event` carries no mode, uid/gid, size, mtime or
 *    hash, and its `inode`/`dev` are documented as diagnostic-only, so nothing
 *    else about it is worth keeping — the reconcile re-reads the file anyway.
 *    The pid is kept for one reason only: the settle, below.
 *
 * THE SETTLE (D16, 12-blocking-decisions.md). `RT_EV_FILE_OPEN` fires on
 * open-with-write-intent, so the event PRECEDES the modification. Reconciling
 * immediately re-reads the pre-write file and stores it as if it were the new
 * state (C23); a write deferred by 8 seconds was measured as never reported at
 * all. Nothing in the provider says "the write finished", so the settle has to
 * happen here.
 *
 * A staged path is therefore held until EITHER the pid that triggered it has
 * exited — which the spike's test-plan finding #3b measured as the common case,
 * a short-lived writer already gone by the time the event is processed — OR a
 * bounded delay has elapsed. Then it is read ONCE. That costs one stat+hash
 * rather than two, needs no per-path state this map was not already keyed by,
 * and its wait is bounded, which "re-read until stable" is not. It does not
 * rescue a writer that outlives the delay; no consumer-side option can.
 *
 * A repeat event for an already-staged path updates the pid (so the liveness
 * probe asks about the most recent writer) but deliberately does NOT extend the
 * deadline: extending it on every write is how an append-heavy log file starves.
 *
 * Deliberately NOT built on fim::BoundedQueue (bounded_queue.hpp), even though
 * that exists and is the obvious transport: it is a FIFO with no de-duplication,
 * and de-duplication is the property that bounds memory here. A container
 * rewriting one file in a loop produces thousands of events and exactly one
 * unit of work; a FIFO would hold thousands of copies of the same path and fill
 * for no reason. The map *is* the buffer.
 *
 * The overflow rule is what makes this safe: **Suspect supersedes staged
 * paths.** When a container exceeds its path budget its set is discarded and it
 * is marked Suspect, meaning "re-walk this container" — a strictly stronger
 * action than the per-path reconciles it replaces. So overflow here is not a
 * loss channel, it is an upgrade, which is why it needs no in-band signal of
 * its own. Losing the same information without escalating would be a silent
 * gap; that is the mistake this rule exists to prevent.
 */

#ifndef _CONTAINER_EVENT_STAGING_HPP
#define _CONTAINER_EVENT_STAGING_HPP

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdio>
#include <functional>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <unistd.h>

namespace fim_container_events
{

/* One container's pending work, handed to the consumer. */
struct Batch
{
    std::string container_id;

    /* Paths to re-read, empty when `suspect` is set. */
    std::vector<std::string> paths;

    /* Re-walk the whole container instead of reconciling `paths`: events were
     * lost for it (kernel ring, or this buffer's own budget), so the set of
     * changed paths is not known to be complete. */
    bool suspect{false};
};

/* Counters for diagnostics; none of these are needed for correctness, but a
 * silently-escalating consumer is impossible to explain in the field. */
struct StagingStats
{
    unsigned long long staged{0};        /* (container, path) pairs accepted */
    unsigned long long deduplicated{0};  /* pairs already pending */
    unsigned long long path_overflows{0};/* containers escalated on their path budget */
    unsigned long long drop_escalations{0}; /* containers escalated on reported loss */
    unsigned long long unknown_overflows{0};/* containers that did not fit at all */
    unsigned long long settle_early{0};  /* paths released early: the writer had exited */
    unsigned long long settle_expired{0};/* paths released on the settle delay instead */
};

/* Is this pid still alive? Injected so the buffer stays testable without
 * spawning processes, and so /proc is not a hidden dependency of a header-only
 * class. The default reads /proc, which is what a real drain wants.
 *
 * Called with the buffer's mutex HELD, so it must not call back into the
 * buffer and must not block — the drain thread is waiting on that mutex. */
using PidAliveFn = std::function<bool(unsigned int)>;

inline bool PidIsAlive(unsigned int pid)
{
    if (pid == 0)
    {
        return false;
    }

    char proc_path[32];
    std::snprintf(proc_path, sizeof(proc_path), "/proc/%u", pid);

    return ::access(proc_path, F_OK) == 0;
}

class ContainerEventStaging
{
    public:
        using Clock = std::chrono::steady_clock;

        /* `max_paths_per_container` bounds one container's pending set before it
         * escalates to Suspect; `max_containers` bounds how many containers can
         * be pending at once. Both are budgets, not limits on correctness — see
         * the overflow rule in this file's header comment.
         *
         * `settle_delay_ms` is D16's bound (see the header comment). It defaults
         * to 0 — i.e. no settle, a path is served the moment it is staged —
         * because this class is the mechanism and the policy belongs to
         * DrainConfig, which sets a real value. A 0 delay also costs no pid
         * probe at all, since the deadline is already past. */
        explicit ContainerEventStaging(std::size_t max_paths_per_container,
                                       std::size_t max_containers,
                                       int         settle_delay_ms = 0,
                                       PidAliveFn  pid_alive = PidIsAlive)
            : m_max_paths(max_paths_per_container)
            , m_max_containers(max_containers)
            , m_settle_delay(std::chrono::milliseconds(settle_delay_ms < 0 ? 0 : settle_delay_ms))
            , m_pid_alive(std::move(pid_alive))
        {
        }

        /* --- drain thread ------------------------------------------------- */

        /* Stage one changed path, triggered by `pid` (0 when unknown, which
         * simply means the settle falls back to its delay). Never blocks on the
         * consumer, and allocates at most one string. */
        void onEvent(const std::string& container_id, const std::string& path, unsigned int pid = 0)
        {
            {
                std::lock_guard<std::mutex> lock(m_mutex);

                if (m_suspect.count(container_id) != 0)
                {
                    /* Already going to be re-walked; the path adds nothing. */
                    ++m_stats.deduplicated;
                    return;
                }

                auto it = m_pending.find(container_id);

                if (it == m_pending.end())
                {
                    if (m_pending.size() >= m_max_containers)
                    {
                        /* No room to track even the container's identity. The
                         * only honest escalation is "something changed somewhere
                         * unknown", so force a full re-baseline rather than
                         * discard the event. */
                        m_all_suspect = true;
                        ++m_stats.unknown_overflows;
                        notifyLocked();
                        return;
                    }

                    it = m_pending.insert(std::make_pair(container_id, PathStates())).first;
                }

                const auto staged = it->second.find(path);

                if (staged != it->second.end())
                {
                    /* Keep the ORIGINAL deadline — a path being written in a
                     * loop must still be served within the bound — but take the
                     * newer pid, so the liveness probe asks about the writer
                     * that is actually holding the file now. */
                    staged->second.pid = pid;
                    ++m_stats.deduplicated;
                    return;
                }

                if (it->second.size() >= m_max_paths)
                {
                    /* Suspect supersedes: drop the set, keep the stronger action. */
                    m_pending.erase(it);
                    m_suspect.insert(container_id);
                    ++m_stats.path_overflows;
                    notifyLocked();
                    return;
                }

                it->second.emplace(path, PathState{pid, Clock::now() + m_settle_delay});
                ++m_stats.staged;
            }

            notify();
        }

        /* Events were lost for this container — a kernel-side drop attributed to
         * its cgroup. The changed-path set is no longer known to be complete, so
         * the container must be re-walked. */
        void onDrops(const std::string& container_id)
        {
            {
                std::lock_guard<std::mutex> lock(m_mutex);

                if (m_suspect.insert(container_id).second)
                {
                    ++m_stats.drop_escalations;
                }

                /* The staged paths are a subset of what changed; re-walking
                 * covers them, so keep the memory rather than the list. */
                m_pending.erase(container_id);
            }

            notify();
        }

        /* Events were lost but could not be attributed to a cgroup — the
         * engine's global counter without per-cgroup accounting, or a BPF object
         * too old to attribute. Nothing is known about what changed, so every
         * container has to be treated as Suspect. */
        void onUnattributedDrops()
        {
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_all_suspect = true;
            }

            notify();
        }

        /* --- lifecycle ---------------------------------------------------- */

        /* Called once the baseline walk's transaction has committed. Until then
         * the consumer sees nothing, because a reconcile racing the walk is the
         * 502-of-504 row loss. */
        void release()
        {
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_released = true;
            }

            notify();
        }

        bool released() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_released;
        }

        /* Wakes the consumer and makes every subsequent nextBatch() return
         * false, so the thread can exit. */
        void stop()
        {
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_stopped = true;
            }

            m_cv.notify_all();
        }

        /* --- consumer thread ---------------------------------------------- */

        /* Takes one container's SETTLED work, waiting up to `timeout_ms` for
         * some to appear. Returns false on timeout or after stop().
         *
         * Suspect containers are served before path batches: a container that
         * needs re-walking is both more urgent and cheaper to hand over, and
         * serving it first frees the memory its paths would have used. A
         * re-walk is also never held back by the settle — it re-reads whole
         * directories rather than a named file, so there is no single write for
         * it to be racing.
         *
         * Work that exists but has not settled does NOT return early: the wait
         * is re-armed in short steps until either something settles or
         * `timeout_ms` runs out. Returning false with unsettled work pending
         * would spin the consumer, because its own loop calls straight back in. */
        bool nextBatch(Batch& out, int timeout_ms)
        {
            std::unique_lock<std::mutex> lock(m_mutex);

            const auto giveup = Clock::now() + std::chrono::milliseconds(timeout_ms < 0 ? 0 : timeout_ms);

            for (;;)
            {
                if (m_stopped)
                {
                    return false;
                }

                if (m_released && takeSettledLocked(out))
                {
                    return true;
                }

                const auto now = Clock::now();

                if (now >= giveup)
                {
                    return false;
                }

                /* Re-check on a short cadence while anything is settling, so a
                 * writer that exits is noticed within kSettlePollMs rather than
                 * at the caller's next poll — the consumer's is 500 ms, which
                 * would throw away most of the early release's value. With
                 * nothing pending this degrades to one plain wait, because the
                 * condition variable is signalled by onEvent/onDrops/release. */
                auto until = giveup;

                if (m_released && !m_pending.empty())
                {
                    auto step = (m_settle_delay < kSettlePoll && m_settle_delay > Duration::zero())
                                    ? m_settle_delay
                                    : kSettlePoll;

                    if (now + step < until)
                    {
                        until = now + step;
                    }
                }

                m_cv.wait_until(lock, until);
            }
        }

        /* --- diagnostics -------------------------------------------------- */

        StagingStats stats() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_stats;
        }

        std::size_t pendingContainers() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_pending.size() + m_suspect.size();
        }

    private:
        using Duration = Clock::duration;

        /* How often the settle is re-evaluated while paths are waiting. Chosen
         * against the consumer's own 500 ms poll: the pid-exit early release is
         * worth having only if it is noticed promptly, and 50 ms of latency is
         * far below anything a FIM alert's timeliness is judged on. */
        static constexpr Duration kSettlePoll = std::chrono::milliseconds(50);

        /* Pid probes per nextBatch() call. Each is an ::access() of /proc/<pid>
         * — a VFS lookup of a couple of microseconds — but they happen under
         * the same mutex the drain takes, so the total has to stay small
         * against the drain's budget: at the measured 8,400 events/s the drain
         * wants the lock every ~119 us, and 64 probes is on the order of 200 us
         * against 2.4 s of ring capacity. Paths not probed this round are
         * probed on the next, or fall through to their deadline. */
        static constexpr std::size_t kMaxPidProbes = 64;

        struct PathState
        {
            unsigned int      pid{0};
            Clock::time_point deadline{};
        };

        using PathStates = std::map<std::string, PathState>;

        bool hasWorkLocked() const
        {
            return m_all_suspect || !m_suspect.empty() || !m_pending.empty();
        }

        /* True when this path may be read now: its deadline has passed (the
         * bound), or the writer that triggered it is gone (the early release).
         * `probes` is the shared per-call budget, incremented here. */
        bool isSettledLocked(const PathState& state, const Clock::time_point& now, std::size_t& probes) const
        {
            if (now >= state.deadline)
            {
                ++m_stats.settle_expired;
                return true;
            }

            if (state.pid == 0 || probes >= kMaxPidProbes || !m_pid_alive)
            {
                return false;
            }

            ++probes;

            if (m_pid_alive(state.pid))
            {
                return false;
            }

            ++m_stats.settle_early;
            return true;
        }

        /* Fills `out` with the first container that has at least one settled
         * path, taking only its settled paths and leaving the rest staged.
         * Suspect work bypasses the settle entirely. */
        bool takeSettledLocked(Batch& out)
        {
            if (!hasWorkLocked())
            {
                return false;
            }

            out.paths.clear();

            if (m_all_suspect)
            {
                /* Reported once as a container-less Suspect batch: the consumer
                 * re-walks everything it knows about. Cleared here so it is not
                 * served forever. */
                m_all_suspect = false;
                out.container_id.clear();
                out.suspect = true;
                return true;
            }

            if (!m_suspect.empty())
            {
                const auto it = m_suspect.begin();
                out.container_id = *it;
                out.suspect = true;
                m_suspect.erase(it);
                return true;
            }

            const auto now = Clock::now();
            std::size_t probes = 0;

            for (auto container = m_pending.begin(); container != m_pending.end(); ++container)
            {
                std::vector<std::string> settled;

                for (auto path = container->second.begin(); path != container->second.end();)
                {
                    if (isSettledLocked(path->second, now, probes))
                    {
                        settled.push_back(path->first);
                        path = container->second.erase(path);
                    }
                    else
                    {
                        ++path;
                    }
                }

                if (settled.empty())
                {
                    continue;
                }

                out.container_id = container->first;
                out.suspect = false;
                out.paths = std::move(settled);

                /* Anything still settling keeps the container pending, so the
                 * remainder is served in a later batch rather than dropped. */
                if (container->second.empty())
                {
                    m_pending.erase(container);
                }

                return true;
            }

            return false;
        }

        void notify()
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            notifyLocked();
        }

        void notifyLocked()
        {
            if (m_released)
            {
                m_cv.notify_one();
            }
        }

        const std::size_t m_max_paths;
        const std::size_t m_max_containers;
        const Duration    m_settle_delay;
        const PidAliveFn  m_pid_alive;

        mutable std::mutex m_mutex;
        std::condition_variable m_cv;

        std::map<std::string, PathStates> m_pending;
        std::set<std::string> m_suspect;

        bool m_all_suspect{false};
        bool m_released{false};
        bool m_stopped{false};

        mutable StagingStats m_stats;
};

} // namespace fim_container_events

#endif /* _CONTAINER_EVENT_STAGING_HPP */
