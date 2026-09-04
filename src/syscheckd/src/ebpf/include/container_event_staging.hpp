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
 * 3. An event can only name a `(container, path)` pair. `rt_file_event`
 *    carries no mode, uid/gid, size, mtime or hash, and its `inode`/`dev` are
 *    documented as diagnostic-only. Nothing about the event is worth keeping
 *    beyond the pair, because the reconcile has to re-read the file anyway.
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

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <utility>
#include <vector>

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
};

class ContainerEventStaging
{
    public:
        /* `max_paths_per_container` bounds one container's pending set before it
         * escalates to Suspect; `max_containers` bounds how many containers can
         * be pending at once. Both are budgets, not limits on correctness — see
         * the overflow rule in this file's header comment. */
        ContainerEventStaging(std::size_t max_paths_per_container, std::size_t max_containers)
            : m_max_paths(max_paths_per_container)
            , m_max_containers(max_containers)
        {
        }

        /* --- drain thread ------------------------------------------------- */

        /* Stage one changed path. Never blocks on the consumer, and allocates at
         * most one string. */
        void onEvent(const std::string& container_id, const std::string& path)
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

                    it = m_pending.insert(std::make_pair(container_id, std::set<std::string>())).first;
                }

                if (it->second.count(path) != 0)
                {
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

                it->second.insert(path);
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

        /* Takes one container's pending work, waiting up to `timeout_ms` for
         * some to appear. Returns false on timeout or after stop().
         *
         * Suspect containers are served before path batches: a container that
         * needs re-walking is both more urgent and cheaper to hand over, and
         * serving it first frees the memory its paths would have used. */
        bool nextBatch(Batch& out, int timeout_ms)
        {
            std::unique_lock<std::mutex> lock(m_mutex);

            if (!m_cv.wait_for(lock, std::chrono::milliseconds(timeout_ms), [this] {
                    return m_stopped || (m_released && hasWorkLocked());
                }))
            {
                return false;
            }

            if (m_stopped || !m_released || !hasWorkLocked())
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

            const auto it = m_pending.begin();
            out.container_id = it->first;
            out.suspect = false;
            out.paths.assign(it->second.begin(), it->second.end());
            m_pending.erase(it);
            return true;
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
        bool hasWorkLocked() const
        {
            return m_all_suspect || !m_suspect.empty() || !m_pending.empty();
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

        mutable std::mutex m_mutex;
        std::condition_variable m_cv;

        std::map<std::string, std::set<std::string>> m_pending;
        std::set<std::string> m_suspect;

        bool m_all_suspect{false};
        bool m_released{false};
        bool m_stopped{false};

        StagingStats m_stats;
};

} // namespace fim_container_events

#endif /* _CONTAINER_EVENT_STAGING_HPP */
