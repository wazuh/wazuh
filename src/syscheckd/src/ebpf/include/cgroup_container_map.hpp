/*
 * Wazuh Syscheckd — cgroup_id -> container_id attribution for the eBPF drain
 * (#37532 / #37396).
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * An rt_file_event names a cgroup, never a container: the engine is
 * consumer-agnostic and has no idea what a container is. Turning `cgroup_id`
 * into a container id is this consumer's job, and it is the only thing standing
 * between a whole-host event stream and a per-container one.
 *
 * The hard constraint is that the drain thread must never block. Resolution
 * lives in container_instances, behind a connect-per-request IPC socket whose
 * client defaults to a 1 s timeout — three orders of magnitude more than the
 * ~120 us per event the drain can afford before an 8 MiB ring holding ~675
 * records overflows. So classification here is a pure in-memory lookup, and
 * every cache miss is recorded for somebody else to resolve off the drain
 * thread. This class does no I/O at all; it is fed by its owner.
 *
 * Three states, not two. "Not a container" has to be cached as an explicit
 * verdict rather than inferred from absence, because in RT_CGROUP_MODE_ALL the
 * host's own cgroups produce the overwhelming majority of events — and an
 * unknown cgroup is re-queued for resolution on every event, so treating the
 * host as permanently unknown would mean an IPC round-trip per host file open.
 *
 * Two failure directions, and only one of them is acceptable:
 *
 *   - Re-resolving something we already knew costs an IPC round-trip. Fine.
 *   - Attributing events to the WRONG container, or silently dropping a real
 *     container's events, is a corrupt or missing baseline. Not fine.
 *
 * Everything below is biased accordingly. Positives are replaced wholesale from
 * the connector's list rather than accumulated, because a cgroup inode is
 * reused after the cgroup is removed: a stale positive would file a new
 * container's events under the dead container's id. Negatives are cleared by
 * any positive evidence for the same inode, because the same reuse in the other
 * direction would make a new container invisible. When a bound is hit the cache
 * is dropped rather than trimmed, which costs re-resolution and never accuracy.
 *
 * A cgroup that turns out to be a container only AFTER its events were seen
 * cannot have those events replayed — they were classified and discarded before
 * anyone knew. That is reported to the caller as an escalation, and the caller
 * marks the container Suspect (re-walk) rather than reconciling paths it cannot
 * enumerate. Same rule as the staging buffer's overflow: the weaker action is
 * replaced by a stronger one, so nothing is lost silently. See
 * container_event_staging.hpp.
 */

#ifndef _CGROUP_CONTAINER_MAP_HPP
#define _CGROUP_CONTAINER_MAP_HPP

#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace fim_container_events
{

enum class CgroupClass
{
    /* Resolved to a container: `container_id` is set. */
    container,

    /* Resolved, and it is not a container — a host cgroup. Its events belong to
     * host FIM, which already covers them; the container consumer discards
     * them. */
    notContainer,

    /* Never resolved, or resolution is still in flight. The cgroup has been
     * recorded for the resolver; the caller cannot attribute this event. */
    unknown,
};

struct CgroupResolution
{
    CgroupClass klass{CgroupClass::unknown};
    std::string container_id;
};

/* One transition of the connector's container set, as applyDelta() consumes it.
 *
 * Deliberately narrower than the wire event: this map attributes cgroups to
 * containers and nothing else, so image digests, labels and the change mask are
 * none of its business. What it needs is which container, which inode, and
 * whether the container is still there. */
struct CgroupDeltaEvent
{
    enum class Kind
    {
        added,
        changed,
        removed
    };

    Kind kind {Kind::changed};

    /* The container's inode NOW. Zero on a `changed` that reports a stop — a
     * container with no process has no cgroup — and on `removed` it is the last
     * one it had, which is how the consumer knows what to withdraw. */
    std::uint64_t cgroup_id {0};
    std::string container_id;
};

/* What a connector list refresh changed.
 *
 * `escalate` is the historical return value and keeps its exact meaning. The
 * two cgroup sets are for a consumer that filters in the kernel: there, a
 * container's events are not delivered at all until its cgroup reaches the
 * allowlist, so the map's own view of "who exists" has to be mirrored into the
 * kernel rather than merely consulted. */
struct CgroupListDelta
{
    /* Containers whose cgroups had produced events before this refresh
     * identified them. Those paths were classified and discarded before anyone
     * knew whose they were, so the container is re-walked instead. */
    std::vector<std::string> escalate;

    /* Entries that were not in the positive map before this refresh. A cgroup
     * whose inode was reused by a DIFFERENT container counts as added, because
     * for every purpose here it is one.
     *
     * Note what this is not: it is not "containers created since the last
     * refresh". A container the connector failed to list for one cycle and
     * listed again in the next appears here too. That is deliberate — the
     * kernel-side effect of its absence was the same either way. */
    std::vector<std::pair<std::uint64_t, std::string>> added;

    /* Cgroups that were in the positive map and are not any more. Tracked so a
     * filtering consumer can take them back out of the kernel: cgroup ids are
     * inodes and are reused, so an allowlist that only ever grows would end up
     * admitting whatever inherits the inode. */
    std::vector<std::uint64_t> removed;
};

struct CgroupMapStats
{
    unsigned long long hits_container{0};
    unsigned long long hits_not_container{0};
    unsigned long long misses{0};          /* classify() calls that found nothing */
    unsigned long long installs{0};        /* connector list refreshes applied */
    unsigned long long escalations{0};     /* containers whose events predated resolution */
    unsigned long long unknown_overflows{0};  /* misses that did not fit the pending set */
    unsigned long long negative_cache_resets{0}; /* not-a-container cache dropped whole */
};

class CgroupContainerMap
{
    public:
        /* `max_unknown` bounds how many unresolved cgroups can be queued for the
         * resolver at once; `max_not_container` bounds the host-cgroup verdict
         * cache. Both are memory budgets — exceeding either costs work, not
         * correctness. */
        explicit CgroupContainerMap(std::size_t max_unknown = 1024, std::size_t max_not_container = 8192)
            : m_max_unknown(max_unknown)
            , m_max_not_container(max_not_container)
        {
        }

        /* --- drain thread ------------------------------------------------- */

        /* Classify one event's cgroup. Pure lookup: no I/O, no blocking, no
         * allocation on the two cached paths. An unknown cgroup is recorded so
         * that takeUnresolved() will hand it to the resolver. */
        CgroupResolution classify(std::uint64_t cgroup_id)
        {
            CgroupResolution out;

            if (cgroup_id == 0)
            {
                /* Not an inode: it is the "could not be determined" sentinel.
                 * Queueing it would put an id in the pending set that no
                 * resolver can ever answer, and rearm() would keep handing it
                 * back forever. Unknown, and left at that.
                 *
                 * A cgroup v1 host is a different problem with the same cause —
                 * there cgroup_id is a fixed non-zero constant shared by every
                 * container (spike #37396 ADR-002) — and it has to be refused
                 * at rt_open() time via rt_host_cgroup_v1(), not papered over
                 * here: this map cannot tell that constant from a real inode. */
                return out;
            }

            std::lock_guard<std::mutex> lock(m_mutex);

            const auto container = m_container.find(cgroup_id);

            if (container != m_container.end())
            {
                ++m_stats.hits_container;
                out.klass = CgroupClass::container;
                out.container_id = container->second;
                return out;
            }

            if (m_not_container.count(cgroup_id) != 0)
            {
                ++m_stats.hits_not_container;
                out.klass = CgroupClass::notContainer;
                return out;
            }

            ++m_stats.misses;

            /* `false` = not yet handed to the resolver. Recording it is what
             * makes the miss actionable; an id already recorded stays as it is,
             * so a busy unresolved cgroup is dispatched once, not once per
             * event. */
            if (m_unknown.find(cgroup_id) == m_unknown.end())
            {
                if (m_unknown.size() >= m_max_unknown)
                {
                    /* The resolver is not keeping up, or a storm of distinct
                     * cgroups arrived. Dropping the id silently would mean this
                     * cgroup is never resolved and its container never
                     * baselined, so the overflow is counted and surfaced
                     * instead — the caller escalates globally, exactly as it
                     * does for unattributable kernel drops. */
                    ++m_stats.unknown_overflows;
                    m_unknown_overflow = true;
                    return out;
                }

                m_unknown.insert(std::make_pair(cgroup_id, false));
            }

            return out;
        }

        /* --- resolver ----------------------------------------------------- */

        /* Cgroups seen but not yet resolved, marked as dispatched so a second
         * call does not return them again. A resolver that cannot answer one
         * (container_instances replying `pending` on a cold cache) must call
         * rearm() to have it handed out again. */
        std::vector<std::uint64_t> takeUnresolved()
        {
            std::vector<std::uint64_t> out;

            std::lock_guard<std::mutex> lock(m_mutex);

            for (auto& entry : m_unknown)
            {
                if (!entry.second)
                {
                    entry.second = true;
                    out.push_back(entry.first);
                }
            }

            return out;
        }

        /* Hand `cgroup_id` back to the next takeUnresolved(): resolution was
         * attempted and did not conclude. Without this a `pending` answer would
         * park the cgroup as dispatched forever and its container would never be
         * discovered. */
        void rearm(std::uint64_t cgroup_id)
        {
            std::lock_guard<std::mutex> lock(m_mutex);

            const auto it = m_unknown.find(cgroup_id);

            if (it != m_unknown.end())
            {
                it->second = false;
            }
        }

        /* Record a single resolution. Returns true when events for this cgroup
         * were already seen and discarded as unknown, i.e. the caller must
         * escalate `container_id` to Suspect: the paths that changed before this
         * point cannot be recovered, so the container is re-walked instead. */
        bool noteContainer(std::uint64_t cgroup_id, const std::string& container_id)
        {
            if (container_id.empty())
            {
                return false;
            }

            std::lock_guard<std::mutex> lock(m_mutex);
            return noteContainerLocked(cgroup_id, container_id);
        }

        /* Record a permanent "this cgroup is not a container" verdict. */
        void noteNotContainer(std::uint64_t cgroup_id)
        {
            std::lock_guard<std::mutex> lock(m_mutex);

            m_unknown.erase(cgroup_id);

            if (m_container.find(cgroup_id) != m_container.end())
            {
                /* Contradictory evidence: the connector listed this inode as a
                 * container and a resolve then called it a host cgroup. The
                 * verdict is not merely ignored, it is not RECORDED — classify()
                 * checks the container map first, so ignoring it would be enough
                 * for now, but the entry would outlive the container and answer
                 * "host cgroup" for whatever inherits the inode next. Refusing
                 * to record it means that inode is re-resolved instead. */
                return;
            }

            if (m_not_container.size() >= m_max_not_container)
            {
                /* Drop the whole verdict cache rather than evict a chosen
                 * victim. Every entry is re-derivable at the cost of one IPC
                 * round-trip, and no eviction policy can be wrong if there is
                 * no eviction policy. */
                m_not_container.clear();
                ++m_stats.negative_cache_resets;
            }

            m_not_container.insert(cgroup_id);
        }

        /* Apply transitions instead of a whole list.
         *
         * Returns the same shape install() does, so everything downstream — the
         * kernel allowlist sync, the router's escalation rule — is reused
         * without knowing which way the list arrived.
         *
         * The one case worth stating: a container that STOPS keeps existing but
         * loses its cgroup, so its inode is withdrawn (nothing can be attributed
         * to it any more, and the kernel must stop admitting it) while the
         * container is NOT reported as added. It therefore gets no re-walk — its
         * files have not changed, it merely has no process — and its stored rows
         * are left alone. Reporting it as removed here would be the same mistake
         * one layer up that `all=1` exists to prevent. */
        CgroupListDelta applyDelta(const std::vector<CgroupDeltaEvent>& events)
        {
            CgroupListDelta delta;

            std::lock_guard<std::mutex> lock(m_mutex);

            for (const auto& event : events)
            {
                if (event.container_id.empty())
                {
                    continue;
                }

                /* Whatever inode this container held until now. Taken for every
                 * kind, because all three can move it: a restart gives it a new
                 * one, a stop takes it away, a removal ends it. */
                const auto previous = eraseByContainerIdLocked(event.container_id);

                if (event.kind == CgroupDeltaEvent::Kind::removed || event.cgroup_id == 0)
                {
                    /* NO VALID KEY any more — deleted, or stopped. Zero is the
                     * test because zero is what every producer sends for "no
                     * key", and that stays true whichever hierarchy the host is
                     * keyed by: on a host with no unified hierarchy the number
                     * is the chosen v1 controller's cgroup inode rather than the
                     * helper's, but it is still a cgroup inode and still zero
                     * when there is none. This map is deliberately key-agnostic
                     * — it compares opaque integers — which is why supporting a
                     * second hierarchy needed no change here.
                     *
                     * Withdraw what it had, preferring `previous` over the
                     * event's own value because ours is what the kernel was
                     * actually told; they agree on a removal and only ours is
                     * set on a stop. */
                    const auto withdraw = (previous != 0) ? previous : event.cgroup_id;

                    if (withdraw != 0)
                    {
                        delta.removed.push_back(withdraw);
                    }
                    continue;
                }

                if (previous != 0 && previous != event.cgroup_id)
                {
                    /* Restarted: the inode it used to have is dead and may be
                     * handed to something else, so it must stop being admitted. */
                    delta.removed.push_back(previous);
                }

                if (noteContainerLocked(event.cgroup_id, event.container_id))
                {
                    delta.escalate.push_back(event.container_id);
                }

                if (previous != event.cgroup_id)
                {
                    /* A new inode for this container: either it has just been
                     * published, or it restarted and the old one is gone. Both
                     * are a container whose contents nobody has walked. */
                    delta.added.emplace_back(event.cgroup_id, event.container_id);
                }
            }

            return delta;
        }

        /* Apply a full refresh from the connector's container list. `containers`
         * is authoritative: a cgroup absent from it stops being a container
         * here, because its inode may already have been reused by a new one.
         *
         * Returns what changed: the container ids that need escalating to
         * Suspect — those whose cgroups had produced events before this refresh
         * identified them — and the cgroups this refresh added and dropped, for
         * a caller that has to mirror the positive map into a kernel filter. */
        CgroupListDelta install(const std::vector<std::pair<std::uint64_t, std::string>>& containers)
        {
            CgroupListDelta delta;

            std::lock_guard<std::mutex> lock(m_mutex);

            ++m_stats.installs;

            /* Kept to diff against, not to merge with. The rebuild below is
             * still a wholesale replacement for the inode-reuse reason in this
             * file's header; the previous contents exist only so the caller can
             * be told which cgroups entered and left. */
            const std::map<std::uint64_t, std::string> previous = m_container;

            m_container.clear();

            for (const auto& entry : containers)
            {
                if (entry.first == 0 || entry.second.empty())
                {
                    /* cgroup_id 0 is "the connector could not determine it"
                     * (cgroup v1, a kata container, a cgroupns-host container),
                     * not a real inode. Indexing on it would collapse every such
                     * container onto one key and attribute all their events to
                     * whichever landed last. */
                    continue;
                }

                if (noteContainerLocked(entry.first, entry.second))
                {
                    delta.escalate.push_back(entry.second);
                }

                const auto before = previous.find(entry.first);

                if (before == previous.end() || before->second != entry.second)
                {
                    delta.added.emplace_back(entry.first, entry.second);
                }
            }

            for (const auto& entry : previous)
            {
                if (m_container.find(entry.first) == m_container.end())
                {
                    delta.removed.push_back(entry.first);
                }
            }

            return delta;
        }

        /* True once since the last call when the pending set overflowed: some
         * cgroup was seen and could not even be queued for resolution, so the
         * caller has to assume the worst about what it missed. Consume-once, so
         * one overflow escalates one time rather than forever. */
        bool takeUnknownOverflow()
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            const bool out = m_unknown_overflow;
            m_unknown_overflow = false;
            return out;
        }

        /* --- diagnostics -------------------------------------------------- */

        CgroupMapStats stats() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_stats;
        }

        std::size_t containerCount() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_container.size();
        }

        std::size_t unresolvedCount() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_unknown.size();
        }

        std::size_t notContainerCount() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_not_container.size();
        }

    private:
        /* Drops whatever inode `container_id` is indexed under, returning it, or
         * 0 when it had none. Linear, and deliberately so: the map is keyed by
         * inode because that is what every event carries, and the reverse
         * direction is only ever needed when a container stops or leaves — rare,
         * against a few hundred entries, and not worth a second index that
         * would have to be kept in step. */
        std::uint64_t eraseByContainerIdLocked(const std::string& container_id)
        {
            for (auto it = m_container.begin(); it != m_container.end(); ++it)
            {
                if (it->second == container_id)
                {
                    const auto inode = it->first;
                    m_container.erase(it);
                    return inode;
                }
            }
            return 0;
        }

        bool noteContainerLocked(std::uint64_t cgroup_id, const std::string& container_id)
        {
            if (cgroup_id == 0)
            {
                return false;
            }

            /* Positive evidence clears a stale negative for the same inode: the
             * cgroup was a host cgroup, was removed, and its inode was reused by
             * this container. */
            m_not_container.erase(cgroup_id);

            const bool was_unknown = m_unknown.erase(cgroup_id) != 0;

            m_container[cgroup_id] = container_id;

            if (was_unknown)
            {
                ++m_stats.escalations;
            }

            return was_unknown;
        }

        const std::size_t m_max_unknown;
        const std::size_t m_max_not_container;

        mutable std::mutex m_mutex;

        std::map<std::uint64_t, std::string> m_container;
        std::set<std::uint64_t> m_not_container;

        /* cgroup id -> already handed to the resolver. */
        std::map<std::uint64_t, bool> m_unknown;

        bool m_unknown_overflow{false};

        CgroupMapStats m_stats;
};

} // namespace fim_container_events

#endif /* _CGROUP_CONTAINER_MAP_HPP */
