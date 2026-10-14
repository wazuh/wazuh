/*
 * Wazuh Syscheckd — routing policy between the eBPF drain and the container
 * reconcile consumer (#37532 / #37396).
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Everything the drain decides, decided here — with no kernel, no sockets and
 * no threads, so it can actually be tested. CgroupContainerMap answers "whose
 * cgroup is this"; ContainerEventStaging holds "what to do about it"; this is
 * the policy joining them, and it is where the subtle calls live.
 *
 * The one worth reading is what happens to a DROP attributed to a cgroup we
 * cannot yet identify.
 *
 * Ignoring it loses a container's changes silently. Escalating it globally is
 * worse than it sounds: in RT_CGROUP_MODE_ALL the ring carries the whole host,
 * so the cgroups dropping events are overwhelmingly the host's own, and "an
 * unknown cgroup dropped something" would re-baseline every container on the
 * node, continuously. That is the exact failure rt_engine_filter_test's third
 * property exists to prevent, arriving through the back door.
 *
 * Neither is necessary, because the map already records every cgroup it could
 * not identify and reports it the moment resolution arrives. So a drop from an
 * unknown cgroup needs no special handling at all: classify() files the cgroup,
 * and if it later turns out to be a container, install()/noteContainer() report
 * it as an escalation and it gets re-walked. If it turns out to be a host
 * cgroup, nothing happens, which is correct. The escalation path built for
 * "events seen before the container was known" covers "events LOST before the
 * container was known" for free.
 *
 * What that leaves genuinely unattributable is narrower and honestly handled:
 * loss the engine could not pin to any cgroup at all, and cgroups the map had
 * no room to even queue. Those escalate globally, once each.
 *
 * A container that container_instances never reports is invisible here. That is
 * not a gap this class can close: the baseline walk resolves containers through
 * the same connector, so such a container was never baselined either and has no
 * stored state to reconcile against. The blindness is shared, not introduced.
 *
 * WHEN THE OWNER FILTERS IN THE KERNEL (setFiltering), one thing above changes
 * and one thing does not.
 *
 * What changes: a container the connector has not yet listed produces no events
 * here at all, rather than events filed under an unknown cgroup. So the unknown
 * path stops being how a new container is discovered, and the connector's list
 * becomes the only discovery mechanism. applyContainerList() takes that over.
 *
 * What does not change: what a newly discovered container actually gets. Today
 * its early events are classified against an unidentified cgroup and discarded
 * — their paths are not recoverable — and the container is re-walked once it is
 * identified. Under filtering those same events are discarded one layer lower,
 * and the container is re-walked once it is listed. Both end in a walk of
 * current on-disk state; only the latency to the trigger differs. A file
 * created and deleted inside that window is missed either way, which is why
 * this is a latency change rather than a correctness one.
 *
 * The reasoning about unattributed drops above is unchanged but largely moot
 * under filtering: with the host's own cgroups discarded in the kernel, there
 * is very little left that can drop events without being identifiable.
 */

#ifndef _CONTAINER_EVENT_ROUTER_HPP
#define _CONTAINER_EVENT_ROUTER_HPP

#include "cgroup_container_map.hpp"
#include "container_event_staging.hpp"

#include <atomic>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace fim_container_events
{

struct RouterStats
{
    unsigned long long routed{0};        /* events staged against a container */
    unsigned long long host_events{0};   /* events discarded as host-cgroup traffic */
    unsigned long long unattributed{0};  /* events whose cgroup is not yet identified */
    unsigned long long drops_routed{0};  /* drop reports escalated to a container */
    unsigned long long drops_host{0};    /* drop reports discarded as host traffic */
    unsigned long long drops_deferred{0};/* drop reports for a not-yet-identified cgroup */
    unsigned long long global_escalations{0}; /* whole-node re-baselines requested */
    unsigned long long late_escalations{0};   /* containers identified after their events */
    unsigned long long renames_routed{0};     /* renames escalated (source path is never reported) */
    unsigned long long discovery_escalations{0}; /* containers walked because the kernel filter had not reached them */
};

class ContainerEventRouter
{
    public:
        ContainerEventRouter(CgroupContainerMap& map, ContainerEventStaging& staging)
            : m_map(map)
            , m_staging(staging)
        {
        }

        /* --- drain thread ------------------------------------------------- */

        /* One file event, triggered by `pid` (0 when unknown). Returns true when
         * it was attributed to a container.
         *
         * The pid is not routing information — it is carried through for the
         * staging buffer's settle (D16), which releases a path early once the
         * writer that triggered it has exited. */
        bool onEvent(std::uint64_t cgroup_id, const std::string& path, unsigned int pid = 0)
        {
            const auto resolution = m_map.classify(cgroup_id);

            switch (resolution.klass)
            {
                case CgroupClass::container:
                    bump(m_stats.routed);
                    m_staging.onEvent(resolution.container_id, path, pid);
                    return true;

                case CgroupClass::notContainer:
                    /* Host traffic. Host FIM already covers it, and the
                     * container consumer has no state to reconcile it against. */
                    bump(m_stats.host_events);
                    return false;

                case CgroupClass::unknown:
                default:
                    /* classify() has filed the cgroup for the resolver. The path
                     * is not recoverable, but the container will be re-walked
                     * once it is identified — see this file's header. */
                    bump(m_stats.unattributed);
                    return false;
            }
        }

        /* One UNLINK event. Returns true when it was attributed to a container.
         *
         * Same routing as onEvent() — the difference is entirely in what the
         * staging buffer does with it. */
        bool onUnlink(std::uint64_t cgroup_id, const std::string& path)
        {
            const auto resolution = m_map.classify(cgroup_id);

            switch (resolution.klass)
            {
                case CgroupClass::container:
                    bump(m_stats.routed);
                    m_staging.onUnlink(resolution.container_id, path);
                    return true;

                case CgroupClass::notContainer:
                    bump(m_stats.host_events);
                    return false;

                case CgroupClass::unknown:
                default:
                    /* Same as onEvent(): the cgroup is filed, and if it turns
                     * out to be a container it is re-walked — which finds the
                     * deletion. See this file's header. */
                    bump(m_stats.unattributed);
                    return false;
            }
        }

        /* One cgroup's dropped-event count, from rt_drain_drops(). `count` is
         * loss since the previous drain, so any non-zero value means this
         * cgroup's changed-path set is incomplete. */
        void onDrops(std::uint64_t cgroup_id, unsigned int count)
        {
            if (count == 0)
            {
                return;
            }

            const auto resolution = m_map.classify(cgroup_id);

            switch (resolution.klass)
            {
                case CgroupClass::container:
                    bump(m_stats.drops_routed);
                    m_staging.onDrops(resolution.container_id);
                    return;

                case CgroupClass::notContainer:
                    bump(m_stats.drops_host);
                    return;

                case CgroupClass::unknown:
                default:
                    /* Deliberately NOT a global escalation: on a busy host in
                     * RT_CGROUP_MODE_ALL that would re-baseline the node
                     * continuously. classify() filed the cgroup, so resolution
                     * escalates it if it turns out to matter. */
                    bump(m_stats.drops_deferred);
                    return;
            }
        }

        /* A rename. The engine reports the DESTINATION path only — bpf/
         * rt_file.bpf.c's kprobe__vfs_rename builds its path from `new_dentry`
         * — so the source path is never named by any event, before or after.
         *
         * Staging just the destination would therefore be silently wrong:
         * `mv /etc/passwd /etc/passwd.bak` inside a container would reconcile
         * the new name and leave the stored row for /etc/passwd describing a
         * file that no longer exists, with nothing to ever correct it. A
         * deletion that FIM never reports is the worst class of bug this
         * consumer can have.
         *
         * So a rename escalates its container instead. That sounds expensive and
         * is not: Suspect is a set keyed by container in the staging buffer, so
         * any number of renames between two consumer batches coalesces into one
         * re-walk. A package upgrade renaming a thousand files costs exactly
         * what one renaming a single file costs.
         *
         * The real fix belongs in the engine — appending the source path to the
         * event record, a MINOR ABI bump. It is not free: the record grows from
         * 12,416 to ~16,512 bytes, cutting the 8 MiB ring from ~675 records to
         * ~508 for every event class to fix one. Worth measuring before taking.
         */
        void onRename(std::uint64_t cgroup_id)
        {
            const auto resolution = m_map.classify(cgroup_id);

            switch (resolution.klass)
            {
                case CgroupClass::container:
                    bump(m_stats.renames_routed);
                    m_staging.onDrops(resolution.container_id);
                    return;

                case CgroupClass::notContainer:
                    bump(m_stats.host_events);
                    return;

                case CgroupClass::unknown:
                default:
                    /* Same reasoning as an unidentified cgroup's drops: the
                     * cgroup is filed, and resolution escalates it if it turns
                     * out to be a container. */
                    bump(m_stats.unattributed);
                    return;
            }
        }

        /* Loss the engine could not attribute to any cgroup — a BPF object with
         * no per-cgroup map, or a drop recorded while that map was full. Nothing
         * is known about what changed, so everything is suspect. */
        void onUnattributedDrops()
        {
            bump(m_stats.global_escalations);
            m_staging.onUnattributedDrops();
        }

        /* --- resolver thread ---------------------------------------------- */

        /* Apply a connector list refresh and escalate every container whose
         * events (or losses) predated its identification. Returns the cgroup
         * delta, so a caller that filters in the kernel can keep its allowlist
         * in step with the map.
         *
         * When filtering is on, a container that is merely NEW to the list
         * escalates as well, and that difference is the whole reason this
         * returns anything. In RT_CGROUP_MODE_ALL "new to the list" says
         * nothing about what was missed: its events had been arriving all
         * along, either attributed or filed as unknown, and the unknown path
         * already escalates. In allowlist mode they were discarded in the
         * kernel before anyone could file anything, so the only honest account
         * of what changed inside that container is a walk.
         *
         * This costs one walk per newly listed container, which is also the
         * cost today — an unlisted container's first event escalates it by the
         * other route. What changes is the trigger, not the work. */
        CgroupListDelta applyContainerList(const std::vector<std::pair<std::uint64_t, std::string>>& containers)
        {
            return escalateDelta(m_map.install(containers));
        }

        /* The same, from transitions rather than a whole list.
         *
         * Shares escalateDelta() with applyContainerList deliberately: which
         * way the list arrived is a transport detail, and the rule for what has
         * to be re-walked must not be able to drift between the two. */
        CgroupListDelta applyContainerDelta(const std::vector<CgroupDeltaEvent>& events)
        {
            return escalateDelta(m_map.applyDelta(events));
        }

        /* Apply one on-demand resolution.
         *
         * Deliberately NOT given the filtering treatment above: reaching here
         * at all means an event for this cgroup was delivered, so either
         * filtering is off or the cgroup was already allowed. There is no
         * "never saw its events" case to cover. */
        void applyContainerResolution(std::uint64_t cgroup_id, const std::string& container_id)
        {
            if (m_map.noteContainer(cgroup_id, container_id))
            {
                escalate({container_id});
            }
        }

        void applyNotContainer(std::uint64_t cgroup_id)
        {
            m_map.noteNotContainer(cgroup_id);
        }

        /* Call once per resolver cycle. The map cannot escalate on its own when
         * it had no room to queue a cgroup — nobody will ever resolve it — so
         * that overflow is the one case that has to become a whole-node
         * re-baseline. */
        void pumpUnknownOverflow()
        {
            if (m_map.takeUnknownOverflow())
            {
                onUnattributedDrops();
            }
        }

        /* Tell the router that its owner discards events in the kernel for any
         * cgroup not on an allowlist, which changes what a newly listed
         * container means. Set before the first refresh that should act on it;
         * see applyContainerList(). */
        void setFiltering(bool filtering)
        {
            m_filtering = filtering;
        }

        RouterStats stats() const
        {
            RouterStats out;
            out.routed = m_stats.routed.load(std::memory_order_relaxed);
            out.host_events = m_stats.host_events.load(std::memory_order_relaxed);
            out.unattributed = m_stats.unattributed.load(std::memory_order_relaxed);
            out.drops_routed = m_stats.drops_routed.load(std::memory_order_relaxed);
            out.drops_host = m_stats.drops_host.load(std::memory_order_relaxed);
            out.drops_deferred = m_stats.drops_deferred.load(std::memory_order_relaxed);
            out.global_escalations = m_stats.global_escalations.load(std::memory_order_relaxed);
            out.discovery_escalations = m_stats.discovery_escalations.load(std::memory_order_relaxed);
            out.late_escalations = m_stats.late_escalations.load(std::memory_order_relaxed);
            out.renames_routed = m_stats.renames_routed.load(std::memory_order_relaxed);
            return out;
        }

    private:
        /* The drain thread and the resolver thread both count, so these cannot
         * be plain integers. Relaxed ordering is enough: they are diagnostics,
         * never read to make a decision, and the drain must not pay for a lock
         * it does not need. */
        struct Counters
        {
            std::atomic<unsigned long long> routed{0};
            std::atomic<unsigned long long> host_events{0};
            std::atomic<unsigned long long> unattributed{0};
            std::atomic<unsigned long long> drops_routed{0};
            std::atomic<unsigned long long> drops_host{0};
            std::atomic<unsigned long long> drops_deferred{0};
            std::atomic<unsigned long long> global_escalations{0};
            std::atomic<unsigned long long> late_escalations{0};
            std::atomic<unsigned long long> renames_routed{0};
            std::atomic<unsigned long long> discovery_escalations{0};
        };

        void bump(std::atomic<unsigned long long>& counter)
        {
            counter.fetch_add(1, std::memory_order_relaxed);
        }

        /* Escalates what a map update says needs re-walking, and hands the
         * delta back for the caller to apply to the kernel filter. */
        CgroupListDelta escalateDelta(CgroupListDelta delta)
        {
            escalate(delta.escalate);

            if (m_filtering)
            {
                for (const auto& entry : delta.added)
                {
                    bump(m_stats.discovery_escalations);
                    m_staging.onDrops(entry.second);
                }
            }

            return delta;
        }

        void escalate(const std::vector<std::string>& container_ids)
        {
            for (const auto& container_id : container_ids)
            {
                bump(m_stats.late_escalations);

                /* Suspect, not a path reconcile: whatever changed before this
                 * container was identified cannot be enumerated, so the only
                 * honest action is to re-walk it. */
                m_staging.onDrops(container_id);
            }
        }

        CgroupContainerMap& m_map;
        ContainerEventStaging& m_staging;

        /* Written once at startup, before the resolver thread exists, and read
         * on that thread only. Not atomic because there is no second writer. */
        bool m_filtering{false};

        Counters m_stats;
};

} // namespace fim_container_events

#endif /* _CONTAINER_EVENT_ROUTER_HPP */
