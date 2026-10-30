/*
 * Wazuh Syscheckd — the eBPF drain that feeds the container reconcile consumer
 * (#37532 / #37396).
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "container_event_drain.hpp"

#include "cgroup_container_map.hpp"
#include "container_baseline_fim_bridge.h"
#include "container_event_router.hpp"
#include "container_list_refresh.hpp"
#include "container_event_staging.hpp"
#include "resolver_wait.hpp"
#include "container_instances_client.hpp"
#include "container_instances_notify_socket.hpp"
#include "defs.h"

#include "rt_engine.h"

#include "cgroup_host_mode.h"

#include <json.hpp>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <map>
#include <optional>
#include <set>
#include <thread>
#include <utility>
#include <vector>

#include <poll.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <unistd.h>

namespace fim_container_events
{

    namespace
    {

        void LogDebug(const std::string& message)
        {
            fim_container_baseline_log_debug(message.c_str());
        }

        void LogWarn(const std::string& message)
        {
            fim_container_baseline_log_warn(message.c_str());
        }

        void LogError(const std::string& message)
        {
            fim_container_baseline_log_error(message.c_str());
        }

        /* rt_engine's diagnostics sink. Without one the engine writes to stderr, which
         * for a daemonised agent means nowhere — a failed eBPF load would never reach
         * ossec.log and "eBPF unavailable" would be undiagnosable in the field. */
        void EngineLog(int level, const char* msg, void* /*user*/)
        {
            if (msg == nullptr) return;

            const std::string line = std::string{"Container eBPF drain: "} + msg;

            if (level <= RT_LOG_WARN)
            {
                LogError(line);
            }
            else
            {
                LogDebug(line);
            }
        }

        /* The container id out of a `resolve` reply.
         *
         * LookupResult::json carries the WHOLE reply line, not the "data" object — the
         * client extracts only the status string and leaves parsing to the consumer. */
        std::string ContainerIdFromResolveReply(const std::string& reply)
        {
            const auto parsed = nlohmann::json::parse(reply, nullptr, false);

            if (parsed.is_discarded() || !parsed.is_object()) return {};

            const auto data = parsed.find("data");

            if (data != parsed.end() && data->is_object())
            {
                const auto id = data->find("container_id");

                if (id != data->end() && id->is_string()) return id->get<std::string>();
            }

            const auto id = parsed.find("container_id");

            if (id != parsed.end() && id->is_string()) return id->get<std::string>();

            return {};
        }

    } // namespace

    /* The admission view a list refresh leaves behind.
     *
     * Rebuilt rather than merged: a full list is the whole truth, so a container
     * absent from it is gone, not unchanged.
     *
     * Unless it is NOT the whole truth. container_instances withholds a running
     * container from the list until its resolver can key it, and says so with
     * `withheld`. Treating such a list as authoritative is the worst of the three
     * consumers' versions of the same mistake: it does not merely skip a sweep,
     * it installs an admission set that omits a live container, and
     * fim_container_set_admission() answers "not admitted" for anything missing
     * -- which retracts every one of its sync=1 rows. On a modulesd restart,
     * when the store is cold and the first list is mostly withheld, that is the
     * whole node.
     *
     * So an incomplete list is a set of upserts: what it names is applied, what
     * it omits is left exactly as it was. The caller does the same for the kernel
     * filter, with applyContainerDelta() in place of applyContainerList()
     * (#37532).
     *
     * Free and pure so the rule can be tested without a connector -- the absence
     * of any seam here is why the drain kept reading a partial list as the whole
     * node long after the other two consumers stopped. */
    std::map<std::string, bool> mergeAdmissionView(
        const std::map<std::string, bool>& current,
        const std::vector<wazuh::container_instances_client::ContainerRef>& refs,
        bool complete)
    {
        std::map<std::string, bool> refreshed;

        if (!complete)
        {
            refreshed = current;
        }

        for (const auto& ref : refs)
        {
            refreshed[ref.containerId] = ref.synced;
        }

        return refreshed;
    }

    /* Fold the connector's whole admitted set into a view built from events.
     *
     * The lifecycle stream carries admission only for containers that HAVE an
     * event, and recomputeAdmittedLocked() moves it for containers that do not:
     * readmit one because another freed a slot under containers.synced_limit,
     * and no event is journalled for it. A view merged from events alone
     * therefore keeps a readmitted container withheld, or keeps reporting one
     * the cap has since pushed out (#37532).
     *
     * Positive always, negative only from a reply that ENUMERATES. Membership
     * in the set is the connector's own answer and can be taken at once;
     * absence from it means "not admitted" only once the reply has named every
     * container that exists, because until then absence is indistinguishable
     * from a container the reply did not get to and withdrawing it would
     * retract a live container's rows.
     *
     * Enumerating is not the same as having keyed them all. The connector ranks
     * a container it cannot key along with the rest and names it in
     * `known_unkeyed`, so a reply that carries that key has accounted for every
     * container even though `complete` is false. Gating this on `complete`
     * meant a single container nobody can key -- or any container for the
     * seconds after it restarts -- held every withdrawal on this path for as
     * long as it stayed unkeyed: lower containers.synced_limit and the drain
     * went on republishing as admitted the containers the baseline had just
     * retracted, which alternated their documents between CREATE and DELETE
     * (#37532). */
    void applyAdmittedSet(std::map<std::string, bool>& view,
                          const std::set<std::string>& admitted,
                          bool admittedKnown,
                          bool enumerated)
    {
        if (!admittedKnown)
        {
            return; /* A server too old to send it; leave the view as it was. */
        }

        for (auto& [containerId, isAdmitted] : view)
        {
            if (admitted.count(containerId) != 0)
            {
                isAdmitted = true;
            }
            else if (enumerated)
            {
                isAdmitted = false;
            }
        }
    }

    /* Put the containers the connector could not key into the view, with the
     * decision it made about them.
     *
     * They are containers, so the cap ranks them, so they are in `admitted` or
     * refused like anything else -- they simply have no record in the reply to
     * carry a `synced` flag, and the whole set is where their answer lives.
     * Keeping them beside the view as an unrankable third category is what let
     * a container report outside containers.synced_limit for as long as it was
     * unkeyed, which is a window every restart opens (#37532).
     *
     * A server too old to send the set leaves no decision to read, and reading
     * silence as a refusal would retract live rows: admit them, as this did
     * before the set existed. */
    void foldUnkeyedIntoView(std::map<std::string, bool>& view,
                             const std::set<std::string>& unkeyed,
                             const std::set<std::string>& admitted,
                             bool admittedKnown)
    {
        for (const auto& containerId : unkeyed)
        {
            view[containerId] = !admittedKnown || admitted.count(containerId) != 0;
        }
    }

    /* Two reasons to hold an admission snapshot back, and one trap in holding it.
     *
     * not released  installing runs a reconciliation that reads and writes
     *               file_entry, and the baseline walk's scoped transaction is
     *               open until release. Same hazard
     *               fim_container_events_release() exists for.
     * not enumerated  the reply does not name every container that exists --
     *                 an older connector that reports neither the unkeyed ids
     *                 nor a complete list. Installing it marks the containers
     *                 it omits "known and refused" rather than "not heard of",
     *                 which retracts live rows, and at a cold start the view it
     *                 merges into is EMPTY, so there is no previous answer to
     *                 protect them either.
     *
     * What this deliberately does NOT wait for is every container to be KEYED.
     * It used to, and a container whose cgroup no process reports never is, so
     * the snapshot was never installed again and every container that started
     * afterwards read as refused for the life of the process (#37532). An
     * unkeyed container has an id, which is all admission needs; only the
     * cgroup map needs the key.
     *
     * The trap: the caller records the new view whether or not it installs it,
     * so "publish when it next CHANGES" silently means never on a quiet node --
     * the change has already been absorbed. `unpublished` is what remembers
     * that the installed snapshot is behind the view, so the next call that can
     * install does, with or without a further change (#37532). */
    AdmissionPublish decideAdmissionPublish(bool changed, bool unpublished, bool released, bool enumerated)
    {
        if (!changed && !unpublished)
        {
            return AdmissionPublish::nothing;
        }

        if (!released || !enumerated)
        {
            return AdmissionPublish::defer;
        }

        return AdmissionPublish::install;
    }

    ListRefreshPlan planListRefresh(const wazuh::container_instances_client::ContainerDelta& delta,
                                    const std::map<std::string, bool>& currentView,
                                    const std::set<std::string>& mappedContainers)
    {
        ListRefreshPlan plan;
        plan.complete = delta.complete;

        /* Keyed-complete and enumerated are different claims, and only the
         * second is what admission needs. A connector too old to report its
         * unkeyed ids leaves `complete` as the only evidence either way. */
        plan.enumerated = delta.complete || delta.unkeyedKnown;

        /* unreachable: nothing was obtained. Change NOTHING -- install()
         * replaces the positive map, so applying an empty list from a connector
         * that simply did not answer would un-attribute every container at once
         * and turn the next event from each into an escalation. */
        if (!delta.available)
        {
            return plan;
        }

        plan.act = true;

        /* deltas unsupported: an older container_instances, which ignored the
         * cursor and answered with the set.
         * resync required:    the cursor is from another store lifetime, or its
         *                     position has been evicted. The set rides the same
         *                     reply, so this costs no extra round trip. */
        if (!delta.deltaSupported || delta.resyncRequired)
        {
            plan.installWholeList = delta.complete;
            plan.containers.reserve(delta.containers.size());

            if (!delta.complete)
            {
                plan.events.reserve(delta.containers.size());
            }

            for (const auto& ref : delta.containers)
            {
                plan.containers.emplace_back(ref.cgroupId, ref.containerId);

                if (!delta.complete)
                {
                    /* applyDelta() withdraws whatever THIS container held before
                     * applying the event, and touches no other container --
                     * which is precisely the difference from install(), and the
                     * whole reason a partial reply may be applied at all. */
                    CgroupDeltaEvent upsert;
                    upsert.kind             = CgroupDeltaEvent::Kind::changed;
                    upsert.cgroup_id        = ref.cgroupId;
                    upsert.container_id     = ref.containerId;
                    upsert.extra_cgroup_ids = ref.extraCgroupIds;
                    plan.events.push_back(std::move(upsert));
                }

                /* Every other cgroup the container occupies, as its own entry. A
                 * container running an init system has one per unit, and the
                 * kernel filter matches an event's cgroup id by equality -- so a
                 * key that does not reach the allowlist is a unit whose file
                 * events are discarded before anything downstream can see them.
                 *
                 * One entry per key rather than a key set in the map, because the
                 * map is keyed by inode precisely because that is what every
                 * event carries; attribution then needs no second lookup. */
                for (const auto extra : ref.extraCgroupIds)
                {
                    plan.containers.emplace_back(extra, ref.containerId);
                }
            }

            /* install() would have removed what the list omits, but it cannot be
             * used here: it replaces the map, and this reply has no cgroup id
             * for the containers it could not key, so installing it would drop
             * their entries and turn their next event into an escalation.
             *
             * Upserts alone never remove anything, though -- so a container
             * that went away while the cursor was invalid kept its cgroups in
             * the map, and allowed in the kernel, for as long as the node held
             * one container nobody could key. The inode is then free for the
             * kernel to hand to something else, and whatever lands on it is
             * filed under a container that no longer exists.
             *
             * The reply does say which containers EXIST, so name the departures
             * one by one. A `removed` event withdraws every cgroup that
             * container held, which is what install() would have done for it.
             * Only when the reply enumerates: without that there is no
             * difference between "gone" and "not mentioned" (#37532). */
            if (!plan.installWholeList && plan.enumerated)
            {
                std::set<std::string> present = delta.unkeyed;

                for (const auto& ref : delta.containers)
                {
                    present.insert(ref.containerId);
                }

                for (const auto& containerId : mappedContainers)
                {
                    if (present.count(containerId) != 0)
                    {
                        continue;
                    }

                    CgroupDeltaEvent gone;
                    gone.kind         = CgroupDeltaEvent::Kind::removed;
                    gone.container_id = containerId;
                    plan.events.push_back(std::move(gone));
                }
            }

            plan.admissionView = mergeAdmissionView(currentView, delta.containers, delta.complete);
            foldUnkeyedIntoView(plan.admissionView, delta.unkeyed, delta.admitted, delta.admittedKnown);
            applyAdmittedSet(plan.admissionView, delta.admitted, delta.admittedKnown, plan.enumerated);
            return plan;
        }

        plan.events.reserve(delta.events.size());

        for (const auto& event : delta.events)
        {
            CgroupDeltaEvent translated;
            translated.container_id     = event.containerId;
            translated.cgroup_id        = event.cgroupId;
            translated.extra_cgroup_ids = event.extraCgroupIds;

            switch (event.kind)
            {
                    using Kind = wazuh::container_instances_client::ContainerEventRef::Kind;

                case Kind::added:
                    translated.kind = CgroupDeltaEvent::Kind::added;
                    break;

                case Kind::removed:
                    translated.kind = CgroupDeltaEvent::Kind::removed;
                    break;

                case Kind::changed:
                default:
                    translated.kind = CgroupDeltaEvent::Kind::changed;
                    break;
            }

            plan.events.push_back(std::move(translated));
        }

        /* Merged into the view rather than rebuilt from it: a delta describes
         * transitions, so a container it does not mention is unchanged, not
         * gone. `added` and `changed` carry the connector's current answer for
         * that container; `removed` carries no record, and a container that no
         * longer exists needs no admission -- dropping it also keeps the view
         * from growing without bound on a host that churns containers. */
        std::map<std::string, bool> updated {currentView};

        for (const auto& event : delta.events)
        {
            if (event.containerId.empty()) continue;

            using Kind = wazuh::container_instances_client::ContainerEventRef::Kind;

            if (event.kind == Kind::removed)
            {
                updated.erase(event.containerId);
            }
            else
            {
                updated[event.containerId] = event.synced;
            }
        }

        /* ...then the containers no event can describe, because the connector
         * cannot key them... */
        foldUnkeyedIntoView(updated, delta.unkeyed, delta.admitted, delta.admittedKnown);

        /* ...and then the set, which is the only place an admission change with
         * no event of its own can reach this view. */
        applyAdmittedSet(updated, delta.admitted, delta.admittedKnown, plan.enumerated);

        plan.admissionView = std::move(updated);
        return plan;
    }

    struct ContainerEventDrain::Impl
    {
        explicit Impl(const DrainConfig& cfg)
            : config(cfg)
            , staging(cfg.max_paths_per_container, cfg.max_containers, cfg.settle_delay_ms)
            , router(map, staging)
            , client(cfg.connector_socket_path)
        {
        }

        DrainConfig                                                  config;
        CgroupContainerMap                                           map;
        ContainerEventStaging                                        staging;
        ContainerEventRouter                                         router;
        wazuh::container_instances_client::ContainerInstancesClient  client;

        rt_handle_t      handle{nullptr};
        ReconcileHandler handler;

        /* Where the drain has read up to in container_instances' journal.
         *
         * In memory only, and that is not a shortcut: on restart the drain reopens
         * the engine with an empty kernel allowlist and has to re-admit every
         * container anyway, so a persisted cursor would describe a world it no
         * longer has. Zero means "no cursor", which the module answers with the
         * full set — the seeding path, reached without a special case. */
        std::uint64_t cursor_epoch{0};
        std::uint64_t cursor_seq{0};

        /* Previous values of the counters that record work being shed.
         *
         * Every bound on this path -- the per-container path budget, the container
         * budget, the unknown-cgroup set, the kernel ring -- escalates or discards
         * SILENTLY. The counters were already collected and thread-safe, and nothing
         * ever read them: a container that recorded a quarter of its file changes
         * looked exactly like one that recorded all of them. Diffed once per
         * resolver pass so a steady state stays quiet and movement gets one line. */
        StagingStats    last_staging{};
        RouterStats     last_router{};
        CgroupMapStats  last_map{};
        bool            stats_primed{false};

        /* Woken by container_instances when its container list changes. Unbound is
         * a supported state, not a failure: fd() is then -1 and the resolver falls
         * back to its interval, which is what it did before this existed. */
        wazuh::container_instances_client::NotifySocket notify;

        /* Wakes the resolver out of poll() on shutdown. A short poll timeout would
         * do the same job only while the interval stays small, and it is on its way
         * to tens of seconds. */
        int stop_event_fd{-1};

        std::atomic<bool> stop{false};

        /* Set when the BPF object predates per-cgroup drop accounting. Only then may
         * an event's in-band RT_F_DROPS_BEFORE flag be treated as loss: with the
         * per-cgroup map available the in-band counter is global, and acting on it
         * would re-baseline every container for one container's loss — the exact
         * thing D14's counter map exists to avoid. */
        std::atomic<bool> per_cgroup_drops_unavailable{false};

        /* The kernel is discarding events from cgroups that are not on the
         * allowlist. Set in start() before any thread exists, and afterwards only
         * cleared, on the resolver thread, by disableAllowlist(). Read on that same
         * thread; the drain thread never looks at it, which is why it needs no
         * synchronisation. */
        bool allowlist_active{false};

        std::thread drain_thread;
        std::thread resolver_thread;
        std::thread consumer_thread;

        void onEvent(const rt_file_event* ev)
        {
            if (ev == nullptr) return;

            if (per_cgroup_drops_unavailable.load(std::memory_order_relaxed) &&
                    (ev->flags & RT_F_DROPS_BEFORE) != 0)
            {
                /* Loss we cannot attribute to anyone. Served once by the staging
                 * buffer, so the several flag-bearing events one loss episode
                 * produces coalesce into one escalation. */
                router.onUnattributedDrops();
            }

            if (ev->event_type == RT_EV_FILE_RENAME)
            {
                /* The event names the destination only; the source path is never
                 * reported by anything. See C21 and ContainerEventRouter::onRename. */
                router.onRename(ev->cgroup_id);
                return;
            }

            /* filename is a fixed 4 KiB field, so bound the scan rather than trusting
             * it to be terminated. */
            const auto length = ::strnlen(ev->filename, sizeof(ev->filename));

            if (length == 0) return;

            if (ev->event_type == RT_EV_FILE_UNLINK)
            {
                /* The kernel names the removed file, so this is not the inference
                 * D15 forbids — see ReconcileMode::deletePaths. Staging it as an
                 * ordinary path would have the re-read find nothing and, correctly,
                 * do nothing, which is why an in-container `rm` used to go
                 * unreported until something else forced a walk. */
                router.onUnlink(ev->cgroup_id, std::string{ev->filename, length});
                return;
            }

            /* ev->pid feeds the staging buffer's settle, not the routing: a path
             * whose writer has exited can be read at once. */
            router.onEvent(ev->cgroup_id, std::string{ev->filename, length}, ev->pid);
        }

        void drainLoop()
        {
            int consecutive_errors = 0;

            while (!stop.load(std::memory_order_relaxed))
            {
                const int polled = rt_poll(handle, &Impl::sinkTrampoline, this, config.poll_timeout_ms);

                if (polled < 0)
                {
                    /* EINTR is routine — a signal delivered mid-poll — and must not
                     * be allowed to tear the drain down. Anything else, repeatedly,
                     * means the ring is gone and polling it forever would spin. */
                    if (polled != -EINTR && ++consecutive_errors >= 10)
                    {
                        LogError("Container eBPF drain: rt_poll failed repeatedly (" +
                                 std::to_string(polled) + "); stopping the event-driven reconcile. "
                                 "Scheduled baselines are unaffected.");
                        break;
                    }
                }
                else
                {
                    consecutive_errors = 0;
                }

                drainDrops();
            }
        }

        void drainDrops()
        {
            const int reported = rt_drain_drops(handle, &Impl::dropTrampoline, this);

            if (reported < 0 && !per_cgroup_drops_unavailable.load(std::memory_order_relaxed))
            {
                /* A BPF object older than this engine. Latch it once — the engine
                 * logs it once too — and fall back to the in-band flag from here on. */
                per_cgroup_drops_unavailable.store(true, std::memory_order_relaxed);
                LogError("Container eBPF drain: the loaded BPF object has no per-cgroup drop "
                         "accounting, so lost events cannot be attributed to a container. "
                         "Falling back to re-baselining every container on any loss.");
            }

            /* The successful path logged nothing, so the only visible drop message
             * was the one saying drops could not be attributed. Events lost while
             * accounting worked perfectly were invisible. */
            if (reported > 0)
            {
                LogWarn("Container eBPF drain: the kernel dropped events for " + std::to_string(reported) +
                        " container(s) since the last check; each is being re-baselined, so its file state "
                        "stays correct but the individual changes are gone.");
            }
        }

        /* One line when work is being shed, nothing while the numbers hold still. */
        void reportShedWork()
        {
            const auto st = staging.stats();
            const auto rt = router.stats();
            const auto mp = map.stats();

            if (!stats_primed)
            {
                last_staging = st;
                last_router = rt;
                last_map = mp;
                stats_primed = true;
                return;
            }

            const auto moved = [](unsigned long long now, unsigned long long before) -> unsigned long long
            {
                return (now > before) ? (now - before) : 0ULL;
            };

            const auto pathOverflows = moved(st.path_overflows, last_staging.path_overflows);
            const auto containerOverflows = moved(st.unknown_overflows, last_staging.unknown_overflows);
            const auto dropEscalations = moved(st.drop_escalations, last_staging.drop_escalations);
            const auto unattributed = moved(rt.unattributed, last_router.unattributed);
            const auto globalEscalations = moved(rt.global_escalations, last_router.global_escalations);
            const auto mapOverflows = moved(mp.unknown_overflows, last_map.unknown_overflows);
            const auto negativeResets = moved(mp.negative_cache_resets, last_map.negative_cache_resets);

            last_staging = st;
            last_router = rt;
            last_map = mp;

            if ((pathOverflows | containerOverflows | dropEscalations | unattributed | globalEscalations |
                    mapOverflows | negativeResets) == 0ULL)
            {
                return;
            }

            std::string line = "Container eBPF drain: shedding work -";
            const auto add = [&line](const char* what, unsigned long long n)
            {
                if (n > 0)
                {
                    line += " " + std::string{what} + "=" + std::to_string(n);
                }
            };
            add("containers_over_path_budget", pathOverflows);
            add("containers_over_budget", containerOverflows);
            add("escalated_on_loss", dropEscalations);
            add("events_unattributed", unattributed);
            add("full_rewalks", globalEscalations);
            add("unknown_cgroups_dropped", mapOverflows);
            add("negative_cache_resets", negativeResets);
            line += ". Affected containers are re-walked, so their recorded state stays correct, but the "
                    "individual changes in between are not reported.";
            LogWarn(line);
        }

        void resolverLoop()
        {
            auto next_list = std::chrono::steady_clock::now();

            while (!stop.load(std::memory_order_relaxed))
            {
                const auto now = std::chrono::steady_clock::now();

                if (now >= next_list)
                {
                    refreshContainerList();
                    reportShedWork();
                    next_list = now + std::chrono::milliseconds(config.resolver_interval_ms);
                }

                resolvePending();
                router.pumpUnknownOverflow();

                if (waitForWork(next_list))
                {
                    /* container_instances says its list moved. Refreshing on the
                     * next pass rather than here keeps one call site for the
                     * refresh, and the loop head is one statement away. */
                    next_list = std::chrono::steady_clock::now();
                }
            }
        }

        /* Blocks until container_instances reports a change, the next scheduled
         * refresh is due, or stop() fires. Returns true only for the first.
         *
         * The interval this replaces is now a FLOOR rather than the way changes are
         * noticed. Discovery used to cost up to a full interval because nothing
         * else could report a new container; with the kernel filter in place that
         * was also the only thing admitting its cgroup, so the wait was the
         * detection latency. Now the common case is a datagram arriving in
         * milliseconds, and the interval only has to cover what no notification can
         * report — a container the module itself never learned about.
         *
         * Three fds, and each is load-bearing:
         *   notify   the wake. Absent (unbound) it is -1, which poll() skips, so
         *            the loop degrades to exactly its previous behaviour.
         *   stop     an eventfd, not a short timeout. The floor is heading for tens
         *            of seconds, and without this, shutdown would wait out whatever
         *            remained of it.
         *   timeout  bounded by resolvePending()'s pacing while cgroups are still
         *            unresolved, since those need revisiting on their own cadence
         *            and no notification is coming for them. */
        bool waitForWork(std::chrono::steady_clock::time_point next_list)
        {
            const auto until_refresh =
                std::chrono::duration_cast<std::chrono::milliseconds>(next_list - std::chrono::steady_clock::now());
            const int timeout_ms = resolverWaitMs(until_refresh, map.unresolvedCount() > 0);

            struct pollfd fds[2];
            fds[0].fd      = notify.fd();
            fds[0].events  = POLLIN;
            fds[0].revents = 0;
            fds[1].fd      = stop_event_fd;
            fds[1].events  = POLLIN;
            fds[1].revents = 0;

            const int ready = ::poll(fds, 2, timeout_ms);

            if (ready <= 0)
            {
                return false; /* timed out, or EINTR: treat both as "carry on". */
            }

            if ((fds[1].revents & POLLIN) != 0)
            {
                return false; /* stopping; the loop condition picks it up. */
            }

            if ((fds[0].revents & POLLIN) != 0)
            {
                /* Drained and discarded. The payload names a cursor, but acting on
                 * it would make a hint into authority: what actually changed is
                 * read from the query socket. Draining collapses a burst — a
                 * ten-container deploy is one refresh, not ten. */
                static_cast<void>(notify.drain());
                return true;
            }

            return false;
        }

        /* Bring the cgroup map up to date with container_instances.
         *
         * Reads forward from a cursor where it can, and falls back to the whole
         * list where it cannot. The three ways it cannot are not interchangeable:
         *
         *   unreachable        nothing was obtained. Change NOTHING — install()
         *                      replaces the positive map, so applying an empty list
         *                      from a connector that simply did not answer would
         *                      un-attribute every container at once and turn the
         *                      next event from each into an escalation. C15's
         *                      failure shape one level down.
         *   deltas unsupported an older container_instances, which ignored the
         *                      cursor and answered with the set. Exactly today's
         *                      behaviour, reached without an error path.
         *   resync required    the cursor is from another store lifetime, or its
         *                      position has been evicted. The set rides the same
         *                      reply, so this costs no extra round trip. */
        void refreshContainerList()
        {
            const auto delta = client.listContainersSince(cursor_epoch, cursor_seq);
            const auto plan = planListRefresh(delta, admission_view, router.mappedContainerIds());

            if (!plan.act) return;

            syncAllowlist(plan.installWholeList ? router.applyContainerList(plan.containers)
                          : router.applyContainerDelta(plan.events));
            publishAdmission(plan.admissionView, plan.enumerated);

            /* Advanced only after the plan has been applied. A crash in between
             * replays it, which is harmless — the map converges to the same place
             * and a repeated walk costs time, not correctness — whereas advancing
             * first would drop it silently. */
            cursor_epoch = delta.epoch;
            cursor_seq   = delta.seq;
        }

        /* Who may report, as this drain last heard it.
         *
         * The connector decides admission and says so on every list reply, in
         * both shapes: ContainerRef::synced on a full list, and the same key
         * inside each delta event's `data`. Holding the answer here is what
         * lets a container created at run time be admitted at run time -- the
         * FIM baseline's own listing is taken once, at startup, and a container
         * it never saw would otherwise read as refused for the life of the
         * process.
         *
         * A map rather than two sets because the distinction that matters is
         * per container: present-and-false (the cap refused it) must not be
         * confused with absent (never heard of), which is exactly what
         * fim_container_admission_is_stale() exists to tell apart.
         *
         * Containers the connector could not key are in here too. The cap ranks
         * a container by its id, which is a fact that needs no attribution key,
         * so there is no third state to keep beside the map (#37532). */
        std::map<std::string, bool> admission_view;

        /* The installed snapshot is behind admission_view. See
         * decideAdmissionPublish() for why a "publish on change" rule alone
         * loses the update that was deferred. */
        bool admission_unpublished {false};

        /* So the deferral is said once, not every resolver cycle. */
        bool admission_deferral_logged {false};

        /* Hands the view to the FIM side, which owns what to do about it.
         *
         * ONLY when something actually changed: installing it runs a
         * reconciliation that re-reads every container's rows, and the resolver
         * refreshes the list every resolver_interval_ms whether or not any
         * container appeared.
         *
         * And NEVER before the whole-node baseline has finished. This runs on
         * the resolver thread, which is live from the moment the drain starts --
         * before the walk, by design, so no change is missed while it runs. The
         * reconciliation reads and writes file_entry, and a single-row write
         * racing that walk's open scoped transaction is what
         * fim_container_events_release() exists to prevent for the consumer
         * thread; it is the same hazard here. The walk takes its own listing and
         * installs admission from it, so nothing is lost by waiting: the view is
         * still tracked meanwhile, and the first change AFTER release publishes
         * it. */
        void publishAdmission(const std::map<std::string, bool>& updated, bool enumerated)
        {
            const bool changed = (updated != admission_view);
            admission_view = updated;

            const auto decision =
                decideAdmissionPublish(changed, admission_unpublished, staging.released(), enumerated);

            if (decision == AdmissionPublish::nothing) return;

            if (decision == AdmissionPublish::defer)
            {
                admission_unpublished = true;

                /* Said once, and at a level an operator sees: until this
                 * clears, containers.synced_limit is not being applied and
                 * every container reports. The walk used to be relied on to
                 * install admission in the meantime, and no longer can -- it
                 * refuses the same reply for the same reason this does.
                 *
                 * Reaching this at all now means a connector too old to say
                 * what it could not key, so it is a version mismatch rather
                 * than something that clears on its own. */
                if (!enumerated && staging.released() && !admission_deferral_logged)
                {
                    admission_deferral_logged = true;
                    LogWarn("Container FIM: holding the admission snapshot because the container connector does "
                            "not report the containers it could not identify, so this agent cannot tell one that "
                            "is gone from one it has not resolved. Until that clears every container reports and "
                            "containers.synced_limit is not applied.");
                }

                return;
            }

            admission_unpublished = false;
            admission_deferral_logged = false;

            std::vector<const char*> known;
            std::vector<const char*> admitted;
            known.reserve(admission_view.size());

            /* The view holds the containers the connector could not key as
             * well, so they reach the known set here like any other. The bridge
             * reads absence from it as "the snapshot predates this container"
             * and retakes the listing to settle it; for one that can never be
             * keyed that would be a listing per batch, for an answer that would
             * not change. */
            for (const auto& [id, is_admitted] : admission_view)
            {
                known.push_back(id.c_str());

                if (is_admitted)
                {
                    admitted.push_back(id.c_str());
                }
            }

            fim_container_set_admission(known.data(), known.size(), admitted.data(), admitted.size());
        }

        /* Mirror a list refresh into the kernel filter.
         *
         * The two sets are disjoint by construction — `removed` holds only cgroups
         * absent from the new list, so an inode handed to a different container is
         * in `added` alone and never in both. Adding first regardless, because the
         * cost of being wrong about that is a live container going unmonitored. */
        void syncAllowlist(const CgroupListDelta& delta)
        {
            if (!allowlist_active) return;

            for (const auto& entry : delta.added)
            {
                if (rt_allow_cgroup(handle, entry.first) != 0)
                {
                    disableAllowlist(entry.first);
                    return;
                }
            }

            for (const auto cgroup_id : delta.removed)
            {
                /* Cgroup ids are inodes and are reused. An allowlist that only grew
                 * would eventually admit whatever inherits a dead container's
                 * inode, and those events would be attributed by the map — which
                 * has dropped the entry — to nobody. */
                rt_deny_cgroup(handle, cgroup_id);
            }
        }

        /* The allowlist could not take a container. Left alone that container's
         * events are discarded in the kernel with nothing but an engine log to say
         * so, which is precisely the silent gap this filter is not allowed to
         * introduce — so stop filtering and go back to delivering everything.
         *
         * Unfiltered costs CPU. This would cost a container's change detection. */
        void disableAllowlist(std::uint64_t cgroup_id)
        {
            if (rt_set_cgroup_mode(handle, RT_CGROUP_MODE_ALL) != 0)
            {
                /* Still filtering, and still unable to admit this cgroup. The
                 * router keeps filtering mode on deliberately: escalating every
                 * newly listed container to a walk is the only change detection
                 * left, and turning it off here would remove that too. */
                LogError("Container eBPF drain: cgroup " + std::to_string(cgroup_id) +
                         " could not be added to the kernel event filter, and the filter could not be "
                         "turned off either. Containers beyond the filter's capacity will only be "
                         "re-walked when they are first listed, not when their files change.");
                return;
            }

            allowlist_active = false;
            router.setFiltering(false);

            LogWarn("Container eBPF drain: cgroup " + std::to_string(cgroup_id) + " did not fit the "
                    "kernel event filter, so filtering has been turned off and every file event on the "
                    "host is delivered again. Container change detection is unaffected; this costs CPU.");
        }

        void resolvePending()
        {
            const auto pending = map.takeUnresolved();
            std::size_t attempted = 0;

            for (const auto cgroup_id : pending)
            {
                if (stop.load(std::memory_order_relaxed)) return;

                if (attempted++ >= config.max_resolves_per_cycle)
                {
                    /* Hand the rest back so the next cycle picks them up; without
                     * this they stay marked dispatched and are never resolved. */
                    map.rearm(cgroup_id);
                    continue;
                }

                const auto result = client.resolveByCgroupId(cgroup_id);

                using wazuh::container_instances_client::LookupStatus;

                switch (result.status)
                {
                    case LookupStatus::resolved:
                        {
                            const auto container_id = ContainerIdFromResolveReply(result.json);

                            if (container_id.empty())
                            {
                                map.rearm(cgroup_id);
                            }
                            else
                            {
                                router.applyContainerResolution(cgroup_id, container_id);

                                /* Not the path by which a container normally reaches the
                                 * allowlist — that is syncAllowlist() — because under
                                 * filtering an event can only arrive from a cgroup that
                                 * is already allowed. It covers the one race that can
                                 * still land here: a container the connector omitted
                                 * from one list was denied in the kernel while an event
                                 * of its was already in the ring, and resolving that
                                 * event puts it back in the map. Without this it would
                                 * be attributable but undeliverable until the next
                                 * refresh. */
                                if (allowlist_active)
                                {
                                    rt_allow_cgroup(handle, cgroup_id);
                                }
                            }

                            break;
                        }

                    case LookupStatus::notContainer:
                        router.applyNotContainer(cgroup_id);
                        break;

                    case LookupStatus::pending:
                    case LookupStatus::unavailable:
                    default:
                        /* Nothing was decided, so it must be asked again — otherwise
                         * a cold-cache `pending` parks the cgroup as dispatched
                         * forever and its container is never discovered. */
                        map.rearm(cgroup_id);
                        break;
                }
            }
        }

        void consumerLoop()
        {
            Batch batch;

            while (!stop.load(std::memory_order_relaxed))
            {
                if (!staging.nextBatch(batch, 500)) continue;

                const auto request = PlanFor(batch);

                if (request.empty() || !handler) continue;

                handler(request);
            }
        }

        static void sinkTrampoline(const rt_file_event* ev, void* user)
        {
            static_cast<Impl*>(user)->onEvent(ev);
        }

        static void dropTrampoline(unsigned long long cgroup_id, unsigned int drops, void* user)
        {
            static_cast<Impl*>(user)->router.onDrops(cgroup_id, drops);
        }
    };

    ContainerEventDrain& ContainerEventDrain::instance()
    {
        static ContainerEventDrain drain;
        return drain;
    }

    ContainerEventDrain::~ContainerEventDrain()
    {
        /* Deliberately does NOT join, and deliberately leaks the Impl.
         *
         * This is a function-local static, so it is destroyed during process exit.
         * stop() joins the consumer thread, which may be inside a container walk
         * taking seconds — stalling syscheckd's exit for that long, on a path where
         * nobody is waiting for a result. syscheckd's other long-lived threads
         * (realtime, whodata) are not joined at exit either, so this matches the
         * daemon's existing shape rather than inventing a stricter one for the
         * newest thread.
         *
         * Signalling without joining means the threads may still be running, so the
         * Impl they reference must outlive them: deleting it here would turn a tidy
         * exit into a use-after-free. The OS reclaims it a moment later.
         *
         * fim_container_events_stop() remains the way to tear the drain down
         * properly, where blocking until the threads are actually gone is the
         * point. */
        if (m_impl != nullptr)
        {
            m_impl->stop.store(true, std::memory_order_relaxed);
            m_impl->staging.stop();
            m_impl = nullptr;
        }
    }

    bool ContainerEventDrain::running() const
    {
        return m_impl != nullptr && m_impl->handle != nullptr;
    }

    bool ContainerEventDrain::start(const DrainConfig& config, ReconcileHandler handler)
    {
        if (m_impl != nullptr) return true;

        /* The record is exchanged by raw memory reinterpretation, so a major
         * mismatch is silent corruption rather than an error. rt_engine.h requires
         * every consumer to refuse it. */
        if (rt_abi_major() != RT_ABI_MAJOR)
        {
            LogError("Container eBPF drain: engine ABI major " + std::to_string(rt_abi_major()) +
                     " does not match this build's " + std::to_string(RT_ABI_MAJOR) +
                     "; refusing to start the event-driven reconcile.");
            return false;
        }

        auto impl = new Impl(config);

        rt_filter filter;
        std::memset(&filter, 0, sizeof(filter));
        filter.type_mask    = RT_FILE_ALL_BITS;
        filter.bpf_obj_path = config.bpf_object_path.empty() ? nullptr : config.bpf_object_path.c_str();
        filter.libbpf_path  = config.libbpf_path.empty() ? nullptr : config.libbpf_path.c_str();
        filter.log          = &EngineLog;
        filter.log_user     = nullptr;

        /* Open already filtering, rather than opening in ALL and narrowing once the
         * map is seeded. Both end in the same place, but the narrowing order has a
         * window — between rt_open() and the switch nothing is polling the ring yet,
         * so the whole host's file traffic lands in it, and the overflow that
         * follows sets RT_F_DROPS_BEFORE on the first events the drain ever sees.
         * Starting closed makes that window deliver nothing instead.
         *
         * Nothing is lost by it: the seeding refresh below runs before the drain
         * thread exists, and the baseline walk that follows start() reads every
         * container's current state anyway. */
        filter.cgroup_mode = config.cgroup_allowlist ? RT_CGROUP_MODE_ALLOWLIST : RT_CGROUP_MODE_ALL;

        /* This consumer reads cgroup_id, filename, pid, event_type and flags, and
         * nothing else. The process-context fields exist for host FIM whodata's
         * "who" attribution and cost two dentry walks per event to produce — the
         * dominant per-event cost on the kprobe path, which is the majority
         * configuration.
         *
         * Still worth setting with the filter above in place: the two attack the
         * same cost from opposite ends. The filter removes events; this removes
         * per-event work from the events that remain, and from every event when the
         * filter has had to turn itself off. */
        filter.skip_mask = RT_SKIP_PROC_CONTEXT;

        impl->handle = rt_open(&filter);

        if (impl->handle == nullptr && filter.cgroup_mode == RT_CGROUP_MODE_ALLOWLIST)
        {
            /* rt_open() REFUSES allowlist mode on a BPF object that has no filtering
             * maps, rather than quietly delivering everything. That is the right
             * call for the engine — a consumer that asked to filter and silently got
             * the whole host is a correctness surprise — and the wrong outcome for
             * this one, where it would mean no container change detection at all.
             *
             * Worth retrying rather than treating as impossible: rt_file.bpf.o is in
             * no packaging manifest (14 §14.6), so an object older than the running
             * agent is a real configuration and not a hypothetical. Unfiltered is
             * what this consumer did until this release, and it works. */
            filter.cgroup_mode = RT_CGROUP_MODE_ALL;
            impl->handle       = rt_open(&filter);

            if (impl->handle != nullptr)
            {
                LogWarn("Container eBPF drain: the loaded BPF object cannot filter events in the "
                        "kernel, so every file event on the host is delivered and discarded in the "
                        "agent instead. Container file monitoring is unaffected; this costs CPU. "
                        "Rebuild rt_file.bpf.o to avoid it.");
            }
        }

        if (impl->handle == nullptr)
        {
            /* Expected on any host without the capability. Host FIM keeps working.
             * Deliberately NOT "container FIM falls back to scheduled baselines":
             * there is no scheduled container baseline to fall back to —
             * fim_run_container_baseline() runs once from main(), and the only
             * thing that re-runs it is this drain's own rebaselineAll. The caller
             * turns this into a WARNING when container directories are actually
             * configured; the detail stays here at debug level. */
            LogDebug("Container eBPF drain: the eBPF engine is unavailable (no rt_file.bpf.o, or the "
                     "kernel/capabilities do not permit loading it).");
            delete impl;
            return false;
        }

        if (rt_host_cgroup_v1(impl->handle) != 0)
        {
            /* A host with no unified hierarchy. bpf_get_current_cgroup_id() reports
             * the task's cgroup in THAT hierarchy, so here it reports nothing that
             * identifies a container (spike #37396 ADR-002) — which is why this
             * used to refuse outright.
             *
             * It refuses no longer, because the helper was the limit and not the
             * kernel: the v1 controllers' cgroups are kernfs nodes carrying ids of
             * exactly the same kind, and the engine can be pointed at one. The
             * controller is chosen by the shared selector, which the resolver asks
             * first too, so on any host where it answers the two halves read the
             * same hierarchy. Where it does NOT answer, this consumer refuses
             * outright while the resolver falls back to its own list -- so the
             * halves differ by one half having no key at all, rather than by two
             * keys that silently fail to match. */
            const char* controller = nullptr;
            const int subsys = wz_cgroup_v1_select_subsys(&controller);

            /* The floor the old refusal existed to provide, kept: a host where no
             * controller can serve as a key gets no attribution rather than wrong
             * attribution. The two ways of getting here are reported apart,
             * because they send the reader to different places -- one is a
             * property of the host, the other is a stale build artifact, and a
             * single message for both blamed the host for either. */
            if (subsys < 0)
            {
                /* None of the candidates is mounted as a v1 hierarchy, or the only
                 * one that is has no subsystem slot to read -- `name=systemd` is
                 * the realistic case. */
                LogError("Container eBPF drain: this host has no unified cgroup hierarchy and no controller "
                         "that can identify a container, so an event's cgroup_id cannot be attributed; "
                         "disabling the event-driven reconcile.");
                rt_close(impl->handle);
                delete impl;
                return false;
            }

            /* The name as well as the index: the engine prefers the kernel's own
             * enum and keeps our /proc/cgroups reading only as the fallback. On a
             * 6.12 or newer kernel the two can disagree, and there the row order
             * is the wrong one -- see wz_cgroup_subsys_index(). */
            if (rt_set_cgroup_v1_subsys(impl->handle, controller, static_cast<unsigned int>(subsys)) != 0)
            {
                /* The host offered a usable controller and the engine would not
                 * take it. The engine has already said why on its own logger. */
                LogError(std::string{"Container eBPF drain: this host's '"} + (controller ? controller : "?") +
                         "' controller can identify a container, but the eBPF engine refused to read ids from "
                         "it; disabling the event-driven reconcile. See the preceding eBPF message for the "
                         "reason -- a loaded rt_file.bpf.o older than this agent is the usual one.");
                rt_close(impl->handle);
                delete impl;
                return false;
            }

            /* Worth a line on the healthy path: "which hierarchy did the agent
             * think it was on, and what did it key by?" is the first question
             * asked of any attribution bug, and an answer that appears only when
             * something is wrong leaves the working case indistinguishable from
             * the probe never having run. */
            LogWarn(std::string{"Container eBPF drain: no unified cgroup hierarchy on this host; reading "
                                "container cgroup ids from the '"} +
                    (controller != nullptr ? controller : "?") + "' controller instead.");
        }

        if (rt_cgroup_id_is_usable(impl->handle) == 0)
        {
            /* Belt and braces, and cheap: every path above either configured a
             * usable key or returned. Asking the engine rather than re-deriving the
             * answer here keeps one source of truth for whether attribution works,
             * which is the question this consumer exists to answer. */
            LogError("Container eBPF drain: the engine reports no usable container identifier; "
                     "disabling the event-driven reconcile.");
            rt_close(impl->handle);
            delete impl;
            return false;
        }

        /* The two sides choose their key independently -- the producer from the
         * cgroup layout, this consumer from what the engine can read -- and they are
         * meant to reach the same answer through the same shared selector. When they
         * did not, nothing said so: the store held mount-namespace inodes, the
         * events carried controller cgroup ids, every lookup missed, and both halves
         * logged success. Ask once at startup, because a mismatch makes the whole
         * feature a no-op and is otherwise invisible.
         *
         * This consumer always keys on a cgroup id: the helper on a unified host,
         * the configured v1 controller on a legacy one. Anything else disagrees. */
        /* The producer binds its socket before its first enumeration finishes, so
         * at this point it may be up but not yet answering -- the same startup race
         * container_baseline_scanner.cpp retries around. One 1 s attempt would
         * report "cannot verify" for a producer that is merely slow, so retry
         * briefly; but only when the socket is actually there, or a host with no
         * container_instances at all pays the whole budget for an answer that can
         * never come. */
        constexpr int kKeyKindAttempts = 10;
        constexpr auto kKeyKindDelay = std::chrono::milliseconds {500};

        std::optional<wz_container_key_kind_t> producerKind;

        for (int attempt = 1; attempt <= kKeyKindAttempts; ++attempt)
        {
            producerKind = impl->client.hostKeyKind();

            if (producerKind)
            {
                break;
            }

            struct stat socketInfo
            {
            };

            if (::stat(impl->client.socketPath().c_str(), &socketInfo) != 0)
            {
                break; // No container_instances on this host; nothing to wait for.
            }

            if (attempt < kKeyKindAttempts)
            {
                std::this_thread::sleep_for(kKeyKindDelay);
            }
        }

        if (producerKind)
        {
            if (*producerKind != WZ_CONTAINER_KEY_CGROUP)
            {
                LogError(std::string{"Container eBPF drain: container_instances is publishing '"} +
                         wz_container_key_kind_name(*producerKind) +
                         "' keys while this consumer reads cgroup ids, so no event can ever be attributed. "
                         "Disabling the event-driven reconcile rather than running with a key space the "
                         "producer does not serve.");
                rt_close(impl->handle);
                delete impl;
                return false;
            }
        }
        else
        {
            /* Not a mismatch -- an unanswered question, which is what an older
             * producer and an absent one both look like. Carry on, because
             * refusing here would disable attribution on every host whose
             * container_instances is simply older than this check. But say so: a
             * disagreement that nothing reports is the failure this whole check
             * exists to end, and silence here reads exactly like agreement. */
            LogWarn("Container eBPF drain: container_instances did not state which key kind it publishes, so "
                    "attribution is running unverified. If no container is ever enriched, the two halves are "
                    "probably keying on different number spaces.");
        }

        impl->handler = std::move(handler);

        impl->allowlist_active = (filter.cgroup_mode == RT_CGROUP_MODE_ALLOWLIST);

        /* Seed the map before the drain starts, so containers that already exist are
         * attributable from the first event rather than each producing an
         * escalation. A failure here is survivable: the resolver retries.
         *
         * Under filtering this also seeds the KERNEL, and it has to happen with the
         * router's filtering mode still off. On it, every container in this first
         * list would be "newly listed" and escalate to a walk — a whole-node
         * re-walk, immediately after the baseline walk that already read all of
         * them.
         *
         * This is ONE attempt, bounded by the client's 1 s timeout. It is not
         * retried, and that is worth stating because the component immediately
         * after it does retry: the baseline scanner waits up to 10 x 500 ms for the
         * connector, because the container_instances socket binds BEFORE its first
         * enumeration completes, so "reachable but empty" is a normal cold-start
         * answer rather than a failure
         * (container_baseline_scanner.cpp's kListRetryAttempts).
         *
         * So the two can disagree: this seed can come back empty while the baseline,
         * a moment later, waits and gets the full list. When that happens the
         * resolver's first non-empty refresh sees every container as newly listed
         * and escalates all of them, and the node is walked a second time just after
         * the baseline walked it.
         *
         * That is wasteful, not wrong - a walk re-reads current state and produces
         * no alerts for rows that have not changed - and it is deliberately
         * preferred to the alternative. Suppressing those escalations would mean
         * trusting that the baseline covered every container, and the baseline takes
         * its list at a single instant: a container created while the walk is still
         * running is in neither that list nor the suppressed set, and would be
         * allowlisted but never walked. A duplicated walk is recoverable; a
         * container whose rootfs is never enumerated is not. */
        impl->refreshContainerList();
        impl->router.setFiltering(impl->allowlist_active);

        /* Bound before the resolver thread starts, so a container created during
         * the baseline walk is announced rather than waiting out an interval.
         *
         * Failure here is not a startup failure. Without it the resolver polls as
         * it always did and nothing is lost but latency — and refusing to start
         * container FIM because a convenience socket could not be bound would trade
         * a bounded delay for an outage. */
        if (!impl->notify.bind(CI_NOTIFY_SYSCHECK))
        {
            LogDebug("Container eBPF drain: could not bind the container lifecycle notification socket; "
                     "container discovery falls back to polling every " +
                     std::to_string(config.resolver_interval_ms) + " ms.");
        }

        impl->stop_event_fd = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);

        m_impl = impl;

        impl->drain_thread    = std::thread([impl] { impl->drainLoop(); });
        impl->resolver_thread = std::thread([impl] { impl->resolverLoop(); });
        impl->consumer_thread = std::thread([impl] { impl->consumerLoop(); });

        LogDebug("Container eBPF drain: started; staging container file events until the baseline walk "
                 "commits.");
        return true;
    }

    void ContainerEventDrain::release()
    {
        if (m_impl == nullptr) return;

        m_impl->staging.release();
        LogDebug("Container eBPF drain: baseline walk committed; the reconcile consumer is now live.");
    }

    void ContainerEventDrain::stop()
    {
        if (m_impl == nullptr) return;

        Impl* impl = m_impl;
        m_impl     = nullptr;

        impl->stop.store(true, std::memory_order_relaxed);
        impl->staging.stop();

        /* Wakes the resolver out of poll() immediately rather than at the end of
         * whatever remained of its interval. Written after the stop flag so the
         * thread cannot wake, see no stop, and go back to waiting. */
        if (impl->stop_event_fd >= 0)
        {
            const std::uint64_t one = 1;
            static_cast<void>(::write(impl->stop_event_fd, &one, sizeof(one)));
        }

        if (impl->drain_thread.joinable()) impl->drain_thread.join();

        if (impl->resolver_thread.joinable()) impl->resolver_thread.join();

        if (impl->consumer_thread.joinable()) impl->consumer_thread.join();

        /* After the threads, never before: rt_close() detaches and frees everything
         * the handle owns, and the drain thread is inside rt_poll() on it. */
        rt_close(impl->handle);
        impl->handle = nullptr;

        if (impl->stop_event_fd >= 0)
        {
            ::close(impl->stop_event_fd);
            impl->stop_event_fd = -1;
        }

        delete impl;
    }

} // namespace fim_container_events
