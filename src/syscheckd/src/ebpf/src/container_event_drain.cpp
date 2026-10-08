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
#include <thread>
#include <utility>
#include <vector>

#include <poll.h>
#include <sys/eventfd.h>
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

        if (!delta.available) return;

        if (!delta.deltaSupported || delta.resyncRequired)
        {
            applyFullList(delta.containers);
        }
        else
        {
            std::vector<CgroupDeltaEvent> events;
            events.reserve(delta.events.size());

            for (const auto& event : delta.events)
            {
                CgroupDeltaEvent translated;
                translated.container_id = event.containerId;
                translated.cgroup_id    = event.cgroupId;

                switch (event.kind)
                {
                    using Kind = wazuh::container_instances_client::ContainerEventRef::Kind;
                    case Kind::added: translated.kind = CgroupDeltaEvent::Kind::added; break;
                    case Kind::removed: translated.kind = CgroupDeltaEvent::Kind::removed; break;
                    case Kind::changed:
                    default: translated.kind = CgroupDeltaEvent::Kind::changed; break;
                }

                events.push_back(std::move(translated));
            }

            syncAllowlist(router.applyContainerDelta(events));
        }

        /* Advanced only after the events have been applied. A crash in between
         * replays them, which is harmless — the map converges to the same place
         * and a repeated walk costs time, not correctness — whereas advancing
         * first would drop them silently. */
        cursor_epoch = delta.epoch;
        cursor_seq   = delta.seq;
    }

    void applyFullList(const std::vector<wazuh::container_instances_client::ContainerRef>& refs)
    {
        std::vector<std::pair<std::uint64_t, std::string>> containers;
        containers.reserve(refs.size());

        for (const auto& ref : refs)
        {
            containers.emplace_back(ref.cgroupId, ref.containerId);
        }

        syncAllowlist(router.applyContainerList(containers));
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
         * controller is chosen by the shared selector, so this and the resolver
         * cannot settle on different hierarchies and then miss every lookup
         * between them. */
        const char* controller = nullptr;
        const int subsys = wz_cgroup_v1_select_subsys(&controller);

        if (subsys < 0 || rt_set_cgroup_v1_subsys(impl->handle, static_cast<unsigned int>(subsys)) != 0)
        {
            /* The floor the old refusal existed to provide, kept: a host where
             * no controller can serve as a key gets no attribution rather than
             * wrong attribution. Reached when none of the candidates is mounted
             * as a v1 hierarchy, or when the only one that is has no subsystem
             * slot to read — `name=systemd` is the realistic case. */
            LogError("Container eBPF drain: this host has no unified cgroup hierarchy and no controller "
                     "that can identify a container, so an event's cgroup_id cannot be attributed; "
                     "disabling the event-driven reconcile.");
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
    if (const auto producerKind = impl->client.hostKeyKind())
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
