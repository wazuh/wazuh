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
#include "container_instances_client.hpp"

#include "rt_engine.h"

#include <json.hpp>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <thread>
#include <utility>
#include <vector>

namespace fim_container_events
{

namespace
{

void LogDebug(const std::string& message)
{
    fim_container_baseline_log_debug(message.c_str());
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
        , staging(cfg.max_paths_per_container, cfg.max_containers)
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

    std::atomic<bool> stop{false};

    /* Set when the BPF object predates per-cgroup drop accounting. Only then may
     * an event's in-band RT_F_DROPS_BEFORE flag be treated as loss: with the
     * per-cgroup map available the in-band counter is global, and acting on it
     * would re-baseline every container for one container's loss — the exact
     * thing D14's counter map exists to avoid. */
    std::atomic<bool> per_cgroup_drops_unavailable{false};

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

        router.onEvent(ev->cgroup_id, std::string{ev->filename, length});
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
                next_list = now + std::chrono::milliseconds(config.resolver_interval_ms);
            }

            resolvePending();
            router.pumpUnknownOverflow();

            /* Sleep in slices so stop() is not held up for a whole interval. */
            for (int slept = 0; slept < 200 && !stop.load(std::memory_order_relaxed); slept += 50)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
        }
    }

    void refreshContainerList()
    {
        bool       reachable = false;
        const auto refs      = client.listContainers(&reachable);

        /* GATED on reachability, and this is not defensive coding for its own
         * sake: install() REPLACES the positive map, so applying an unreachable
         * connector's empty list would un-attribute every container at once and
         * turn the next event from each into an escalation. That is C15's
         * failure shape one level down. */
        if (!reachable) return;

        std::vector<std::pair<std::uint64_t, std::string>> containers;
        containers.reserve(refs.size());

        for (const auto& ref : refs)
        {
            containers.emplace_back(ref.cgroupId, ref.containerId);
        }

        router.applyContainerList(containers);
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

    /* Deliberately ALL, not ALLOWLIST. In allowlist mode an event from a cgroup
     * that has not been added is invisible rather than merely unattributed,
     * which removes "an event arrived for a cgroup I do not know" as a discovery
     * path — the fallback that covers a container created after startup. Until
     * container_instances has a create-time trigger (item 20), narrowing the
     * filter would trade a bounded cost for a silent gap. */
    filter.cgroup_mode = RT_CGROUP_MODE_ALL;

    impl->handle = rt_open(&filter);

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
        /* bpf_get_current_cgroup_id() collapses to a fixed value on cgroup v1
         * (spike #37396 ADR-002), so every container shares one cgroup_id and
         * attribution would file every container's events under whichever
         * resolved first. Wrong attribution is worse than none. */
        LogError("Container eBPF drain: this host uses cgroup v1, where an event's cgroup_id "
                 "cannot identify a container; disabling the event-driven reconcile.");
        rt_close(impl->handle);
        delete impl;
        return false;
    }

    impl->handler = std::move(handler);

    /* Seed the map before the drain starts, so containers that already exist are
     * attributable from the first event rather than each producing an
     * escalation. A failure here is survivable: the resolver retries. */
    impl->refreshContainerList();

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

    if (impl->drain_thread.joinable()) impl->drain_thread.join();
    if (impl->resolver_thread.joinable()) impl->resolver_thread.join();
    if (impl->consumer_thread.joinable()) impl->consumer_thread.join();

    /* After the threads, never before: rt_close() detaches and frees everything
     * the handle owns, and the drain thread is inside rt_poll() on it. */
    rt_close(impl->handle);
    impl->handle = nullptr;

    delete impl;
}

} // namespace fim_container_events
