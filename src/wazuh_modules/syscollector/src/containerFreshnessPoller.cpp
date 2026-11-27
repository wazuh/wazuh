/*
 * Wazuh SysCollector
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#if defined(__linux__)

#include "containerFreshnessPoller.hpp"

#include "cgroup_host_mode.h"
#include "container_list_refresh.hpp"
#include "container_resolve_reply.hpp"

#include <sys/stat.h>

#include <cerrno>
#include <cstring>
#include <memory>
#include <thread>
#include <utility>

namespace
{
    constexpr int MAX_CONSECUTIVE_POLL_ERRORS = 10;

    // container_instances binds its socket before its first enumeration, so a
    // first question can go unanswered by a connector that is merely starting.
    constexpr int KEY_KIND_ATTEMPTS = 10;
    constexpr std::chrono::milliseconds KEY_KIND_DELAY(500);
} // namespace

ContainerFreshnessPoller::Connector ContainerFreshnessPoller::clientConnector(const std::string& socketPath)
{
    using wazuh::container_instances_client::ContainerInstancesClient;

    const auto client = std::make_shared<ContainerInstancesClient>(socketPath);
    Connector connector;
    connector.listSince = [client](std::uint64_t epoch, std::uint64_t seq)
    {
        return client->listContainersSince(epoch, seq);
    };
    connector.resolve = [client](std::uint64_t cgroupId)
    {
        return client->resolveByCgroupId(cgroupId);
    };
    connector.hostKeyKind = [client]()
    {
        return client->hostKeyKind();
    };
    connector.present = [socketPath]()
    {
        struct stat info {};
        return ::stat(socketPath.c_str(), &info) == 0;
    };
    return connector;
}

ContainerFreshnessPoller::ContainerFreshnessPoller(Config config,
                                                   Callbacks callbacks,
                                                   std::function<bool()> stopping,
                                                   std::atomic<bool>& listRefreshRequested,
                                                   Engine engine,
                                                   Connector connector)
    : m_config(std::move(config))
    , m_callbacks(std::move(callbacks))
    , m_stopping(std::move(stopping))
    , m_listRefreshRequested(listRefreshRequested)
    , m_engine(engine)
    , m_connector(std::move(connector))
{
}

void ContainerFreshnessPoller::log(LogLevel level, const std::string& message) const
{
    if (m_config.log)
    {
        m_config.log(level, "Container inventory: " + message);
    }
}

void ContainerFreshnessPoller::engineLogTrampoline(int, const char* message, void* user)
{
    if (message != nullptr && user != nullptr)
    {
        // Debug only: on a host the engine cannot serve, its reasons are the
        // details behind the one INFO line startEngine() writes.
        static_cast<ContainerFreshnessPoller*>(user)->log(LogLevel::debug, std::string {"eBPF engine: "} + message);
    }
}

bool ContainerFreshnessPoller::startEngine()
{
    const auto unavailable = [this](const std::string & reason)
    {
        if (m_handle != nullptr)
        {
            m_engine.close(m_handle);
            m_handle = nullptr;
        }

        log(LogLevel::info,
            "eBPF change detection is not available (" + reason +
            "); container changes are picked up by the periodic pass.");
        return false;
    };

    if (m_engine.abiMajor() != RT_ABI_MAJOR)
    {
        return unavailable("the eBPF engine has a different event ABI");
    }

    std::vector<const char*> fileNames;

    for (const auto& name : m_config.fileNames)
    {
        fileNames.push_back(name.c_str());
    }

    fileNames.push_back(nullptr);

    struct rt_filter filter;
    std::memset(&filter, 0, sizeof(filter));
    filter.type_mask = RT_FILE_ALL_BITS;
    filter.bpf_obj_path = m_config.bpfObjectPath.empty() ? nullptr : m_config.bpfObjectPath.c_str();
    filter.libbpf_path = m_config.libbpfPath.empty() ? nullptr : m_config.libbpfPath.c_str();
    filter.log = engineLogTrampoline;
    filter.log_user = this;
    filter.cgroup_mode = RT_CGROUP_MODE_ALLOWLIST;
    filter.skip_mask = RT_SKIP_PROC_CONTEXT;
    filter.name_filter = m_config.fileNames.empty() ? nullptr : fileNames.data();

    m_handle = m_engine.open(&filter);

    if (m_handle == nullptr)
    {
        return unavailable("the eBPF engine could not be opened");
    }

    // A host without a unified hierarchy keys containers on a v1 controller's
    // cgroups, which the program reads only once it is told which one.
    if (m_engine.hostCgroupV1(m_handle) != 0)
    {
        const char* controller = nullptr;
        const int subsys = wz_cgroup_v1_select_subsys(&controller);

        if (subsys < 0 || controller == nullptr ||
                m_engine.setCgroupV1Subsys(m_handle, controller, static_cast<unsigned int>(subsys)) != 0)
        {
            return unavailable("no cgroup v1 controller can identify a container");
        }

        log(LogLevel::debug, std::string {"keying containers on the cgroup v1 '"} + controller + "' controller.");
    }

    if (m_engine.cgroupIdIsUsable(m_handle) == 0)
    {
        return unavailable("an event's cgroup id does not identify a container on this host");
    }

    // The allowlist holds cgroup ids; a connector keying containers by
    // anything else would never match one, and nothing would say why.
    std::optional<wz_container_key_kind_t> kind;

    for (int attempt = 1; attempt <= KEY_KIND_ATTEMPTS && !m_stopping(); ++attempt)
    {
        kind = m_connector.hostKeyKind();

        if (kind || !m_connector.present())
        {
            break;
        }

        std::this_thread::sleep_for(KEY_KIND_DELAY);
    }

    if (kind && *kind != WZ_CONTAINER_KEY_CGROUP)
    {
        return unavailable(std::string {"container_instances keys containers by '"} + wz_container_key_kind_name(*kind) +
                           "', not by cgroup id");
    }

    if (!kind)
    {
        log(LogLevel::debug, "container_instances did not say how it keys containers; assuming cgroup ids.");
    }

    log(LogLevel::debug, "eBPF change detection started.");
    return true;
}

void ContainerFreshnessPoller::run()
{
    if (m_stopping() || !startEngine())
    {
        return;
    }

    auto nextList = std::chrono::steady_clock::now();
    bool seeding = true;
    int pollErrors = 0;

    while (!m_stopping())
    {
        // Nothing may leave this thread: an exception reaching std::thread
        // would terminate modulesd, every module with it.
        try
        {
            const auto now = std::chrono::steady_clock::now();

            if (seeding || m_listRefreshRequested.exchange(false) || now >= nextList)
            {
                refreshList(seeding);
                seeding = false;
                nextList = now + m_config.listInterval;
            }

            const int polled = m_engine.poll(m_handle, eventTrampoline, this, m_config.pollTimeoutMs);

            if (polled < 0 && polled != -EINTR)
            {
                if (++pollErrors >= MAX_CONSECUTIVE_POLL_ERRORS)
                {
                    log(LogLevel::error, "the eBPF engine keeps failing to deliver events; change detection stopped.");
                    break;
                }
            }
            else
            {
                pollErrors = 0;
            }

            if (!m_perCgroupDropsUnavailable && m_engine.drainDrops(m_handle, dropTrampoline, this) < 0)
            {
                // From here on loss is only known in-band, and to no cgroup.
                m_perCgroupDropsUnavailable = true;
                log(LogLevel::debug, "lost events can no longer be attributed to a container.");
            }

            if (m_map.takeUnknownOverflow())
            {
                allContainersChanged();
            }

            resolvePending();
        }
        catch (const std::exception& e)
        {
            log(LogLevel::error, std::string {"change detection error: "} + e.what());
        }
    }

    m_engine.close(m_handle);
    m_handle = nullptr;
}

void ContainerFreshnessPoller::refreshList(bool seeding)
{
    const auto delta = m_connector.listSince(m_cursorEpoch, m_cursorSeq);
    auto plan = container_attribution::planListRefresh(delta, m_view, m_map.mappedContainerIds(), m_unkeyed);

    // An unanswered query is not an empty node: keep the map, the view and the
    // cursor exactly as they were.
    if (!plan.act)
    {
        return;
    }

    const auto applied = plan.installWholeList ? m_map.install(plan.containers) : m_map.applyDelta(plan.events);
    syncAllowlist(applied);

    std::set<std::string> changed {applied.escalate.begin(), applied.escalate.end()};

    // A container's lock opens before its cgroup was allowed never reached here.
    // Not on the seed: containers running at start are read by the start-up
    // pass, or at the first interval. Only its primary cgroup: an init system
    // inside a container adds one per unit it starts, and a timer would
    // otherwise re-check the container each time it fires.
    if (m_filtering && !seeding)
    {
        std::set<std::uint64_t> primaries;

        for (const auto& container : delta.containers)
        {
            primaries.insert(container.cgroupId);
        }

        for (const auto& event : delta.events)
        {
            primaries.insert(event.cgroupId);
        }

        for (const auto& entry : applied.added)
        {
            if (primaries.count(entry.first) != 0)
            {
                changed.insert(entry.second);
            }
        }
    }

    for (const auto& containerId : changed)
    {
        m_callbacks.containerChanged(containerId);
    }

    m_view = std::move(plan.admissionView);

    if (plan.enumerated)
    {
        m_unkeyed = std::move(plan.unkeyed);
    }

    m_cursorEpoch = delta.epoch;
    m_cursorSeq = delta.seq;
}

void ContainerFreshnessPoller::syncAllowlist(const container_attribution::CgroupListDelta& delta)
{
    if (!m_filtering)
    {
        return;
    }

    for (const auto& entry : delta.added)
    {
        if (m_engine.allowCgroup(m_handle, entry.first) != 0)
        {
            // Unfiltered costs CPU; a container left out costs its changes.
            if (m_engine.setCgroupMode(m_handle, RT_CGROUP_MODE_ALL) == 0)
            {
                m_filtering = false;
                log(LogLevel::warning,
                    "the kernel event filter is full, so every file event on the host is delivered again. "
                    "Change detection is unaffected; this costs CPU.");
            }
            else
            {
                log(LogLevel::error,
                    "cgroup " + std::to_string(entry.first) +
                    " could not be added to the kernel event filter; that container's changes are picked up "
                    "by the periodic pass.");
            }

            return;
        }
    }

    for (const auto cgroupId : delta.removed)
    {
        // Cgroup ids are inodes and are reused.
        m_engine.denyCgroup(m_handle, cgroupId);
    }
}

void ContainerFreshnessPoller::resolvePending()
{
    using wazuh::container_instances_client::LookupStatus;

    const auto deadline = std::chrono::steady_clock::now() + m_config.resolveBudget;

    for (const auto cgroupId : m_map.takeUnresolved())
    {
        if (m_stopping() || std::chrono::steady_clock::now() >= deadline)
        {
            m_map.rearm(cgroupId);
            continue;
        }

        const auto result = m_connector.resolve(cgroupId);

        if (result.status == LookupStatus::resolved)
        {
            const auto containerId = container_attribution::ContainerIdFromResolveReply(result.json);

            if (containerId.empty())
            {
                m_map.rearm(cgroupId);
                continue;
            }

            // True: this cgroup produced events before anyone knew whose they were.
            if (m_map.noteContainer(cgroupId, containerId))
            {
                m_callbacks.containerChanged(containerId);
            }

            if (m_filtering)
            {
                m_engine.allowCgroup(m_handle, cgroupId);
            }
        }
        else if (result.status == LookupStatus::notContainer)
        {
            m_map.noteNotContainer(cgroupId);
        }
        else
        {
            m_map.rearm(cgroupId);
        }
    }
}

void ContainerFreshnessPoller::onEvent(const struct rt_file_event* event)
{
    if (m_perCgroupDropsUnavailable && (event->flags & RT_F_DROPS_BEFORE) != 0)
    {
        allContainersChanged();
    }

    const std::string path {event->filename, ::strnlen(event->filename, sizeof(event->filename))};

    if (path.empty())
    {
        return;
    }

    const auto resolution = m_map.classify(event->cgroup_id);

    if (resolution.klass == container_attribution::CgroupClass::container)
    {
        m_callbacks.fileEvent(resolution.container_id, path, static_cast<int>(event->pid), event->timestamp_ns);
    }
}

void ContainerFreshnessPoller::onDrops(unsigned long long cgroupId, unsigned int drops)
{
    if (drops == 0)
    {
        return;
    }

    // An unknown cgroup is queued by classify(); resolving it reports the
    // container then, through noteContainer().
    const auto resolution = m_map.classify(cgroupId);

    if (resolution.klass == container_attribution::CgroupClass::container)
    {
        m_callbacks.containerChanged(resolution.container_id);
    }
}

void ContainerFreshnessPoller::allContainersChanged()
{
    for (const auto& containerId : m_map.mappedContainerIds())
    {
        m_callbacks.containerChanged(containerId);
    }
}

// The trampolines are called from the engine's C code, which an exception must
// never unwind through.
void ContainerFreshnessPoller::eventTrampoline(const struct rt_file_event* event, void* user)
{
    if (event == nullptr || user == nullptr)
    {
        return;
    }

    auto* self = static_cast<ContainerFreshnessPoller*>(user);

    try
    {
        self->onEvent(event);
    }
    catch (const std::exception& e)
    {
        self->log(LogLevel::error, std::string {"change detection error: "} + e.what());
    }
}

void ContainerFreshnessPoller::dropTrampoline(unsigned long long cgroupId, unsigned int drops, void* user)
{
    if (user == nullptr)
    {
        return;
    }

    auto* self = static_cast<ContainerFreshnessPoller*>(user);

    try
    {
        self->onDrops(cgroupId, drops);
    }
    catch (const std::exception& e)
    {
        self->log(LogLevel::error, std::string {"change detection error: "} + e.what());
    }
}

#endif // __linux__
