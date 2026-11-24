/*
 * Wazuh SysCollector
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CONTAINER_FRESHNESS_POLLER_HPP
#define _CONTAINER_FRESHNESS_POLLER_HPP

#if defined(__linux__)

#include "cgroup_container_map.hpp"
#include "container_instances_client.hpp"
#include "rt_engine.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

/// Syscollector's own eBPF engine handle: it keeps the kernel allowlist and a
/// cgroup -> container map in step with container_instances, and reports every
/// event on a file the name filter lets through as the container and process it
/// happened in.
///
/// Everything runs on the thread that calls run(), startup included, so a slow
/// BPF load or connector never delays the scan thread.
class ContainerFreshnessPoller
{
    public:
        enum class LogLevel
        {
            debug,
            info,
            warning,
            error
        };

        struct Config
        {
            std::string bpfObjectPath;
            std::string libbpfPath;
            /// The kernel's name filter: the file names to report.
            std::vector<std::string> fileNames;
            std::chrono::milliseconds listInterval {15000};
            int pollTimeoutMs {200};
            std::chrono::milliseconds resolveBudget {250};
            std::function<void(LogLevel, const std::string&)> log;
        };

        struct Callbacks
        {
            /// A file event at `path` inside the container, by process `pid` (host
            /// namespace) at `timestampNs` since boot.
            std::function<void(const std::string& containerId, const std::string& path, int pid, std::uint64_t timestampNs)>
            fileEvent;
            /// Events of this container may have been lost.
            std::function<void(const std::string& containerId)> containerChanged;
        };

        /// The engine calls this uses; tests replace them.
        struct Engine
        {
            int (*abiMajor)(void) = rt_abi_major;
            rt_handle_t (*open)(const struct rt_filter*) = rt_open;
            int (*poll)(rt_handle_t, rt_sink_fn, void*, int) = rt_poll;
            void (*close)(rt_handle_t) = rt_close;
            int (*allowCgroup)(rt_handle_t, unsigned long long) = rt_allow_cgroup;
            int (*denyCgroup)(rt_handle_t, unsigned long long) = rt_deny_cgroup;
            int (*setCgroupMode)(rt_handle_t, int) = rt_set_cgroup_mode;
            int (*drainDrops)(rt_handle_t, rt_drop_fn, void*) = rt_drain_drops;
            int (*hostCgroupV1)(rt_handle_t) = rt_host_cgroup_v1;
            int (*setCgroupV1Subsys)(rt_handle_t, const char*, unsigned int) = rt_set_cgroup_v1_subsys;
            int (*cgroupIdIsUsable)(rt_handle_t) = rt_cgroup_id_is_usable;
        };

        /// container_instances; tests replace it.
        struct Connector
        {
            std::function<wazuh::container_instances_client::ContainerDelta(std::uint64_t epoch, std::uint64_t seq)> listSince;
            std::function<wazuh::container_instances_client::LookupResult(std::uint64_t cgroupId)> resolve;
            std::function<std::optional<wz_container_key_kind_t>()> hostKeyKind;
            /// Whether the connector's socket exists: no point waiting for an
            /// answer from a host without container_instances.
            std::function<bool()> present;
        };

        /// A connector backed by a real ContainerInstancesClient at `socketPath`.
        static Connector clientConnector(const std::string& socketPath);

        ContainerFreshnessPoller(Config config,
                                 Callbacks callbacks,
                                 std::function<bool()> stopping,
                                 std::atomic<bool>& listRefreshRequested,
                                 Engine engine,
                                 Connector connector);

        /// Runs until `stopping` returns true; returns at once when the engine
        /// cannot be used.
        void run();

    private:
        bool startEngine();
        void refreshList(bool seeding);
        void syncAllowlist(const container_attribution::CgroupListDelta& delta);
        void resolvePending();
        void onEvent(const struct rt_file_event* event);
        void onDrops(unsigned long long cgroupId, unsigned int drops);
        void allContainersChanged();
        void log(LogLevel level, const std::string& message) const;

        static void engineLogTrampoline(int level, const char* message, void* user);
        static void eventTrampoline(const struct rt_file_event* event, void* user);
        static void dropTrampoline(unsigned long long cgroupId, unsigned int drops, void* user);

        Config                                    m_config;
        Callbacks                                 m_callbacks;
        std::function<bool()>                     m_stopping;
        std::atomic<bool>&                        m_listRefreshRequested;
        Engine                                    m_engine;
        Connector                                 m_connector;

        rt_handle_t                               m_handle {nullptr};
        bool                                      m_filtering {true};
        bool                                      m_perCgroupDropsUnavailable {false};
        container_attribution::CgroupContainerMap m_map;
        std::map<std::string, bool>               m_view;
        std::set<std::string>                     m_unkeyed;
        std::uint64_t                             m_cursorEpoch {0};
        std::uint64_t                             m_cursorSeq {0};
};

#endif // __linux__

#endif // _CONTAINER_FRESHNESS_POLLER_HPP
