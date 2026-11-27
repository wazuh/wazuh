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

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <deque>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

using wazuh::container_instances_client::ContainerDelta;
using wazuh::container_instances_client::ContainerRef;
using wazuh::container_instances_client::LookupResult;
using wazuh::container_instances_client::LookupStatus;

namespace
{
    struct FakeEvent
    {
        unsigned long long cgroupId;
        std::string path;
        unsigned short flags;
        unsigned int pid {0};
        unsigned long long timestampNs {0};
    };

    // The engine's state. Plain functions read it, because the engine seam is
    // a table of function pointers.
    struct FakeEngineState
    {
        int abi {RT_ABI_MAJOR};
        bool openFails {false};
        bool v1 {false};
        int v1Result {0};
        bool allowFails {false};
        bool dropsUnavailable {false};

        int opens {0};
        int closes {0};
        int polls {0};
        int maxPolls {3};
        std::vector<std::string> openedNames;
        std::vector<std::string> openedParents;
        int openedMode {-1};
        unsigned int openedSkip {0};
        std::vector<unsigned long long> allowed;
        std::vector<unsigned long long> denied;
        std::vector<int> modes;

        // What each poll delivers, one entry per poll.
        std::deque<std::vector<FakeEvent>> events;
        std::deque<std::vector<std::pair<unsigned long long, unsigned int>>> drops;

        // Raises the poller's list-refresh flag during this poll, as a
        // lifecycle notification would.
        int refreshAtPoll {-1};
        std::atomic<bool>* refreshFlag {nullptr};
    };

    FakeEngineState g_engine;

    std::vector<std::string> ListOf(const char* const* list)
    {
        std::vector<std::string> out;

        for (; list != nullptr && *list != nullptr; ++list)
        {
            out.emplace_back(*list);
        }

        return out;
    }

    rt_handle_t FakeOpen(const struct rt_filter* filter)
    {
        ++g_engine.opens;
        g_engine.openedNames = ListOf(filter->name_filter);
        g_engine.openedParents = ListOf(filter->parent_dir_filter);
        g_engine.openedMode = filter->cgroup_mode;
        g_engine.openedSkip = filter->skip_mask;
        return g_engine.openFails ? nullptr : reinterpret_cast<rt_handle_t>(1);
    }

    int FakePoll(rt_handle_t, rt_sink_fn sink, void* user, int)
    {
        ++g_engine.polls;

        if (g_engine.polls == g_engine.refreshAtPoll && g_engine.refreshFlag != nullptr)
        {
            g_engine.refreshFlag->store(true);
        }

        if (g_engine.events.empty())
        {
            return 0;
        }

        const auto batch = g_engine.events.front();
        g_engine.events.pop_front();
        auto event = std::make_unique<struct rt_file_event>();

        for (const auto& fake : batch)
        {
            std::memset(event.get(), 0, sizeof(*event));
            event->cgroup_id = fake.cgroupId;
            event->flags = fake.flags;
            event->pid = fake.pid;
            event->timestamp_ns = fake.timestampNs;
            std::strncpy(event->filename, fake.path.c_str(), sizeof(event->filename) - 1);
            sink(event.get(), user);
        }

        return static_cast<int>(batch.size());
    }

    void FakeClose(rt_handle_t)
    {
        ++g_engine.closes;
    }

    int FakeAllow(rt_handle_t, unsigned long long cgroupId)
    {
        if (g_engine.allowFails)
        {
            return -1;
        }

        g_engine.allowed.push_back(cgroupId);
        return 0;
    }

    int FakeDeny(rt_handle_t, unsigned long long cgroupId)
    {
        g_engine.denied.push_back(cgroupId);
        return 0;
    }

    int FakeSetMode(rt_handle_t, int mode)
    {
        g_engine.modes.push_back(mode);
        return 0;
    }

    int FakeDrainDrops(rt_handle_t, rt_drop_fn cb, void* user)
    {
        if (g_engine.dropsUnavailable)
        {
            return -1;
        }

        if (g_engine.drops.empty())
        {
            return 0;
        }

        const auto batch = g_engine.drops.front();
        g_engine.drops.pop_front();

        for (const auto& [cgroupId, count] : batch)
        {
            cb(cgroupId, count, user);
        }

        return static_cast<int>(batch.size());
    }

    int FakeAbi()
    {
        return g_engine.abi;
    }

    int FakeHostV1(rt_handle_t)
    {
        return g_engine.v1 ? 1 : 0;
    }

    int FakeSetV1(rt_handle_t, const char*, unsigned int)
    {
        return g_engine.v1Result;
    }

    int FakeUsable(rt_handle_t)
    {
        return 1;
    }

    ContainerFreshnessPoller::Engine FakeEngine()
    {
        ContainerFreshnessPoller::Engine engine;
        engine.abiMajor = FakeAbi;
        engine.open = FakeOpen;
        engine.poll = FakePoll;
        engine.close = FakeClose;
        engine.allowCgroup = FakeAllow;
        engine.denyCgroup = FakeDeny;
        engine.setCgroupMode = FakeSetMode;
        engine.drainDrops = FakeDrainDrops;
        engine.hostCgroupV1 = FakeHostV1;
        engine.setCgroupV1Subsys = FakeSetV1;
        engine.cgroupIdIsUsable = FakeUsable;
        return engine;
    }

    ContainerRef Container(const std::string& id, std::uint64_t cgroupId, std::vector<std::uint64_t> extra = {})
    {
        ContainerRef ref;
        ref.containerId = id;
        ref.cgroupId = cgroupId;
        ref.extraCgroupIds = std::move(extra);
        ref.synced = true;
        return ref;
    }

    // A whole-node list that covers every container.
    ContainerDelta FullList(std::vector<ContainerRef> containers)
    {
        ContainerDelta delta;
        delta.available = true;
        delta.deltaSupported = false;
        delta.complete = true;
        delta.containers = std::move(containers);
        return delta;
    }

    class ContainerFreshnessPollerTest : public ::testing::Test
    {
        protected:
            void SetUp() override
            {
                g_engine = {};
            }

            // Runs the poller until the fake engine has been polled maxPolls
            // times; each list request takes the next reply.
            void run()
            {
                ContainerFreshnessPoller::Config config;
                config.fileNames = {"lock", ".rpm.lock"};
                config.listInterval = std::chrono::hours {1};
                config.resolveBudget = std::chrono::seconds {5};

                ContainerFreshnessPoller::Callbacks callbacks;
                callbacks.fileEvent = [this](const std::string & id, const std::string & path, int pid,
                                             std::uint64_t timestampNs)
                {
                    if (throwOnFileEvent)
                    {
                        throw std::runtime_error("callback failure");
                    }

                    fileEvents.emplace_back(id, path);
                    fileEventProcesses.emplace_back(pid, timestampNs);
                };
                callbacks.containerChanged = [this](const std::string & id)
                {
                    changed.push_back(id);
                };

                ContainerFreshnessPoller::Connector connector;
                connector.listSince = [this](std::uint64_t, std::uint64_t)
                {
                    ++listRequests;

                    if (lists.empty())
                    {
                        return ContainerDelta {};
                    }

                    auto reply = lists.front();
                    lists.pop_front();
                    return reply;
                };
                connector.resolve = [this](std::uint64_t cgroupId)
                {
                    LookupResult result;
                    const auto found = resolutions.find(cgroupId);

                    if (found != resolutions.end())
                    {
                        result.status = LookupStatus::resolved;
                        result.json = R"({"status":"resolved","data":{"container_id":")" + found->second + R"("}})";
                    }

                    return result;
                };
                connector.hostKeyKind = [this]()
                {
                    return keyKind;
                };
                connector.present = []()
                {
                    return false;
                };

                ContainerFreshnessPoller poller {config,
                                                 callbacks,
                                                 []()
                {
                    return g_engine.polls >= g_engine.maxPolls;
                },
                refreshRequested,
                FakeEngine(),
                connector};

                refreshRequested = false;
                g_engine.refreshFlag = &refreshRequested;
                poller.run();
            }

            std::deque<ContainerDelta> lists;
            std::map<std::uint64_t, std::string> resolutions;
            std::optional<wz_container_key_kind_t> keyKind {WZ_CONTAINER_KEY_CGROUP};
            std::atomic<bool> refreshRequested {false};
            bool throwOnFileEvent {false};

            int listRequests {0};
            std::vector<std::pair<std::string, std::string>> fileEvents;
            std::vector<std::pair<int, std::uint64_t>> fileEventProcesses;
            std::vector<std::string> changed;
    };
} // namespace

TEST_F(ContainerFreshnessPollerTest, ItOpensAnAllowlistedHandleWithTheNameListsAndNoProcessContext)
{
    g_engine.maxPolls = 1;
    run();

    EXPECT_EQ(g_engine.opens, 1);
    EXPECT_EQ(g_engine.openedMode, RT_CGROUP_MODE_ALLOWLIST);
    EXPECT_EQ(g_engine.openedSkip, RT_SKIP_PROC_CONTEXT);
    EXPECT_EQ(g_engine.openedNames, (std::vector<std::string> {"lock", ".rpm.lock"}));
    EXPECT_TRUE(g_engine.openedParents.empty());
    EXPECT_EQ(g_engine.closes, 1);
}

TEST_F(ContainerFreshnessPollerTest, AnEngineThatCannotServeEndsItWithoutReportingAnything)
{
    g_engine.openFails = true;
    run();
    EXPECT_EQ(g_engine.polls, 0);
    EXPECT_EQ(listRequests, 0);

    g_engine = {};
    g_engine.abi = RT_ABI_MAJOR + 1;
    run();
    EXPECT_EQ(g_engine.opens, 0) << "a different event ABI is refused before loading anything";

    g_engine = {};
    g_engine.v1 = true;
    g_engine.v1Result = -1;
    run();
    EXPECT_EQ(g_engine.polls, 0);
    EXPECT_EQ(g_engine.closes, 1);

    g_engine = {};
    keyKind = WZ_CONTAINER_KEY_MNT_NS;
    run();
    EXPECT_EQ(g_engine.polls, 0) << "an allowlist of cgroup ids would never match a connector keying by mount namespace";
    EXPECT_EQ(g_engine.closes, 1);
    EXPECT_TRUE(fileEvents.empty());
    EXPECT_TRUE(changed.empty());
}

TEST_F(ContainerFreshnessPollerTest, TheListKeepsTheAllowlistAndReportsContainersAllowedLate)
{
    lists.push_back(FullList({Container("a", 11, {12})}));
    lists.push_back(FullList({Container("b", 21)}));
    g_engine.refreshAtPoll = 1;
    g_engine.maxPolls = 3;
    run();

    EXPECT_EQ(listRequests, 2) << "the seed, then the refresh a lifecycle notification asked for";
    EXPECT_EQ(g_engine.allowed, (std::vector<unsigned long long> {11, 12, 21})) << "every cgroup of a, then b";
    EXPECT_EQ(std::set<unsigned long long>(g_engine.denied.begin(), g_engine.denied.end()),
              (std::set<unsigned long long> {11, 12}))
            << "cgroup ids are inodes and are reused";
    EXPECT_EQ(changed, (std::vector<std::string> {"b"}))
            << "b's writes before its cgroup was allowed are lost; a was walked by the startup pass";
}

TEST_F(ContainerFreshnessPollerTest, OnlyANewPrimaryCgroupReChecksAContainer)
{
    // A unit starting inside the container adds an extra cgroup: allowed, but
    // nothing to re-check. A restart gives it a new primary cgroup: re-checked.
    lists.push_back(FullList({Container("a", 11, {12})}));
    lists.push_back(FullList({Container("a", 11, {12, 13})}));
    lists.push_back(FullList({Container("a", 14, {12, 13})}));
    g_engine.refreshAtPoll = 1;
    g_engine.maxPolls = 2;
    run();

    EXPECT_EQ(g_engine.allowed, (std::vector<unsigned long long> {11, 12, 13}));
    EXPECT_TRUE(changed.empty()) << "an extra cgroup is not a reason to walk the container";

    g_engine = {};
    lists.clear();
    lists.push_back(FullList({Container("a", 11, {12})}));
    lists.push_back(FullList({Container("a", 14, {12})}));
    g_engine.refreshAtPoll = 1;
    g_engine.maxPolls = 2;
    run();

    EXPECT_EQ(changed, (std::vector<std::string> {"a"}));
}

TEST_F(ContainerFreshnessPollerTest, EventsAreAttributedAndAnUnknownCgroupIsResolved)
{
    lists.push_back(FullList({Container("a", 11)}));
    g_engine.events.push_back({{11, "/var/lib/dpkg/lock", 0, 4242, 77}, {99, "/var/lib/dpkg/lock", 0}});
    g_engine.events.push_back({{99, "/var/lib/dpkg/lock", 0, 4343, 88}});
    resolutions[99] = "z";
    g_engine.maxPolls = 2;
    run();

    const std::vector<std::pair<std::string, std::string>> expected {{"a", "/var/lib/dpkg/lock"}, {"z", "/var/lib/dpkg/lock"}};
    EXPECT_EQ(fileEvents, expected);
    EXPECT_EQ(fileEventProcesses, (std::vector<std::pair<int, std::uint64_t>> {{4242, 77}, {4343, 88}}))
            << "each event's process and time reach the callback";
    EXPECT_EQ(changed, (std::vector<std::string> {"z"})) << "z wrote before anyone knew whose cgroup 99 was";
    EXPECT_NE(std::find(g_engine.allowed.begin(), g_engine.allowed.end(), 99ull), g_engine.allowed.end());
}

TEST_F(ContainerFreshnessPollerTest, LostEventsMarkTheirContainerOrEveryContainer)
{
    lists.push_back(FullList({Container("a", 11), Container("b", 21)}));
    g_engine.drops.push_back({{11, 3}});
    g_engine.maxPolls = 1;
    run();
    EXPECT_EQ(changed, (std::vector<std::string> {"a"}));

    g_engine = {};
    changed.clear();
    lists.push_back(FullList({Container("a", 11), Container("b", 21)}));
    g_engine.dropsUnavailable = true;
    g_engine.events.push_back({});
    g_engine.events.push_back({{11, "/var/lib/dpkg/lock", RT_F_DROPS_BEFORE}});
    g_engine.maxPolls = 2;
    run();
    EXPECT_EQ(std::set<std::string>(changed.begin(), changed.end()), (std::set<std::string> {"a", "b"}))
            << "loss no cgroup can be charged with could have been anyone's";
}

TEST_F(ContainerFreshnessPollerTest, AnUnansweredListChangesNothing)
{
    lists.push_back(FullList({Container("a", 11)}));
    lists.push_back(ContainerDelta {}); // not available
    g_engine.events.push_back({});
    g_engine.events.push_back({{11, "/var/lib/dpkg/lock", 0}});
    g_engine.refreshAtPoll = 1;
    g_engine.maxPolls = 2;
    run();
    ASSERT_EQ(listRequests, 2);

    EXPECT_TRUE(g_engine.denied.empty()) << "an unanswered query is not an empty node";
    EXPECT_EQ(fileEvents, (std::vector<std::pair<std::string, std::string>> {{"a", "/var/lib/dpkg/lock"}}));
}

TEST_F(ContainerFreshnessPollerTest, ACallbackThatThrowsDoesNotEndTheLoop)
{
    lists.push_back(FullList({Container("a", 11)}));
    g_engine.events.push_back({{11, "/var/lib/dpkg/lock", 0}});
    g_engine.maxPolls = 3;
    throwOnFileEvent = true;
    run();

    EXPECT_EQ(g_engine.polls, 3);
    EXPECT_EQ(g_engine.closes, 1);
}

TEST_F(ContainerFreshnessPollerTest, AFullAllowlistFallsBackToEveryEvent)
{
    lists.push_back(FullList({Container("a", 11)}));
    g_engine.allowFails = true;
    g_engine.maxPolls = 1;
    run();

    EXPECT_EQ(g_engine.modes, (std::vector<int> {RT_CGROUP_MODE_ALL}));
}

#endif // __linux__
