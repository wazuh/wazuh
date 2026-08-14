/*
 * Wazuh remoted module - ControlHandler unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 31, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * ControlHandler orchestrates AgentRegistry, WazuhDBClient, TaskClient and
 * HashCache. These tests wire real instances of each and route the socket
 * clients at a FakeUdsServer that produces canned responses. That gives us
 * end-to-end coverage of the request/response shape without spinning up wdb
 * or the task manager.
 */

#include "common/vdClient.hpp"
#include "control/agentRegistry.hpp"
#include "control/controlConfig.hpp"
#include "control/controlHandler.hpp"
#include "control/controlTypes.hpp"
#include "control/hashCache.hpp"
#include "control/metrics.hpp"
#include "control/taskClient.hpp"
#include "control/wazuhDBClient.hpp"
#include "fakeUdsServer.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <json.hpp>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unistd.h>

using namespace remoted::control;
using remoted::test::FakeUdsServer;
namespace fs = std::filesystem;
using namespace std::chrono_literals;

namespace
{
    // Per-test temp roots for shared/multi group dirs (HashCache watcher needs
    // both to exist for its inotify init to succeed).
    struct TempEnv
    {
        fs::path base;
        std::string wdbPath;
        std::string taskPath;

        TempEnv()
        {
            base = fs::temp_directory_path() / ("wazuh_ctrl_handler_test_" + std::to_string(::getpid()) + "_" +
                                                std::to_string(reinterpret_cast<uintptr_t>(this)));
            fs::create_directories(base / "shared");
            fs::create_directories(base / "multi");
            wdbPath = remoted::test::makeUniqueSocketPath("ch_wdb");
            taskPath = remoted::test::makeUniqueSocketPath("ch_task");
        }
        ~TempEnv()
        {
            std::error_code ec;
            fs::remove_all(base, ec);
        }
    };

    Config makeConfig(const TempEnv& env)
    {
        Config c;
        c.sharedGroupsRoot = (env.base / "shared").string();
        c.multiGroupsRoot = (env.base / "multi").string();
        c.wdbSocketPath = env.wdbPath;
        c.taskSocketPath = env.taskPath;
        c.clusterName = "wazuh";
        c.managerVersion = "5.0.0";
        c.isWorkerNode = false;
        c.allowHigherVersions = false;
        c.keepaliveThrottleSec = 0;     // don't throttle in tests; every notify writes.
        c.groupsRefreshIntervalSec = 0; // and always refresh groups from wdb.
        c.registryEvictionTtlSec = 21600;
        c.wdbRequestConnections = 1;
        c.wdbRoundtripDeadlineMs = 2000;
        c.wdbMaxQueueSize = 100;
        c.tmConcurrency = 1;
        c.tmDeadlineMs = 2000;
        c.tmMaxQueueSize = 100;
        c.limits = nlohmann::json::object();
        c.limits["max_agents"] = 100;
        return c;
    }

    template<typename T>
    struct Waiter
    {
        std::mutex mu;
        std::condition_variable cv;
        bool done {false};
        T value {};

        void complete(T v)
        {
            std::lock_guard<std::mutex> lock(mu);
            value = std::move(v);
            done = true;
            cv.notify_all();
        }
        bool wait(std::chrono::milliseconds timeout)
        {
            std::unique_lock<std::mutex> lock(mu);
            return cv.wait_for(lock, timeout, [&] { return done; });
        }
    };

    // A wdb responder that dispatches on the first token of the command.
    class WdbRouter
    {
    public:
        void onSelectAgentGroup(std::function<std::string(const std::string&)> h)
        {
            m_selectHandler = std::move(h);
        }
        void onWrite(std::function<std::string(const std::string&)> h)
        {
            m_writeHandler = std::move(h);
        }

        std::string operator()(const std::string& req)
        {
            std::lock_guard<std::mutex> lock(m_mu);
            m_last = req;
            m_commands.push_back(req);
            if (req.find("global select-agent-group") == 0 && m_selectHandler)
            {
                return m_selectHandler(req);
            }
            if (m_writeHandler)
            {
                return m_writeHandler(req);
            }
            return "ok"; // default: acknowledge any writes.
        }

        std::string last()
        {
            std::lock_guard<std::mutex> lock(m_mu);
            return m_last;
        }
        std::vector<std::string> commands()
        {
            std::lock_guard<std::mutex> lock(m_mu);
            return m_commands;
        }

    private:
        std::mutex m_mu;
        std::string m_last;
        std::vector<std::string> m_commands;
        std::function<std::string(const std::string&)> m_selectHandler;
        std::function<std::string(const std::string&)> m_writeHandler;
    };

    // Standard "handler under test" fixture: all four collaborators plus the
    // handler itself, wired in the exact same order as production code.
    struct HandlerFixture
    {
        TempEnv env;
        Config cfg;
        ControlMetrics metrics;

        std::unique_ptr<FakeUdsServer> wdbServer;
        std::unique_ptr<FakeUdsServer> taskServer;

        std::shared_ptr<AgentRegistry> registry;
        std::shared_ptr<WazuhDBClient> wdbClient;
        std::shared_ptr<TaskClient> taskClient;
        std::shared_ptr<HashCache> hashCache;
        std::shared_ptr<remoted::common::VdClient> vdClient;
        std::unique_ptr<ControlHandler> handler;

        HandlerFixture(std::shared_ptr<WdbRouter> wdb, std::function<std::string(const std::string&)> taskResp)
            : cfg(makeConfig(env))
        {
            wdbServer = std::make_unique<FakeUdsServer>(env.wdbPath, [wdb](const std::string& r) { return (*wdb)(r); });
            taskServer = std::make_unique<FakeUdsServer>(env.taskPath, std::move(taskResp));

            registry = std::make_shared<AgentRegistry>();
            wdbClient = std::make_shared<WazuhDBClient>(
                cfg.wdbSocketPath, cfg.wdbRequestConnections, cfg.wdbRoundtripDeadlineMs, cfg.wdbMaxQueueSize, metrics);
            taskClient = std::make_shared<TaskClient>(
                cfg.taskSocketPath, cfg.tmConcurrency, cfg.tmDeadlineMs, cfg.tmMaxQueueSize, metrics);
            hashCache = std::make_shared<HashCache>(cfg);
            vdClient = std::make_shared<remoted::common::VdClient>();
            handler =
                std::make_unique<ControlHandler>(registry, wdbClient, taskClient, hashCache, vdClient, metrics, cfg);
        }
    };
} // namespace

// =============================================================================
// handleStartup
// =============================================================================

TEST(ControlHandlerTest, StartupInvalidVersionReturns400AndUpdatesStatusCode)
{
    auto wdb = std::make_shared<WdbRouter>();
    HandlerFixture h(wdb, [](const std::string&) { return "{\"status\":\"ok\",\"tasks\":[]}"; });

    Waiter<HttpResponse> w;
    StartupData data;
    data.version = "not-a-version"; // rejected by regex
    h.handler->handleStartup(1, data, [&](const HttpResponse& r) { w.complete(r); });

    ASSERT_TRUE(w.wait(3000ms));
    EXPECT_EQ(w.value.status, 400);
    EXPECT_NE(w.value.body.find("invalid_version"), std::string::npos);
    EXPECT_GE(h.metrics.startupCount.load(), 1U);

    // A status_code update should have been fired-and-forgot to wdb.
    // Give it a beat to hit the wire.
    for (int i = 0; i < 100 && h.wdbServer->requestCount() < 1; ++i)
    {
        std::this_thread::sleep_for(5ms);
    }
    ASSERT_GE(h.wdbServer->requestCount(), 1U);
    const auto commands = wdb->commands();
    bool sawStatusCode = false;
    for (const auto& c : commands)
    {
        if (c.find("global update-status-code") != std::string::npos &&
            c.find("\"status_code\":1") != std::string::npos)
        {
            sawStatusCode = true;
            // A malformed version can't be persisted verbatim: the framework's WazuhVersion
            // parser raises on anything outside MAJOR.MINOR.PATCH, which used to break the
            // entire agent listing the moment one agent sent garbage. It must be sentinelized.
            EXPECT_NE(c.find("\"version\":\"N/A\""), std::string::npos);
        }
    }
    EXPECT_TRUE(sawStatusCode);
}

TEST(ControlHandlerTest, StartupHigherVersionRejectedWhenAllowHigherFalse)
{
    auto wdb = std::make_shared<WdbRouter>();
    HandlerFixture h(wdb, [](const std::string&) { return "{\"status\":\"ok\",\"tasks\":[]}"; });

    // Agent claims v5.9.9; manager is 5.0.0 and allowHigherVersions=false.
    StartupData data;
    data.version = "5.9.9";
    Waiter<HttpResponse> w;
    h.handler->handleStartup(1, data, [&](const HttpResponse& r) { w.complete(r); });

    ASSERT_TRUE(w.wait(3000ms));
    EXPECT_EQ(w.value.status, 400);
    EXPECT_NE(w.value.body.find("invalid_version"), std::string::npos);

    // The reported version is well-formed -- just too high for this manager's policy -- so it's
    // safe to persist as-is in wdb and worth keeping visible, unlike a truly malformed version.
    for (int i = 0; i < 100 && h.wdbServer->requestCount() < 1; ++i)
    {
        std::this_thread::sleep_for(5ms);
    }
    ASSERT_GE(h.wdbServer->requestCount(), 1U);
    const auto commands = wdb->commands();
    bool sawStatusCode = false;
    for (const auto& c : commands)
    {
        if (c.find("global update-status-code") != std::string::npos &&
            c.find("\"status_code\":1") != std::string::npos)
        {
            sawStatusCode = true;
            EXPECT_NE(c.find("\"version\":\"5.9.9\""), std::string::npos);
            EXPECT_EQ(c.find("\"version\":\"N/A\""), std::string::npos);
        }
    }
    EXPECT_TRUE(sawStatusCode);
}

TEST(ControlHandlerTest, StartupHappyPathReturns200WithGroupsAndClusterEnvelope)
{
    auto wdb = std::make_shared<WdbRouter>();
    wdb->onSelectAgentGroup([](const std::string&) { return "ok [{\"group\":\"default,web\"}]"; });
    HandlerFixture h(wdb, [](const std::string&) { return "{\"status\":\"ok\",\"tasks\":[]}"; });

    StartupData data;
    data.version = "5.0.0";
    Waiter<HttpResponse> w;
    h.handler->handleStartup(42, data, [&](const HttpResponse& r) { w.complete(r); });
    ASSERT_TRUE(w.wait(3000ms));

    EXPECT_EQ(w.value.status, 200);
    auto j = nlohmann::json::parse(w.value.body);
    EXPECT_EQ(j["cluster"]["name"], "wazuh");
    ASSERT_TRUE(j["agent"]["groups"].is_array());
    ASSERT_EQ(j["agent"]["groups"].size(), 2U);
    EXPECT_EQ(j["agent"]["groups"][0], "default");
    EXPECT_EQ(j["agent"]["groups"][1], "web");
    EXPECT_TRUE(j.contains("limits"));

    // Registry should now know about agent 42.
    auto entry = h.registry->get(42);
    ASSERT_TRUE(entry);
    EXPECT_EQ(entry->groups.size(), 2U);
}

TEST(ControlHandlerTest, StartupFallsBackToDefaultGroupOnEmptyWdbCsv)
{
    auto wdb = std::make_shared<WdbRouter>();
    wdb->onSelectAgentGroup([](const std::string&) { return "ok [{\"group\":\"\"}]"; });
    HandlerFixture h(wdb, [](const std::string&) { return "{\"status\":\"ok\",\"tasks\":[]}"; });

    StartupData data;
    data.version = "5.0.0";
    Waiter<HttpResponse> w;
    h.handler->handleStartup(1, data, [&](const HttpResponse& r) { w.complete(r); });
    ASSERT_TRUE(w.wait(3000ms));

    auto j = nlohmann::json::parse(w.value.body);
    ASSERT_EQ(j["agent"]["groups"].size(), 1U);
    EXPECT_EQ(j["agent"]["groups"][0], "default");
}

TEST(ControlHandlerTest, StartupReturns500OnWdbProtocolError)
{
    auto wdb = std::make_shared<WdbRouter>();
    wdb->onSelectAgentGroup([](const std::string&) { return "err some failure"; });
    HandlerFixture h(wdb, [](const std::string&) { return "{\"status\":\"ok\",\"tasks\":[]}"; });

    StartupData data;
    data.version = "5.0.0";
    Waiter<HttpResponse> w;
    h.handler->handleStartup(1, data, [&](const HttpResponse& r) { w.complete(r); });
    ASSERT_TRUE(w.wait(3000ms));

    EXPECT_EQ(w.value.status, 500);
    EXPECT_NE(w.value.body.find("database_error"), std::string::npos);
}

// =============================================================================
// handleNotify
// =============================================================================

TEST(ControlHandlerTest, NotifyInvalidHostReturns400)
{
    auto wdb = std::make_shared<WdbRouter>();
    HandlerFixture h(wdb, [](const std::string&) { return "{\"status\":\"ok\",\"tasks\":[]}"; });

    NotifyData data;
    data.version = "5.0.0";
    HostInfo host;
    host.hostname = std::string(kMaxHostnameLength + 1, 'x'); // over the cap
    data.host = host;

    Waiter<HttpResponse> w;
    h.handler->handleNotify(1, data, [&](const HttpResponse& r) { w.complete(r); });
    ASSERT_TRUE(w.wait(3000ms));

    EXPECT_EQ(w.value.status, 400);
    EXPECT_NE(w.value.body.find("invalid_host_info"), std::string::npos);
}

TEST(ControlHandlerTest, NotifyReturnsGroupsSettingsHashAndTasks)
{
    auto wdb = std::make_shared<WdbRouter>();
    wdb->onSelectAgentGroup([](const std::string&) { return "ok {\"group\":\"default\"}"; });

    HandlerFixture h(wdb,
                     [](const std::string&) -> std::string
                     {
                         nlohmann::json j;
                         j["status"] = "ok";
                         j["tasks"] = nlohmann::json::array();
                         j["tasks"].push_back(
                             {{"task_id", "T1"}, {"task_type", "upgrade"}, {"payload", {{"v", "5.1"}}}});
                         return j.dump();
                     });

    NotifyData data;
    data.version = "5.0.0";
    HostInfo host;
    host.hostname = "web01";
    host.ip = "127.0.0.1";
    host.osName = "Ubuntu";
    host.osVersion = "24.04";
    host.osPlatform = "ubuntu";
    host.architecture = "x86_64";
    host.osType = "Linux";
    data.host = host;

    Waiter<HttpResponse> w;
    h.handler->handleNotify(7, data, [&](const HttpResponse& r) { w.complete(r); });
    ASSERT_TRUE(w.wait(3000ms));

    EXPECT_EQ(w.value.status, 200);
    auto j = nlohmann::json::parse(w.value.body);
    ASSERT_TRUE(j["agent"]["groups"].is_array());
    EXPECT_EQ(j["agent"]["groups"][0], "default");
    // No merged.mg file exists in the group dir, so config_hash must be "0".
    EXPECT_EQ(j["agent"]["config_hash"], "0");
    EXPECT_TRUE(j.contains("settings_hash"));
    EXPECT_EQ(j["settings_hash"].get<std::string>().size(), 64U); // sha256 hex

    ASSERT_TRUE(j["tasks"].is_array());
    ASSERT_EQ(j["tasks"].size(), 1U);
    EXPECT_EQ(j["tasks"][0]["task_id"], "T1");
    EXPECT_EQ(j["tasks"][0]["task_type"], "upgrade");

    EXPECT_GE(h.metrics.notifyCount.load(), 1U);
}

TEST(ControlHandlerTest, NotifyReturnsRealConfigHashWhenMergedMgExists)
{
    auto wdb = std::make_shared<WdbRouter>();
    wdb->onSelectAgentGroup([](const std::string&) { return "ok {\"group\":\"default\"}"; });
    HandlerFixture h(wdb, [](const std::string&) { return "{\"status\":\"ok\",\"tasks\":[]}"; });

    // Materialise the merged.mg file for group "default" so getConfigHash
    // returns a real hash rather than the "0" fallback.
    const auto mergedMg = h.env.base / "shared" / "default" / "merged.mg";
    fs::create_directories(mergedMg.parent_path());
    {
        std::ofstream f(mergedMg, std::ios::binary);
        f << "hello";
    }

    NotifyData data;
    data.version = "5.0.0";
    Waiter<HttpResponse> w;
    h.handler->handleNotify(1, data, [&](const HttpResponse& r) { w.complete(r); });
    ASSERT_TRUE(w.wait(3000ms));
    EXPECT_EQ(w.value.status, 200);

    auto j = nlohmann::json::parse(w.value.body);
    // sha256("hello") -- verifies the hash cache picks up the file we wrote.
    EXPECT_EQ(j["agent"]["config_hash"], "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
}

// =============================================================================
// handleShutdown
// =============================================================================

TEST(ControlHandlerTest, ShutdownReturns200WithEmptyBodyImmediately)
{
    auto wdb = std::make_shared<WdbRouter>();
    HandlerFixture h(wdb, [](const std::string&) { return "{\"status\":\"ok\",\"tasks\":[]}"; });

    Waiter<HttpResponse> w;
    ShutdownData data;
    h.handler->handleShutdown(1, data, [&](const HttpResponse& r) { w.complete(r); });
    // Fire-and-forget: response must come back essentially instantly.
    ASSERT_TRUE(w.wait(500ms));
    EXPECT_EQ(w.value.status, 200);
    EXPECT_EQ(w.value.body, "{}");
    EXPECT_GE(h.metrics.shutdownCount.load(), 1U);

    // Give the async wdb write a beat to hit the wire and confirm the command.
    for (int i = 0; i < 200 && h.wdbServer->requestCount() < 1; ++i)
    {
        std::this_thread::sleep_for(5ms);
    }
    ASSERT_GE(h.wdbServer->requestCount(), 1U);
    bool sawUpdateConnectionStatus = false;
    for (const auto& c : wdb->commands())
    {
        if (c.find("global update-connection-status") != std::string::npos &&
            c.find("\"connection_status\":\"disconnected\"") != std::string::npos)
        {
            sawUpdateConnectionStatus = true;
        }
    }
    EXPECT_TRUE(sawUpdateConnectionStatus);
}

TEST(ControlHandlerTest, ShutdownTouchesRegistryLastActivity)
{
    auto wdb = std::make_shared<WdbRouter>();
    HandlerFixture h(wdb, [](const std::string&) { return "{\"status\":\"ok\",\"tasks\":[]}"; });

    // Before: no entry.
    EXPECT_FALSE(h.registry->get(99));

    Waiter<HttpResponse> w;
    ShutdownData data;
    h.handler->handleShutdown(99, data, [&](const HttpResponse& r) { w.complete(r); });
    ASSERT_TRUE(w.wait(500ms));

    // After: an entry with a lastActivitySec.
    auto e = h.registry->get(99);
    ASSERT_TRUE(e);
    EXPECT_GT(e->lastActivitySec, 0U);
}
