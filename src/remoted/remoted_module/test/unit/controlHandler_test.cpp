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

#include <wazuh_metrics/manager.hpp>

#include <gtest/gtest.h>

#include <algorithm>
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

    // The host block three tests build identically.
    NotifyData notifyWithHost()
    {
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
        return data;
    }

    // Standard "handler under test" fixture: all four collaborators plus the
    // handler itself, wired in the exact same order as production code.
    struct HandlerFixture
    {
        TempEnv env;
        Config cfg;
        // A real manager-backed set (not the null object): these tests assert the counts.
        wazuh::metrics::Manager metricsManager;
        ControlMetrics metrics {makeControlMetrics(metricsManager)};

        std::unique_ptr<FakeUdsServer> wdbServer;
        std::unique_ptr<FakeUdsServer> taskServer;

        std::shared_ptr<AgentRegistry> registry;
        std::shared_ptr<WazuhDBClient> wdbClient;
        std::shared_ptr<TaskClient> taskClient;
        std::shared_ptr<HashCache> hashCache;
        std::shared_ptr<remoted::common::VdClient> vdClient;
        std::unique_ptr<ControlHandler> handler;

        HandlerFixture(std::shared_ptr<WdbRouter> wdb,
                       std::function<std::string(const std::string&)> taskResp,
                       std::function<void(Config&)> tweakCfg = {})
            : cfg(makeConfig(env))
        {
            if (tweakCfg)
            {
                tweakCfg(cfg);
            }
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

TEST(ControlHandlerTest, StartupMalformedVersionReturns400AndUpdatesStatusCode)
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
    EXPECT_GE(h.metrics.startup->get(), 1U);

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

TEST(ControlHandlerTest, StartupHigherVersionReturns409WhenAllowHigherFalse)
{
    auto wdb = std::make_shared<WdbRouter>();
    HandlerFixture h(wdb, [](const std::string&) { return "{\"status\":\"ok\",\"tasks\":[]}"; });

    // Agent claims v5.9.9; manager is 5.0.0 and allowHigherVersions=false.
    StartupData data;
    data.version = "5.9.9";
    Waiter<HttpResponse> w;
    h.handler->handleStartup(1, data, [&](const HttpResponse& r) { w.complete(r); });

    ASSERT_TRUE(w.wait(3000ms));
    // 409, NOT 400: the version is well-formed, so this is a policy conflict the agent can recover
    // from without changing anything it sends. The agent's client maps 409 to VersionRejected, which
    // is what drives its REJECTED state and the slow Startup retry; a 400 here would classify as
    // Permanent and leave that state unreachable. Malformed versions keep 400 -- see the test above.
    EXPECT_EQ(w.value.status, 409);
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

TEST(ControlHandlerTest, StartupPersistsAcceptedVersionWithOkStatusCode)
{
    auto wdb = std::make_shared<WdbRouter>();
    wdb->onSelectAgentGroup([](const std::string&) { return "ok [{\"group\":\"default\"}]"; });
    HandlerFixture h(wdb, [](const std::string&) { return "{\"status\":\"ok\",\"tasks\":[]}"; });

    StartupData data;
    data.version = "5.0.0";
    Waiter<HttpResponse> w;
    h.handler->handleStartup(7, data, [&](const HttpResponse& r) { w.complete(r); });
    ASSERT_TRUE(w.wait(3000ms));
    EXPECT_EQ(w.value.status, 200);

    // Two commands expected: select-agent-group plus a single fire-and-forget
    // write persisting the version, the pending status and the keepalive.
    for (int i = 0; i < 200 && wdb->commands().size() < 2; ++i)
    {
        std::this_thread::sleep_for(5ms);
    }
    bool sawVersionPersist = false;
    for (const auto& c : wdb->commands())
    {
        // The accepted version must land in wdb at startup: the notify path only
        // persists it together with host metadata, which the agent may take a
        // while to report, and GET /agents must not show a versionless agent.
        if (c.find("global update-status-code") != std::string::npos &&
            c.find("\"status_code\":0") != std::string::npos && c.find("\"version\":\"5.0.0\"") != std::string::npos &&
            c.find("\"connection_status\":\"pending\"") != std::string::npos)
        {
            sawVersionPersist = true;
        }
        EXPECT_EQ(c.find("global update-keepalive"), std::string::npos)
            << "startup must issue a single wdb write, got: " << c;
    }
    EXPECT_TRUE(sawVersionPersist);
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
    // config_token is always present and never empty, even when nothing resolved: the agent
    // needs some resource to name on /download, and the next notify re-triggers the download.
    EXPECT_EQ(j["agent"]["config_token"], "default");
    EXPECT_TRUE(j.contains("settings_hash"));
    EXPECT_EQ(j["settings_hash"].get<std::string>().size(), 64U); // sha256 hex

    ASSERT_TRUE(j["tasks"].is_array());
    ASSERT_EQ(j["tasks"].size(), 1U);
    EXPECT_EQ(j["tasks"][0]["task_id"], "T1");
    EXPECT_EQ(j["tasks"][0]["task_type"], "upgrade");

    EXPECT_GE(h.metrics.notify->get(), 1U);
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
    // The token names the very group whose merged.mg that hash was taken over.
    EXPECT_EQ(j["agent"]["config_token"], "default");
}

// The token is what /download resolves, and config_hash is what the agent verifies the bytes
// against, so the two must always describe the SAME merged.mg. For a multigroup agent that
// means the token has to carry every group, comma-joined in wdb's order -- the same CSV the
// multigroups directory name is hashed from -- and must never be re-sorted or truncated to
// the first group.
TEST(ControlHandlerTest, NotifyConfigTokenIsTheFullMultigroupSelectorInWdbOrder)
{
    auto wdb = std::make_shared<WdbRouter>();
    // Deliberately not alphabetical: "web" before "default" proves wdb's order survives.
    wdb->onSelectAgentGroup([](const std::string&) { return "ok [{\"group\":\"web,default\"}]"; });
    HandlerFixture h(wdb, [](const std::string&) { return "{\"status\":\"ok\",\"tasks\":[]}"; });

    // sha256("web,default") = 4b323b4242e8... -> the multigroup dir is its first 8 hex chars.
    const auto mergedMg = h.env.base / "multi" / "4b323b42" / "merged.mg";
    fs::create_directories(mergedMg.parent_path());
    {
        std::ofstream f(mergedMg, std::ios::binary);
        f << "hello";
    }

    NotifyData data;
    data.version = "5.0.0";
    Waiter<HttpResponse> w;
    h.handler->handleNotify(11, data, [&](const HttpResponse& r) { w.complete(r); });
    ASSERT_TRUE(w.wait(3000ms));
    EXPECT_EQ(w.value.status, 200);

    auto j = nlohmann::json::parse(w.value.body);
    EXPECT_EQ(j["agent"]["config_token"], "web,default");
    // A real hash proves the token and the hash resolved to the same file: had the token been
    // re-sorted or cut to "web", the multigroup dir would differ and this would be "0".
    EXPECT_EQ(j["agent"]["config_hash"], "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    EXPECT_EQ(j["agent"]["groups"], nlohmann::json::array({"web", "default"}));
}

TEST(ControlHandlerTest, NotifyFirstHostMetadataBypassesKeepaliveThrottle)
{
    auto wdb = std::make_shared<WdbRouter>();
    wdb->onSelectAgentGroup([](const std::string&) { return "ok {\"group\":\"default\"}"; });
    HandlerFixture h(
        wdb,
        [](const std::string&) { return "{\"status\":\"ok\",\"tasks\":[]}"; },
        [](Config& c) { c.keepaliveThrottleSec = 3600; });

    // First notify carries no host metadata (agent_info has not populated it
    // yet): a lightweight keepalive is written and stamps the throttle window.
    NotifyData bare;
    bare.version = "5.0.0";
    Waiter<HttpResponse> w1;
    h.handler->handleNotify(1, bare, [&](const HttpResponse& r) { w1.complete(r); });
    ASSERT_TRUE(w1.wait(3000ms));
    EXPECT_EQ(w1.value.status, 200);

    NotifyData withHost;
    withHost.version = "5.0.0";
    HostInfo host;
    host.hostname = "mac01";
    host.ip = "127.0.0.1";
    host.osName = "macOS";
    host.osVersion = "26.0";
    host.osPlatform = "darwin";
    host.architecture = "arm64";
    host.osType = "macos";
    withHost.host = host;

    // Second notify brings host metadata inside the throttle window: it must
    // still produce a full update, or the agent stays without version/os data
    // in the API until the window expires.
    Waiter<HttpResponse> w2;
    h.handler->handleNotify(1, withHost, [&](const HttpResponse& r) { w2.complete(r); });
    ASSERT_TRUE(w2.wait(3000ms));
    EXPECT_EQ(w2.value.status, 200);

    // Third notify with host inside the window: host data is persisted now, so
    // the throttle applies again and no further write is issued.
    Waiter<HttpResponse> w3;
    h.handler->handleNotify(1, withHost, [&](const HttpResponse& r) { w3.complete(r); });
    ASSERT_TRUE(w3.wait(3000ms));
    EXPECT_EQ(w3.value.status, 200);

    // Expected wdb traffic: one select per notify (groupsRefreshIntervalSec=0),
    // one lightweight keepalive and exactly one full update.
    for (int i = 0; i < 200 && wdb->commands().size() < 5; ++i)
    {
        std::this_thread::sleep_for(5ms);
    }
    std::this_thread::sleep_for(50ms); // settle so a stray extra write would be visible

    size_t fullUpdates = 0;
    size_t lightweightKeepalives = 0;
    for (const auto& c : wdb->commands())
    {
        if (c.find("global update-agent-data") != std::string::npos)
        {
            ++fullUpdates;
            EXPECT_NE(c.find("\"version\":\"5.0.0\""), std::string::npos);
            EXPECT_NE(c.find("\"os_name\":\"macOS\""), std::string::npos);
        }
        if (c.find("global update-keepalive") != std::string::npos &&
            c.find("\"connection_status\":\"active\"") != std::string::npos)
        {
            ++lightweightKeepalives;
        }
    }
    EXPECT_EQ(fullUpdates, 1U);
    EXPECT_EQ(lightweightKeepalives, 1U);
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
    EXPECT_GE(h.metrics.shutdown->get(), 1U);

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

// =============================================================================
// Downstream failures must not be reported as success
// =============================================================================

TEST(ControlHandlerTest, NotifyWithNoCachedGroupsReturns500OnWdbError)
{
    // Nothing cached and wazuh-db down: "default" here would be a wrong answer served as
    // authoritative, which is what every agent gets after a restart with wazuh-db down.
    auto wdb = std::make_shared<WdbRouter>();
    wdb->onSelectAgentGroup([](const std::string&) { return "err some failure"; });
    HandlerFixture h(wdb, [](const std::string&) { return "{\"status\":\"ok\",\"tasks\":[]}"; });

    NotifyData data;
    data.version = "5.0.0";
    Waiter<HttpResponse> w;
    h.handler->handleNotify(1, data, [&](const HttpResponse& r) { w.complete(r); });
    ASSERT_TRUE(w.wait(3000ms));

    EXPECT_EQ(w.value.status, 500);
    EXPECT_NE(w.value.body.find("database_error"), std::string::npos);
    EXPECT_FALSE(h.registry->get(1));
}

TEST(ControlHandlerTest, NotifyServesCachedGroupsWithoutOverwritingThemOnWdbError)
{
    std::atomic<bool> wdbDown {false};
    auto wdb = std::make_shared<WdbRouter>();
    // Array form: getAgentGroups() reads the group out of [{"group": "..."}] only, so an object
    // here would parse to no groups and cache "default".
    wdb->onSelectAgentGroup([&](const std::string&) -> std::string
                            { return wdbDown.load() ? "err some failure" : "ok [{\"group\":\"g1\"}]"; });
    HandlerFixture h(
        wdb,
        [](const std::string&) { return "{\"status\":\"ok\",\"tasks\":[]}"; },
        [](Config& c) { c.groupsRefreshIntervalSec = 3600; });

    StartupData startup;
    startup.version = "5.0.0";
    Waiter<HttpResponse> ws;
    h.handler->handleStartup(1, startup, [&](const HttpResponse& r) { ws.complete(r); });
    ASSERT_TRUE(ws.wait(3000ms));
    ASSERT_EQ(ws.value.status, 200);

    // Age the cached refresh so the next notify is due for one, then take wazuh-db down.
    h.registry->update(1,
                       [](std::shared_ptr<const AgentEntry> old)
                       {
                           auto e = std::make_shared<AgentEntry>(*old);
                           e->groupsRefreshedAtSec = 1000;
                           return e;
                       });
    wdbDown.store(true);

    NotifyData data;
    data.version = "5.0.0";
    Waiter<HttpResponse> w1;
    h.handler->handleNotify(1, data, [&](const HttpResponse& r) { w1.complete(r); });
    ASSERT_TRUE(w1.wait(3000ms));
    EXPECT_EQ(w1.value.status, 200);
    EXPECT_EQ(nlohmann::json::parse(w1.value.body)["agent"]["groups"][0], "g1");

    // The registry's copy is untouched: a failed query neither marks the cached membership fresh
    // nor overwrites what a concurrent notify may have refreshed.
    auto entry = h.registry->get(1);
    ASSERT_TRUE(entry);
    EXPECT_EQ(entry->groupsRefreshedAtSec, 1000U);
    ASSERT_EQ(entry->groups.size(), 1U);
    EXPECT_EQ(entry->groups[0], "g1");

    // And a successful query afterwards does write, so the failure path is not sticky.
    wdbDown.store(false);
    Waiter<HttpResponse> w2;
    h.handler->handleNotify(1, data, [&](const HttpResponse& r) { w2.complete(r); });
    ASSERT_TRUE(w2.wait(3000ms));

    entry = h.registry->get(1);
    ASSERT_TRUE(entry);
    EXPECT_GT(entry->groupsRefreshedAtSec, 1000U);
}

TEST(ControlHandlerTest, NotifyAfterStartupBypassesKeepaliveThrottle)
{
    auto wdb = std::make_shared<WdbRouter>();
    wdb->onSelectAgentGroup([](const std::string&) { return "ok [{\"group\":\"default\"}]"; });
    HandlerFixture h(
        wdb,
        [](const std::string&) { return "{\"status\":\"ok\",\"tasks\":[]}"; },
        [](Config& c) { c.keepaliveThrottleSec = 3600; });

    const NotifyData data = notifyWithHost();

    // Steady state: one full update, and the throttle window is now open.
    Waiter<HttpResponse> w1;
    h.handler->handleNotify(1, data, [&](const HttpResponse& r) { w1.complete(r); });
    ASSERT_TRUE(w1.wait(3000ms));

    // The agent restarts. /startup writes "pending", and hostPersisted lives here and is not
    // reset by it, so without the bypass the agent reads "pending" for a whole window.
    StartupData startup;
    startup.version = "5.0.0";
    Waiter<HttpResponse> ws;
    h.handler->handleStartup(1, startup, [&](const HttpResponse& r) { ws.complete(r); });
    ASSERT_TRUE(ws.wait(3000ms));
    ASSERT_EQ(ws.value.status, 200);

    Waiter<HttpResponse> w2;
    h.handler->handleNotify(1, data, [&](const HttpResponse& r) { w2.complete(r); });
    ASSERT_TRUE(w2.wait(3000ms));
    EXPECT_EQ(w2.value.status, 200);

    const auto fullUpdates = [&]
    {
        const auto commands = wdb->commands();
        return std::count_if(commands.begin(),
                             commands.end(),
                             [](const std::string& c)
                             {
                                 return c.find("global update-agent-data") != std::string::npos &&
                                        c.find("\"connection_status\":\"active\"") != std::string::npos;
                             });
    };

    for (int i = 0; i < 200 && fullUpdates() < 2; ++i)
    {
        std::this_thread::sleep_for(5ms);
    }
    std::this_thread::sleep_for(50ms); // settle so a stray extra write would be visible

    EXPECT_EQ(fullUpdates(), 2);
}
