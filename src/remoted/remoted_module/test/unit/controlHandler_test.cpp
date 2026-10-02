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
#include "control/registryLookup.hpp"
#include "control/taskClient.hpp"
#include "control/wazuhDBClient.hpp"
#include "fakeTaskServer.hpp"
#include "fakeUdsServer.hpp"

#include <wazuh_metrics/manager.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <future>
#include <json.hpp>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unistd.h>

using namespace remoted::control;
using remoted::test::FakeTaskServer;
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

    /// wazuh-db writes the handler issued (fire-and-forget, so they may still be in flight).
    std::size_t writeCount(WdbRouter& wdb)
    {
        const auto cmds = wdb.commands();
        return static_cast<std::size_t>(std::count_if(
            cmds.begin(), cmds.end(), [](const std::string& c) { return c.rfind("global update-", 0) == 0; }));
    }

    /// Bounded wait for at least `n` writes: a baseline before asserting that no further one arrives.
    bool waitForWrites(WdbRouter& wdb, std::size_t n)
    {
        for (int i = 0; i < 200; ++i)
        {
            if (writeCount(wdb) >= n)
            {
                return true;
            }
            std::this_thread::sleep_for(10ms);
        }
        return false;
    }

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
        // wazuh-db still speaks the framed protocol; the Task Manager serves HTTP, so only one
        // of these two is a FakeUdsServer any more.
        std::unique_ptr<FakeTaskServer> taskServer;

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
            taskServer = std::make_unique<FakeTaskServer>(env.taskPath);
            // The fixture keeps its request -> body responder signature so every case below reads the
            // same; only the transport under it changed.
            taskServer->setHandler([taskResp = std::move(taskResp)](const httplib::Request& req, httplib::Response& res)
                                   { res.set_content(taskResp(req.body), "application/json"); });

            registry = std::make_shared<AgentRegistry>();
            wdbClient = std::make_shared<WazuhDBClient>(cfg.wdbSocketPath,
                                                        cfg.wdbRequestConnections,
                                                        cfg.wdbRoundtripDeadlineMs,
                                                        cfg.wdbMaxQueueSize,
                                                        metrics,
                                                        cfg.wdbRequestDeadlineMs);
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
    HandlerFixture h(wdb, [](const std::string&) { return "{\"tasks\":[]}"; });

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
    HandlerFixture h(wdb, [](const std::string&) { return "{\"tasks\":[]}"; });

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
    HandlerFixture h(wdb, [](const std::string&) { return "{\"tasks\":[]}"; });

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
    HandlerFixture h(wdb, [](const std::string&) { return "{\"tasks\":[]}"; });

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
    HandlerFixture h(wdb, [](const std::string&) { return "{\"tasks\":[]}"; });

    StartupData data;
    data.version = "5.0.0";
    Waiter<HttpResponse> w;
    h.handler->handleStartup(1, data, [&](const HttpResponse& r) { w.complete(r); });
    ASSERT_TRUE(w.wait(3000ms));

    auto j = nlohmann::json::parse(w.value.body);
    ASSERT_EQ(j["agent"]["groups"].size(), 1U);
    EXPECT_EQ(j["agent"]["groups"][0], "default");
}

TEST(ControlHandlerTest, StartupAnswers503ForAnAgentWithNoLocalRow)
{
    // No row in the local wazuh-db ("ok []") is not membership of "default": the agent may simply
    // not have reached this node's replica yet, so it is told to retry -- with the very answer a
    // failed lookup gets, and counted apart from one.
    auto wdb = std::make_shared<WdbRouter>();
    wdb->onSelectAgentGroup([](const std::string&) { return "ok []"; });
    HandlerFixture h(wdb, [](const std::string&) { return "{\"tasks\":[]}"; });

    StartupData data;
    data.version = "5.0.0";
    Waiter<HttpResponse> w;
    h.handler->handleStartup(1, data, [&](const HttpResponse& r) { w.complete(r); });
    ASSERT_TRUE(w.wait(3000ms));

    EXPECT_EQ(w.value.status, 503);
    EXPECT_EQ(w.value.body, R"({"error":"dependency_unavailable","dependency":"wazuh-db"})")
        << "the same body as a failed lookup";
    EXPECT_FALSE(h.registry->get(1)) << "a missing row never creates an entry";
    EXPECT_EQ(h.metrics.noRow->get(), 1U);
    EXPECT_EQ(h.metrics.wdbError->get(), 0U) << "wazuh-db answered: this is not a failed lookup";
    // Nothing is persisted for an agent the database does not hold.
    for (const auto& c : wdb->commands())
    {
        EXPECT_EQ(c.rfind("global update-", 0), std::string::npos) << c;
    }
}

TEST(ControlHandlerTest, StartupReturns503OnWdbProtocolError)
{
    auto wdb = std::make_shared<WdbRouter>();
    wdb->onSelectAgentGroup([](const std::string&) { return "err some failure"; });
    HandlerFixture h(wdb, [](const std::string&) { return "{\"tasks\":[]}"; });

    StartupData data;
    data.version = "5.0.0";
    Waiter<HttpResponse> w;
    h.handler->handleStartup(1, data, [&](const HttpResponse& r) { w.complete(r); });
    ASSERT_TRUE(w.wait(3000ms));

    // 503, not 500: remoted is fine, a dependency is not answering, and the condition clears on
    // its own. That is the class the agent already retries with back-pressure.
    EXPECT_EQ(w.value.status, 503);
    EXPECT_NE(w.value.body.find("dependency_unavailable"), std::string::npos);
    EXPECT_NE(w.value.body.find("wazuh-db"), std::string::npos) << "the body must name WHICH dependency";
}

// =============================================================================
// handleNotify
// =============================================================================

TEST(ControlHandlerTest, NotifyInvalidHostReturns400)
{
    auto wdb = std::make_shared<WdbRouter>();
    HandlerFixture h(wdb, [](const std::string&) { return "{\"tasks\":[]}"; });

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
    wdb->onSelectAgentGroup([](const std::string&) { return "ok [{\"group\":\"default\"}]"; });

    HandlerFixture h(wdb,
                     [](const std::string&) -> std::string
                     {
                         nlohmann::json j;
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

// A failed task-manager poll (here: the task server answers a non-2xx status, one of the
// SocketError causes routed through controlHandler.cpp's DEBUG1 log) must not change the
// agent-visible contract: still 200, with an empty tasks array instead of an error surfaced to
// the agent. The manager retries on the next successful poll.
TEST(ControlHandlerTest, NotifyReturnsEmptyTasksOnTaskManagerFailure)
{
    auto wdb = std::make_shared<WdbRouter>();
    wdb->onSelectAgentGroup([](const std::string&) { return "ok [{\"group\":\"default\"}]"; });

    HandlerFixture h(wdb, [](const std::string&) { return "{}"; });
    h.taskServer->setHandler([](const httplib::Request&, httplib::Response& res) { res.status = 500; });

    NotifyData data;
    data.version = "5.0.0";

    Waiter<HttpResponse> w;
    h.handler->handleNotify(1, data, [&](const HttpResponse& r) { w.complete(r); });
    ASSERT_TRUE(w.wait(3000ms));

    EXPECT_EQ(w.value.status, 200);
    auto j = nlohmann::json::parse(w.value.body);
    ASSERT_TRUE(j["tasks"].is_array());
    EXPECT_TRUE(j["tasks"].empty());
}

TEST(ControlHandlerTest, NotifyReturnsRealConfigHashWhenMergedMgExists)
{
    auto wdb = std::make_shared<WdbRouter>();
    wdb->onSelectAgentGroup([](const std::string&) { return "ok [{\"group\":\"default\"}]"; });
    HandlerFixture h(wdb, [](const std::string&) { return "{\"tasks\":[]}"; });

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
    HandlerFixture h(wdb, [](const std::string&) { return "{\"tasks\":[]}"; });

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
    wdb->onSelectAgentGroup([](const std::string&) { return "ok [{\"group\":\"default\"}]"; });
    HandlerFixture h(
        wdb, [](const std::string&) { return "{\"tasks\":[]}"; }, [](Config& c) { c.keepaliveThrottleSec = 3600; });

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

// -----------------------------------------------------------------------------
// ca_generation (issue #39319, RF-3): what m_config.caGenerationProvider hands back on every
// notify. The provider itself is a plain std::function the fixture injects through tweakCfg, so
// none of these tests need a real HTTPS listener or CA file -- that wiring is
// RemotedModuleFacade's (production, not under test here) and IHttpServer::caDescriptor()'s (see
// httpServer_test.cpp). Every assertion reads a parsed nlohmann::json by KEY, never by comparing
// serialized text: the library sorts object keys alphabetically ("ca_generation" lands between
// "agent" and "settings_hash" on the wire), and a test that assumed a different order would break
// on a library upgrade for no reason that has anything to do with this feature (design §2.4).
// -----------------------------------------------------------------------------

TEST(ControlHandlerTest, NotifyReportsCaGenerationTimestampFromProvider)
{
    auto wdb = std::make_shared<WdbRouter>();
    wdb->onSelectAgentGroup([](const std::string&) { return "ok [{\"group\":\"default\"}]"; });
    HandlerFixture h(
        wdb,
        [](const std::string&) { return "{\"tasks\":[]}"; },
        [](Config& c)
        {
            c.caGenerationProvider = []() -> std::optional<std::int64_t>
            {
                return std::int64_t {1758000000};
            };
        });

    NotifyData data;
    data.version = "5.0.0";
    Waiter<HttpResponse> w;
    h.handler->handleNotify(1, data, [&](const HttpResponse& r) { w.complete(r); });
    ASSERT_TRUE(w.wait(3000ms));

    EXPECT_EQ(w.value.status, 200);
    const auto j = nlohmann::json::parse(w.value.body);
    ASSERT_TRUE(j.contains("ca_generation"));
    EXPECT_EQ(j["ca_generation"], 1758000000);
}

TEST(ControlHandlerTest, NotifyReportsCaGenerationZeroFromProvider)
{
    auto wdb = std::make_shared<WdbRouter>();
    wdb->onSelectAgentGroup([](const std::string&) { return "ok [{\"group\":\"default\"}]"; });
    HandlerFixture h(
        wdb,
        [](const std::string&) { return "{\"tasks\":[]}"; },
        [](Config& c)
        {
            c.caGenerationProvider = []() -> std::optional<std::int64_t>
            {
                return std::int64_t {0};
            };
        });

    NotifyData data;
    data.version = "5.0.0";
    Waiter<HttpResponse> w;
    h.handler->handleNotify(1, data, [&](const HttpResponse& r) { w.complete(r); });
    ASSERT_TRUE(w.wait(3000ms));

    EXPECT_EQ(w.value.status, 200);
    const auto j = nlohmann::json::parse(w.value.body);
    ASSERT_TRUE(j.contains("ca_generation"));
    EXPECT_EQ(j["ca_generation"], 0);
}

TEST(ControlHandlerTest, NotifyReportsCaGenerationNullWhenProviderHasNoBundle)
{
    auto wdb = std::make_shared<WdbRouter>();
    wdb->onSelectAgentGroup([](const std::string&) { return "ok [{\"group\":\"default\"}]"; });
    HandlerFixture h(
        wdb,
        [](const std::string&) { return "{\"tasks\":[]}"; },
        [](Config& c)
        {
            c.caGenerationProvider = []() -> std::optional<std::int64_t>
            {
                return std::nullopt;
            };
        });

    NotifyData data;
    data.version = "5.0.0";
    Waiter<HttpResponse> w;
    h.handler->handleNotify(1, data, [&](const HttpResponse& r) { w.complete(r); });
    ASSERT_TRUE(w.wait(3000ms));

    EXPECT_EQ(w.value.status, 200);
    const auto j = nlohmann::json::parse(w.value.body);
    ASSERT_TRUE(j.contains("ca_generation"));
    // A provider that answers "no servable bundle" puts `null` on the wire, not an absent key:
    // absent means "no provider at all" (a manager older than this feature), which is a different
    // state (NotifyOmitsCaGenerationWithoutProvider, below).
    EXPECT_TRUE(j["ca_generation"].is_null());
}

TEST(ControlHandlerTest, NotifyOmitsCaGenerationWithoutProvider)
{
    auto wdb = std::make_shared<WdbRouter>();
    wdb->onSelectAgentGroup([](const std::string&) { return "ok [{\"group\":\"default\"}]"; });
    // No tweakCfg: makeConfig() leaves caGenerationProvider default-constructed (empty), exactly
    // as buildControlConfig() does today on a build with no HTTPS listener behind it.
    HandlerFixture h(wdb,
                     [](const std::string&) -> std::string
                     {
                         nlohmann::json j;
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
    const auto j = nlohmann::json::parse(w.value.body);
    EXPECT_FALSE(j.contains("ca_generation"));

    // Nothing else about the response changed: same shape as
    // NotifyReturnsGroupsSettingsHashAndTasks, field for field.
    ASSERT_TRUE(j["agent"]["groups"].is_array());
    EXPECT_EQ(j["agent"]["groups"][0], "default");
    EXPECT_EQ(j["agent"]["config_hash"], "0");
    EXPECT_EQ(j["agent"]["config_token"], "default");
    EXPECT_TRUE(j.contains("settings_hash"));
    EXPECT_EQ(j["settings_hash"].get<std::string>().size(), 64U); // sha256 hex
    ASSERT_TRUE(j["tasks"].is_array());
    ASSERT_EQ(j["tasks"].size(), 1U);
    EXPECT_EQ(j["tasks"][0]["task_id"], "T1");
    ASSERT_TRUE(j.contains("vd_feed_offset"));
    EXPECT_TRUE(j["vd_feed_offset"].is_number_unsigned());
}

// =============================================================================
// handleShutdown
// =============================================================================

TEST(ControlHandlerTest, ShutdownReturns200WithEmptyBodyImmediately)
{
    auto wdb = std::make_shared<WdbRouter>();
    HandlerFixture h(wdb, [](const std::string&) { return "{\"tasks\":[]}"; });

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
    HandlerFixture h(wdb, [](const std::string&) { return "{\"tasks\":[]}"; });

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

TEST(ControlHandlerTest, NotifyWithNoCachedGroupsReturns503OnWdbError)
{
    // Nothing cached and wazuh-db down: "default" here would be a wrong answer served as
    // authoritative, which is what every agent gets after a restart with wazuh-db down.
    auto wdb = std::make_shared<WdbRouter>();
    wdb->onSelectAgentGroup([](const std::string&) { return "err some failure"; });
    HandlerFixture h(wdb, [](const std::string&) { return "{\"tasks\":[]}"; });

    NotifyData data;
    data.version = "5.0.0";
    Waiter<HttpResponse> w;
    h.handler->handleNotify(1, data, [&](const HttpResponse& r) { w.complete(r); });
    ASSERT_TRUE(w.wait(3000ms));

    EXPECT_EQ(w.value.status, 503);
    EXPECT_NE(w.value.body.find("dependency_unavailable"), std::string::npos);
    EXPECT_NE(w.value.body.find("wazuh-db"), std::string::npos) << "the body must name WHICH dependency";
    EXPECT_FALSE(h.registry->get(1));
}

TEST(ControlHandlerTest, NotifyWithAnExpiredEntryReturns503OnWdbError)
{
    std::atomic<bool> wdbDown {false};
    auto wdb = std::make_shared<WdbRouter>();
    // Array form: getAgentGroups() reads the group out of [{"group": "..."}] only.
    wdb->onSelectAgentGroup([&](const std::string&) -> std::string
                            { return wdbDown.load() ? "err some failure" : "ok [{\"group\":\"g1\"}]"; });
    HandlerFixture h(
        wdb, [](const std::string&) { return "{\"tasks\":[]}"; }, [](Config& c) { c.groupsRefreshIntervalSec = 3600; });

    StartupData startup;
    startup.version = "5.0.0";
    Waiter<HttpResponse> ws;
    h.handler->handleStartup(1, startup, [&](const HttpResponse& r) { ws.complete(r); });
    ASSERT_TRUE(ws.wait(3000ms));
    ASSERT_EQ(ws.value.status, 200);
    ASSERT_TRUE(waitForWrites(*wdb, 1U)) << "startup's status write never arrived";

    // Age the cached refresh so the next notify is due for one, then take wazuh-db down.
    h.registry->update(1,
                       [](std::shared_ptr<const AgentEntry> old)
                       {
                           auto e = std::make_shared<AgentEntry>(*old);
                           e->groupsRefreshedAtSec = 1000;
                           return e;
                       });
    const auto before = h.registry->get(1);
    wdbDown.store(true);

    NotifyData data;
    data.version = "5.0.0";
    Waiter<HttpResponse> w1;
    h.handler->handleNotify(1, data, [&](const HttpResponse& r) { w1.complete(r); });
    ASSERT_TRUE(w1.wait(3000ms));
    // An expired membership is never served in place of an answer.
    EXPECT_EQ(w1.value.status, 503);
    EXPECT_EQ(w1.value.body, R"({"error":"dependency_unavailable","dependency":"wazuh-db"})");

    // Nothing was written: not the membership, not the activity, not a keepalive.
    const auto entry = h.registry->get(1);
    ASSERT_TRUE(entry);
    EXPECT_EQ(entry, before) << "the registry entry was replaced";
    std::this_thread::sleep_for(100ms); // a keepalive write would be queued by now
    EXPECT_EQ(writeCount(*wdb), 1U);

    // And a successful query afterwards serves and writes, so the failure path is not sticky.
    wdbDown.store(false);
    Waiter<HttpResponse> w2;
    h.handler->handleNotify(1, data, [&](const HttpResponse& r) { w2.complete(r); });
    ASSERT_TRUE(w2.wait(3000ms));
    EXPECT_EQ(w2.value.status, 200);
    EXPECT_GT(h.registry->get(1)->groupsRefreshedAtSec, 1000U);
}

TEST(ControlHandlerTest, NotifyAfterStartupBypassesKeepaliveThrottle)
{
    auto wdb = std::make_shared<WdbRouter>();
    wdb->onSelectAgentGroup([](const std::string&) { return "ok [{\"group\":\"default\"}]"; });
    HandlerFixture h(
        wdb, [](const std::string&) { return "{\"tasks\":[]}"; }, [](Config& c) { c.keepaliveThrottleSec = 3600; });

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

// =============================================================================
// wazuh-db refusing connections: every request is answered within the end-to-end deadline
// =============================================================================

namespace
{
    constexpr auto kRequestDeadlineMs = 300U;

    void withShortRequestDeadline(Config& c)
    {
        c.wdbRequestDeadlineMs = kRequestDeadlineMs;
    }
} // namespace

TEST(ControlHandlerTest, StartupReturns503WithinDeadlineWhenWazuhDbRefusesConnections)
{
    auto wdb = std::make_shared<WdbRouter>();
    wdb->onSelectAgentGroup([](const std::string&) { return "ok [{\"group\":\"g1\"}]"; });
    HandlerFixture h(wdb, [](const std::string&) { return "{\"tasks\":[]}"; }, withShortRequestDeadline);
    h.wdbServer.reset();

    StartupData data;
    data.version = "5.0.0";
    for (int attempt = 0; attempt < 2; ++attempt)
    {
        Waiter<HttpResponse> w;
        const auto start = std::chrono::steady_clock::now();
        h.handler->handleStartup(1, data, [&](const HttpResponse& r) { w.complete(r); });
        ASSERT_TRUE(w.wait(10000ms)) << "attempt " << attempt << " was never answered";
        EXPECT_EQ(w.value.status, 503) << "attempt " << attempt;
        EXPECT_NE(w.value.body.find("dependency_unavailable"), std::string::npos);
        EXPECT_LT(std::chrono::steady_clock::now() - start, 5s) << "attempt " << attempt;
    }
}

TEST(ControlHandlerTest, NotifyWithAnExpiredEntryReturns503WhenWazuhDbRefusesConnections)
{
    auto wdb = std::make_shared<WdbRouter>();
    wdb->onSelectAgentGroup([](const std::string&) { return "ok [{\"group\":\"g1\"}]"; });
    HandlerFixture h(wdb, [](const std::string&) { return "{\"tasks\":[]}"; }, withShortRequestDeadline);

    StartupData startup;
    startup.version = "5.0.0";
    Waiter<HttpResponse> ws;
    h.handler->handleStartup(1, startup, [&](const HttpResponse& r) { ws.complete(r); });
    ASSERT_TRUE(ws.wait(3000ms));
    ASSERT_EQ(ws.value.status, 200);

    // groupsRefreshIntervalSec is 0 in these fixtures, so every notify asks wazuh-db first -- and
    // with it gone, is refused within the request deadline instead of served the cached groups.
    h.wdbServer.reset();
    NotifyData data;
    data.version = "5.0.0";
    for (int attempt = 0; attempt < 2; ++attempt)
    {
        Waiter<HttpResponse> w;
        const auto start = std::chrono::steady_clock::now();
        h.handler->handleNotify(1, data, [&](const HttpResponse& r) { w.complete(r); });
        ASSERT_TRUE(w.wait(10000ms)) << "attempt " << attempt << " was never answered";
        EXPECT_EQ(w.value.status, 503) << "attempt " << attempt;
        EXPECT_LT(std::chrono::steady_clock::now() - start, 5s) << "attempt " << attempt;
    }
    // The cached membership is kept, untouched, for when wazuh-db comes back.
    const auto entry = h.registry->get(1);
    ASSERT_TRUE(entry);
    EXPECT_EQ(entry->groups, std::vector<std::string> {"g1"});
}

TEST(ControlHandlerTest, NotifyWithoutCacheReturns503WhenWazuhDbRefusesConnections)
{
    auto wdb = std::make_shared<WdbRouter>();
    HandlerFixture h(wdb, [](const std::string&) { return "{\"tasks\":[]}"; }, withShortRequestDeadline);
    h.wdbServer.reset();

    NotifyData data;
    data.version = "5.0.0";
    for (int attempt = 0; attempt < 2; ++attempt)
    {
        Waiter<HttpResponse> w;
        h.handler->handleNotify(2, data, [&](const HttpResponse& r) { w.complete(r); });
        ASSERT_TRUE(w.wait(10000ms)) << "attempt " << attempt << " was never answered";
        EXPECT_EQ(w.value.status, 503) << "attempt " << attempt;
        EXPECT_FALSE(h.registry->get(2));
    }
}

// =============================================================================
// One ordering rule for every groups writer (#39147): a /control lookup never overwrites a newer
// membership push, and a "no row" answer invalidates -- never establishes -- a membership
// =============================================================================

namespace
{
    std::size_t selectCount(WdbRouter& wdb)
    {
        const auto cmds = wdb.commands();
        return static_cast<std::size_t>(std::count_if(cmds.begin(),
                                                      cmds.end(),
                                                      [](const std::string& c)
                                                      { return c.rfind("global select-agent-group", 0) == 0; }));
    }

    /// Answers every select-agent-group with `answer`, holding the `gateAt`-th one (1-based) until
    /// the test calls release(): the query has been issued, and its ticket taken, before the test
    /// pushes, so "issue -> push -> answer" is the order every run.
    class GatedSelect
    {
    public:
        GatedSelect(WdbRouter& wdb, std::string answer, int gateAt)
            : m_releaseFuture(m_release.get_future().share())
            , m_receivedFuture(m_received.get_future())
        {
            wdb.onSelectAgentGroup(
                [this, answer = std::move(answer), gateAt](const std::string&)
                {
                    if (++m_calls == gateAt)
                    {
                        m_received.set_value();
                        m_releaseFuture.wait_for(10s); // bounded: a failing test must not hang the fake
                    }
                    return answer;
                });
        }
        bool waitReceived()
        {
            return m_receivedFuture.wait_for(5s) == std::future_status::ready;
        }
        void release()
        {
            m_release.set_value();
        }

    private:
        std::promise<void> m_release;
        std::shared_future<void> m_releaseFuture;
        std::promise<void> m_received;
        std::future<void> m_receivedFuture;
        std::atomic<int> m_calls {0};
    };

    uint64_t wallSec()
    {
        return static_cast<uint64_t>(std::time(nullptr));
    }

    /// What another reader's store leaves while a /control query is in flight -- a /download lookup
    /// for the same agent (RegistryLookup coalesces only its own): the groups it read, established at
    /// its issue time and stamped. A push never establishes groups (S45), so this is the only newer
    /// established write a /control query can meet. Activity fields are left as they are.
    void storeOtherRead(AgentRegistry& registry, AgentId id, std::vector<std::string> groups)
    {
        registry.update(id,
                        [&](std::shared_ptr<const AgentEntry> old)
                        {
                            auto e = old ? std::make_shared<AgentEntry>(*old) : std::make_shared<AgentEntry>();
                            e->groups = groups;
                            e->groupsRefreshedAtSec = wallSec();
                            e->groupsSeq = registry.nextGroupsSeq();
                            return e;
                        });
    }
} // namespace

TEST(ControlHandlerTest, NoRowInvalidatesAnEstablishedEntryAndKeepsActivity)
{
    std::atomic<bool> rowGone {false};
    auto wdb = std::make_shared<WdbRouter>();
    wdb->onSelectAgentGroup([&](const std::string&) -> std::string
                            { return rowGone.load() ? "ok []" : "ok [{\"group\":\"g1\"}]"; });
    HandlerFixture h(wdb, [](const std::string&) { return "{\"tasks\":[]}"; });

    StartupData startup;
    startup.version = "5.0.0";
    Waiter<HttpResponse> ws;
    h.handler->handleStartup(1, startup, [&](const HttpResponse& r) { ws.complete(r); });
    ASSERT_TRUE(ws.wait(3000ms));
    ASSERT_EQ(ws.value.status, 200);
    ASSERT_TRUE(waitForWrites(*wdb, 1U));
    const auto before = h.registry->get(1);
    ASSERT_NE(before->groupsRefreshedAtSec, 0U);

    // The row disappears from this node's replica (or the agent was removed): the next refresh
    // says so, and the membership stops counting -- the entry and its activity stay.
    rowGone.store(true);
    NotifyData data;
    data.version = "5.0.0";
    Waiter<HttpResponse> w;
    h.handler->handleNotify(1, data, [&](const HttpResponse& r) { w.complete(r); });
    ASSERT_TRUE(w.wait(3000ms));
    EXPECT_EQ(w.value.status, 503);
    EXPECT_EQ(w.value.body, R"({"error":"dependency_unavailable","dependency":"wazuh-db"})");

    const auto entry = h.registry->get(1);
    ASSERT_TRUE(entry);
    EXPECT_EQ(entry->groups, std::vector<std::string> {"g1"});
    EXPECT_EQ(entry->groupsRefreshedAtSec, 0U) << "invalidated, so /download never authorizes from it";
    EXPECT_GT(entry->groupsSeq, before->groupsSeq);
    EXPECT_EQ(entry->lastActivitySec, before->lastActivitySec) << "a 503 records no activity";
    EXPECT_EQ(h.metrics.noRow->get(), 1U);
    std::this_thread::sleep_for(100ms);
    EXPECT_EQ(writeCount(*wdb), 1U) << "a 503 notify writes no keepalive";

    // Not established any more, so a restart of the agent asks wazuh-db again -- and is refused.
    Waiter<HttpResponse> ws2;
    h.handler->handleStartup(1, startup, [&](const HttpResponse& r) { ws2.complete(r); });
    ASSERT_TRUE(ws2.wait(3000ms));
    EXPECT_EQ(ws2.value.status, 503);
    EXPECT_EQ(h.metrics.noRow->get(), 2U);
    EXPECT_EQ(selectCount(*wdb), 3U);
}

TEST(ControlHandlerTest, StartupWithAFreshEntryMakesNoQuery)
{
    std::atomic<bool> wdbDown {false};
    auto wdb = std::make_shared<WdbRouter>();
    wdb->onSelectAgentGroup([&](const std::string&) -> std::string
                            { return wdbDown.load() ? "err some failure" : "ok [{\"group\":\"g1\"}]"; });
    HandlerFixture h(
        wdb, [](const std::string&) { return "{\"tasks\":[]}"; }, [](Config& c) { c.groupsRefreshIntervalSec = 60; });

    StartupData startup;
    startup.version = "5.0.0";
    Waiter<HttpResponse> ws;
    h.handler->handleStartup(1, startup, [&](const HttpResponse& r) { ws.complete(r); });
    ASSERT_TRUE(ws.wait(3000ms));
    ASSERT_EQ(ws.value.status, 200);

    // An agent restart inside the refresh interval, with wazuh-db failing: the fresh membership
    // answers, exactly as a notify's would, and the accepted version is still persisted.
    wdbDown.store(true);
    Waiter<HttpResponse> w;
    h.handler->handleStartup(1, startup, [&](const HttpResponse& r) { w.complete(r); });
    ASSERT_TRUE(w.wait(3000ms));
    ASSERT_EQ(w.value.status, 200);
    EXPECT_EQ(nlohmann::json::parse(w.value.body)["agent"]["groups"][0], "g1");
    EXPECT_EQ(selectCount(*wdb), 1U);
    EXPECT_TRUE(waitForWrites(*wdb, 2U)) << "both startups persist the version";
}

TEST(ControlHandlerTest, StartupRacingANewerReadAnswersIt)
{
    auto wdb = std::make_shared<WdbRouter>();
    GatedSelect gate(*wdb, "ok [{\"group\":\"g-old\"}]", 1);
    HandlerFixture h(wdb, [](const std::string&) { return "{\"tasks\":[]}"; });

    // An entry this node already holds: what /control/shutdown mints for an agent it has not seen.
    Waiter<HttpResponse> wd;
    h.handler->handleShutdown(1, ShutdownData {}, [&](const HttpResponse& r) { wd.complete(r); });
    ASSERT_TRUE(wd.wait(3000ms));

    StartupData startup;
    startup.version = "5.0.0";
    Waiter<HttpResponse> w;
    h.handler->handleStartup(1, startup, [&](const HttpResponse& r) { w.complete(r); });
    ASSERT_TRUE(gate.waitReceived());
    storeOtherRead(*h.registry, 1, {"g-new"});
    const auto storedSeq = h.registry->get(1)->groupsSeq;
    gate.release();
    ASSERT_TRUE(w.wait(3000ms));

    ASSERT_EQ(w.value.status, 200);
    EXPECT_EQ(nlohmann::json::parse(w.value.body)["agent"]["groups"][0], "g-new");
    const auto entry = h.registry->get(1);
    EXPECT_EQ(entry->groups, std::vector<std::string> {"g-new"});
    EXPECT_EQ(entry->groupsSeq, storedSeq); // this answer did not write over it
}

TEST(ControlHandlerTest, NoRowRacingANewerReadAnswersIt)
{
    auto wdb = std::make_shared<WdbRouter>();
    GatedSelect gate(*wdb, "ok []", 1);
    HandlerFixture h(wdb, [](const std::string&) { return "{\"tasks\":[]}"; });

    // An entry this node already holds: what /control/shutdown mints for an agent it has not seen.
    Waiter<HttpResponse> wd;
    h.handler->handleShutdown(1, ShutdownData {}, [&](const HttpResponse& r) { wd.complete(r); });
    ASSERT_TRUE(wd.wait(3000ms));

    StartupData startup;
    startup.version = "5.0.0";
    Waiter<HttpResponse> w;
    h.handler->handleStartup(1, startup, [&](const HttpResponse& r) { w.complete(r); });
    ASSERT_TRUE(gate.waitReceived());
    // The row was replicated -- and another read stored it -- after this query read the replica.
    storeOtherRead(*h.registry, 1, {"g-new"});
    const auto storedSeq = h.registry->get(1)->groupsSeq;
    gate.release();
    ASSERT_TRUE(w.wait(3000ms));

    ASSERT_EQ(w.value.status, 200) << "the newer, established membership answers";
    EXPECT_EQ(nlohmann::json::parse(w.value.body)["agent"]["groups"][0], "g-new");
    const auto entry = h.registry->get(1);
    EXPECT_EQ(entry->groupsSeq, storedSeq) << "the older answer neither wrote nor invalidated";
    EXPECT_NE(entry->groupsRefreshedAtSec, 0U);
    EXPECT_EQ(h.metrics.noRow->get(), 0U);
}

TEST(ControlHandlerTest, NotifyRefreshRacingANewerReadKeepsIt)
{
    auto wdb = std::make_shared<WdbRouter>();
    GatedSelect gate(*wdb, "ok [{\"group\":\"g-old\"}]", 2); // 1: startup; 2: the notify refresh
    HandlerFixture h(wdb, [](const std::string&) { return "{\"tasks\":[]}"; });

    StartupData startup;
    startup.version = "5.0.0";
    Waiter<HttpResponse> ws;
    h.handler->handleStartup(1, startup, [&](const HttpResponse& r) { ws.complete(r); });
    ASSERT_TRUE(ws.wait(3000ms));
    ASSERT_EQ(h.registry->get(1)->groups, std::vector<std::string> {"g-old"});

    // groupsRefreshIntervalSec is 0 in these fixtures: the notify refreshes from wazuh-db.
    NotifyData data;
    data.version = "5.0.0";
    Waiter<HttpResponse> w;
    h.handler->handleNotify(1, data, [&](const HttpResponse& r) { w.complete(r); });
    ASSERT_TRUE(gate.waitReceived());
    storeOtherRead(*h.registry, 1, {"g-new"});
    gate.release();
    ASSERT_TRUE(w.wait(3000ms));

    ASSERT_EQ(w.value.status, 200);
    EXPECT_EQ(nlohmann::json::parse(w.value.body)["agent"]["config_token"], "g-new");
    EXPECT_EQ(h.registry->get(1)->groups, std::vector<std::string> {"g-new"});
}

// FR-13 is withdrawn (S45): a publication withdraws the membership instead of refreshing it, so the
// next notify reads wazuh-db again even within the interval -- and hands out what it read.
TEST(ControlHandlerTest, NotifyAfterAPublicationQueriesAgain)
{
    std::atomic<bool> moved {false};
    auto wdb = std::make_shared<WdbRouter>();
    wdb->onSelectAgentGroup([&](const std::string&) -> std::string
                            { return moved.load() ? "ok [{\"group\":\"g2\"}]" : "ok [{\"group\":\"g1\"}]"; });
    HandlerFixture h(
        wdb, [](const std::string&) { return "{\"tasks\":[]}"; }, [](Config& c) { c.groupsRefreshIntervalSec = 60; });

    StartupData startup;
    startup.version = "5.0.0";
    Waiter<HttpResponse> ws;
    h.handler->handleStartup(1, startup, [&](const HttpResponse& r) { ws.complete(r); });
    ASSERT_TRUE(ws.wait(3000ms));
    ASSERT_EQ(selectCount(*wdb), 1U);

    moved = true; // the cluster daemon wrote g2, then published the agent
    ASSERT_EQ(h.registry->invalidateGroups(1), AgentRegistry::PushOutcome::Invalidated);
    NotifyData data;
    data.version = "5.0.0";
    Waiter<HttpResponse> w;
    h.handler->handleNotify(1, data, [&](const HttpResponse& r) { w.complete(r); });
    ASSERT_TRUE(w.wait(3000ms));

    ASSERT_EQ(w.value.status, 200);
    EXPECT_EQ(nlohmann::json::parse(w.value.body)["agent"]["config_token"], "g2");
    EXPECT_EQ(selectCount(*wdb), 2U);
    EXPECT_TRUE(groupsFresh(*h.registry->get(1), wallSec(), 60));
}

TEST(ControlHandlerTest, StartupBlockedByASkippedPushAnswers503)
{
    auto wdb = std::make_shared<WdbRouter>();
    GatedSelect gate(*wdb, "ok [{\"group\":\"g1\"}]", 1);
    HandlerFixture h(wdb, [](const std::string&) { return "{\"tasks\":[]}"; });

    StartupData startup;
    startup.version = "5.0.0";
    Waiter<HttpResponse> w;
    h.handler->handleStartup(1, startup, [&](const HttpResponse& r) { w.complete(r); });
    ASSERT_TRUE(gate.waitReceived());
    // While the query is in flight, a push is skipped for an agent this node does not hold -- it
    // may have been agent 1's, so this read may predate agent 1's change.
    ASSERT_EQ(h.registry->invalidateGroups(1), AgentRegistry::PushOutcome::Skipped);
    gate.release();
    ASSERT_TRUE(w.wait(3000ms));

    EXPECT_EQ(w.value.status, 503);
    EXPECT_EQ(w.value.body, R"({"error":"dependency_unavailable","dependency":"wazuh-db"})");
    EXPECT_FALSE(h.registry->get(1)) << "nothing is written, not even provisionally";
    std::this_thread::sleep_for(100ms);
    EXPECT_EQ(writeCount(*wdb), 0U) << "a 503 startup persists no status";
}

TEST(ControlHandlerTest, StartupRacingAnInvalidationAnswers503)
{
    auto wdb = std::make_shared<WdbRouter>();
    GatedSelect gate(*wdb, "ok [{\"group\":\"g-old\"}]", 1);
    HandlerFixture h(wdb, [](const std::string&) { return "{\"tasks\":[]}"; });

    // The entry an invalidation can reach: what /control/shutdown mints for an agent it has not seen.
    Waiter<HttpResponse> wd;
    h.handler->handleShutdown(1, ShutdownData {}, [&](const HttpResponse& r) { wd.complete(r); });
    ASSERT_TRUE(wd.wait(3000ms));
    ASSERT_TRUE(waitForWrites(*wdb, 1U)); // the shutdown's own status write

    StartupData startup;
    startup.version = "5.0.0";
    Waiter<HttpResponse> w;
    h.handler->handleStartup(1, startup, [&](const HttpResponse& r) { w.complete(r); });
    ASSERT_TRUE(gate.waitReceived());
    // The worker applied a change it could not confirm while this query was reading the database.
    ASSERT_EQ(h.registry->invalidateGroups(1), AgentRegistry::PushOutcome::Invalidated);
    const auto invalidated = h.registry->get(1);
    gate.release();
    ASSERT_TRUE(w.wait(3000ms));

    EXPECT_EQ(w.value.status, 503);
    EXPECT_EQ(w.value.body, R"({"error":"dependency_unavailable","dependency":"wazuh-db"})");
    EXPECT_EQ(h.registry->get(1), invalidated) << "a 503 writes nothing: the entry stays invalidated";
    std::this_thread::sleep_for(100ms);
    EXPECT_EQ(writeCount(*wdb), 1U) << "a 503 startup persists no status";
}

TEST(ControlHandlerTest, NotifyRefreshRacingAnInvalidationAnswers503)
{
    auto wdb = std::make_shared<WdbRouter>();
    GatedSelect gate(*wdb, "ok [{\"group\":\"g-old\"}]", 2); // 1: startup; 2: the notify refresh
    HandlerFixture h(wdb, [](const std::string&) { return "{\"tasks\":[]}"; });

    StartupData startup;
    startup.version = "5.0.0";
    Waiter<HttpResponse> ws;
    h.handler->handleStartup(1, startup, [&](const HttpResponse& r) { ws.complete(r); });
    ASSERT_TRUE(ws.wait(3000ms));
    ASSERT_EQ(ws.value.status, 200);
    ASSERT_TRUE(waitForWrites(*wdb, 1U));

    // groupsRefreshIntervalSec is 0 in these fixtures: the notify refreshes from wazuh-db.
    NotifyData data;
    data.version = "5.0.0";
    Waiter<HttpResponse> w;
    h.handler->handleNotify(1, data, [&](const HttpResponse& r) { w.complete(r); });
    ASSERT_TRUE(gate.waitReceived());
    ASSERT_EQ(h.registry->invalidateGroups(1), AgentRegistry::PushOutcome::Invalidated);
    const auto invalidated = h.registry->get(1);
    gate.release();
    ASSERT_TRUE(w.wait(3000ms));

    // Neither the read (it may predate the change) nor the invalidated membership answers.
    EXPECT_EQ(w.value.status, 503);
    EXPECT_EQ(w.value.body, R"({"error":"dependency_unavailable","dependency":"wazuh-db"})");
    EXPECT_EQ(h.registry->get(1), invalidated);
    std::this_thread::sleep_for(100ms);
    EXPECT_EQ(writeCount(*wdb), 1U) << "a 503 notify writes no keepalive";
}

namespace
{
    /// The /download fallback's own view of wazuh-db, holding its select-agent-group until
    /// release(): a lookup whose query -- and ticket -- predate a /control read that is stored
    /// first. A separate fake rather than the fixture's WdbRouter, which answers under its own lock
    /// and would hold /control's query behind the gated one.
    class GatedLookupWdb
    {
    public:
        explicit GatedLookupWdb(std::string answer)
            : m_path(remoted::test::makeUniqueSocketPath("ch_lookup_wdb"))
            , m_releaseFuture(m_release.get_future().share())
            , m_receivedFuture(m_received.get_future())
            , m_server(m_path,
                       [this, answer = std::move(answer)](const std::string& request)
                       {
                           if (request.rfind("global select-agent-group", 0) == 0 && !m_receivedSet.exchange(true))
                           {
                               m_received.set_value();
                               m_releaseFuture.wait_for(10s); // bounded: a failing test must not hang the fake
                           }
                           return answer;
                       })
        {
        }

        ~GatedLookupWdb()
        {
            release(); // before m_server's stop() joins a connection thread still waiting on it
        }

        GatedLookupWdb(const GatedLookupWdb&) = delete;
        GatedLookupWdb& operator=(const GatedLookupWdb&) = delete;

        const std::string& path() const
        {
            return m_path;
        }
        bool waitReceived()
        {
            return m_receivedFuture.wait_for(5s) == std::future_status::ready;
        }
        void release()
        {
            if (!m_released.exchange(true))
            {
                m_release.set_value();
            }
        }

    private:
        std::string m_path;
        std::promise<void> m_release;
        std::shared_future<void> m_releaseFuture;
        std::atomic<bool> m_released {false};
        std::promise<void> m_received;
        std::future<void> m_receivedFuture;
        std::atomic<bool> m_receivedSet {false};
        FakeUdsServer m_server; // last: its handler uses every member above
    };

    /// Generous deadlines for the two tests below: the lookup's query is held while /control runs,
    /// and the default 2 s round trip would let a slow runner (valgrind, ASan) time it out first.
    void patientWdb(Config& c)
    {
        c.wdbRoundtripDeadlineMs = 10000;
        c.wdbRequestDeadlineMs = 10000;
    }
} // namespace

// /control stamps what it stores (storeLookedUpGroups()): a /download lookup issued BEFORE a startup
// read, and answered after it, must find that newer write and answer from it -- never overwrite it
// with its own, older read. Without the stamp the entry looks no newer than the lookup's ticket, and
// the agent's previous groups come back as an established membership.
TEST(ControlHandlerTest, AnOlderDownloadLookupNeverOverwritesAStartupRead)
{
    auto wdb = std::make_shared<WdbRouter>();
    wdb->onSelectAgentGroup([](const std::string&) { return std::string("ok [{\"group\":\"g-new\"}]"); });
    HandlerFixture h(wdb, [](const std::string&) { return "{\"tasks\":[]}"; }, patientWdb);

    // The /download fallback over the same registry, as the facade wires it.
    GatedLookupWdb lookupWdb("ok [{\"group\":\"g-old\"}]");
    auto lookupCfg = h.cfg;
    lookupCfg.wdbSocketPath = lookupWdb.path();
    Waiter<LookupOutcome> wl; // before the lookup: it must outlive any late callback
    RegistryLookup lookup(h.registry, lookupCfg, h.metrics);

    lookup.lookup(1, wallSec(), [&](LookupOutcome outcome) { wl.complete(std::move(outcome)); });
    ASSERT_TRUE(lookupWdb.waitReceived()) << "the lookup never queried wazuh-db; the test would prove nothing";

    StartupData startup;
    startup.version = "5.0.0";
    Waiter<HttpResponse> ws;
    h.handler->handleStartup(1, startup, [&](const HttpResponse& r) { ws.complete(r); });
    ASSERT_TRUE(ws.wait(5000ms));
    ASSERT_EQ(ws.value.status, 200);
    const auto stored = h.registry->get(1);
    ASSERT_EQ(stored->groups, std::vector<std::string> {"g-new"});

    lookupWdb.release();
    ASSERT_TRUE(wl.wait(5000ms));

    EXPECT_EQ(wl.value.kind, LookupOutcome::Kind::Groups);
    EXPECT_EQ(wl.value.groups, std::vector<std::string> {"g-new"}) << "the older read answers with the newer write";
    const auto entry = h.registry->get(1);
    EXPECT_EQ(entry->groups, std::vector<std::string> {"g-new"}) << "the older read overwrote /control's";
    EXPECT_EQ(entry->groupsSeq, stored->groupsSeq);
}

// The same rule on the notify refresh, which writes over an entry that already carries a stamp: the
// refresh must take a new one, or the entry keeps the startup's -- older than the lookup's ticket.
TEST(ControlHandlerTest, AnOlderDownloadLookupNeverOverwritesANotifyRead)
{
    std::atomic<bool> moved {false};
    auto wdb = std::make_shared<WdbRouter>();
    wdb->onSelectAgentGroup([&](const std::string&) -> std::string
                            { return moved.load() ? "ok [{\"group\":\"g-new\"}]" : "ok [{\"group\":\"g-old\"}]"; });
    HandlerFixture h(wdb, [](const std::string&) { return "{\"tasks\":[]}"; }, patientWdb);

    StartupData startup;
    startup.version = "5.0.0";
    Waiter<HttpResponse> ws;
    h.handler->handleStartup(1, startup, [&](const HttpResponse& r) { ws.complete(r); });
    ASSERT_TRUE(ws.wait(5000ms));
    ASSERT_EQ(h.registry->get(1)->groups, std::vector<std::string> {"g-old"});

    GatedLookupWdb lookupWdb("ok [{\"group\":\"g-old\"}]");
    auto lookupCfg = h.cfg;
    lookupCfg.wdbSocketPath = lookupWdb.path();
    Waiter<LookupOutcome> wl; // before the lookup: it must outlive any late callback
    RegistryLookup lookup(h.registry, lookupCfg, h.metrics);

    lookup.lookup(1, wallSec(), [&](LookupOutcome outcome) { wl.complete(std::move(outcome)); });
    ASSERT_TRUE(lookupWdb.waitReceived()) << "the lookup never queried wazuh-db; the test would prove nothing";

    // The agent moves after the lookup read; groupsRefreshIntervalSec is 0 in these fixtures, so the
    // notify refreshes from wazuh-db and stores what it read.
    moved = true;
    NotifyData data;
    data.version = "5.0.0";
    Waiter<HttpResponse> wn;
    h.handler->handleNotify(1, data, [&](const HttpResponse& r) { wn.complete(r); });
    ASSERT_TRUE(wn.wait(5000ms));
    ASSERT_EQ(wn.value.status, 200);
    ASSERT_EQ(nlohmann::json::parse(wn.value.body)["agent"]["config_token"], "g-new");
    const auto stored = h.registry->get(1);

    lookupWdb.release();
    ASSERT_TRUE(wl.wait(5000ms));

    EXPECT_EQ(wl.value.kind, LookupOutcome::Kind::Groups);
    EXPECT_EQ(wl.value.groups, std::vector<std::string> {"g-new"}) << "the older read answers with the newer write";
    const auto entry = h.registry->get(1);
    EXPECT_EQ(entry->groups, std::vector<std::string> {"g-new"}) << "the older read overwrote the notify's";
    EXPECT_EQ(entry->groupsSeq, stored->groupsSeq);
}
