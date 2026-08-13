/*
 * Wazuh remoted module - WazuhDBClient unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 31, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "control/metrics.hpp"
#include "control/wazuhDBClient.hpp"
#include "fakeUdsServer.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <future>
#include <mutex>
#include <string>
#include <thread>

using namespace remoted::control;
using remoted::test::FakeUdsServer;
using namespace std::chrono_literals;

namespace
{
    // Bounded blocking wait for an async completion. Async callbacks are the
    // client's only completion channel, and if the deadline plumbing is broken
    // the tests must fail loudly rather than hang the whole test run.
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
} // namespace

// -----------------------------------------------------------------------------
// Static parser: isOk / getPayload.
// -----------------------------------------------------------------------------
TEST(WazuhDBClientStaticTest, IsOkAcceptsBareOk)
{
    EXPECT_TRUE(WazuhDBClient::isOk("ok"));
}
TEST(WazuhDBClientStaticTest, IsOkAcceptsOkWithPayload)
{
    EXPECT_TRUE(WazuhDBClient::isOk("ok something"));
}
TEST(WazuhDBClientStaticTest, IsOkRejectsErr)
{
    EXPECT_FALSE(WazuhDBClient::isOk("err bad request"));
}
TEST(WazuhDBClientStaticTest, IsOkRejectsEmpty)
{
    EXPECT_FALSE(WazuhDBClient::isOk(""));
}
TEST(WazuhDBClientStaticTest, IsOkRejectsPrefixMasqueradingAsOk)
{
    // "okabc" would incorrectly be accepted by a plain "starts_with ok" check;
    // the real code requires "ok" alone or "ok " (space) to guard against this.
    EXPECT_FALSE(WazuhDBClient::isOk("okabc"));
}

TEST(WazuhDBClientStaticTest, GetPayloadReturnsEverythingAfterOkSpace)
{
    EXPECT_EQ(WazuhDBClient::getPayload("ok {\"a\":1}"), "{\"a\":1}");
}
TEST(WazuhDBClientStaticTest, GetPayloadEmptyForBareOk)
{
    EXPECT_EQ(WazuhDBClient::getPayload("ok"), "");
}
TEST(WazuhDBClientStaticTest, GetPayloadEmptyForErr)
{
    EXPECT_EQ(WazuhDBClient::getPayload("err x"), "");
}

// -----------------------------------------------------------------------------
// Integration: real client + fake wdb over UDS.
// -----------------------------------------------------------------------------

TEST(WazuhDBClientTest, QueryRoundTripsCommandAndResponse)
{
    const auto path = remoted::test::makeUniqueSocketPath("wdb_rt");

    std::string lastReceived;
    FakeUdsServer server(path,
                         [&](const std::string& req) -> std::string
                         {
                             lastReceived = req;
                             return "ok {\"result\":42}";
                         });

    ControlMetrics metrics;
    WazuhDBClient client(path,
                         /*poolSize*/ 1,
                         /*deadlineMs*/ 1000,
                         /*maxQueueSize*/ 100,
                         metrics);

    Waiter<std::pair<SocketError, std::string>> w;
    client.query("global select-agent-group 42",
                 [&](SocketError err, const std::string& resp) { w.complete({err, resp}); });

    ASSERT_TRUE(w.wait(3000ms));
    EXPECT_EQ(w.value.first, SocketError::None);
    EXPECT_EQ(w.value.second, "ok {\"result\":42}");
    EXPECT_EQ(lastReceived, "global select-agent-group 42");
}

TEST(WazuhDBClientTest, GetAgentGroupsParsesCsvFromWdbResponse)
{
    const auto path = remoted::test::makeUniqueSocketPath("wdb_grp");
    FakeUdsServer server(path, [](const std::string&) -> std::string { return "ok [{\"group\":\"default,web,dmz\"}]"; });

    ControlMetrics metrics;
    WazuhDBClient client(path, 1, 1000, 100, metrics);

    Waiter<std::pair<SocketError, std::vector<std::string>>> w;
    client.getAgentGroups(7, [&](SocketError e, std::vector<std::string> g) { w.complete({e, std::move(g)}); });
    ASSERT_TRUE(w.wait(3000ms));
    EXPECT_EQ(w.value.first, SocketError::None);
    ASSERT_EQ(w.value.second.size(), 3U);
    EXPECT_EQ(w.value.second[0], "default");
    EXPECT_EQ(w.value.second[1], "web");
    EXPECT_EQ(w.value.second[2], "dmz");
}

TEST(WazuhDBClientTest, GetAgentGroupsReturnsEmptyOnEmptyCsv)
{
    const auto path = remoted::test::makeUniqueSocketPath("wdb_gemp");
    FakeUdsServer server(path, [](const std::string&) -> std::string { return "ok [{\"group\":\"\"}]"; });

    ControlMetrics metrics;
    WazuhDBClient client(path, 1, 1000, 100, metrics);

    Waiter<std::pair<SocketError, std::vector<std::string>>> w;
    client.getAgentGroups(7, [&](SocketError e, std::vector<std::string> g) { w.complete({e, std::move(g)}); });
    ASSERT_TRUE(w.wait(3000ms));
    EXPECT_EQ(w.value.first, SocketError::None);
    EXPECT_TRUE(w.value.second.empty());
}

TEST(WazuhDBClientTest, GetAgentGroupsProtocolErrorOnErrResponse)
{
    const auto path = remoted::test::makeUniqueSocketPath("wdb_gerr");
    FakeUdsServer server(path, [](const std::string&) -> std::string { return "err no such agent"; });

    ControlMetrics metrics;
    WazuhDBClient client(path, 1, 1000, 100, metrics);

    Waiter<std::pair<SocketError, std::vector<std::string>>> w;
    client.getAgentGroups(7, [&](SocketError e, std::vector<std::string> g) { w.complete({e, std::move(g)}); });
    ASSERT_TRUE(w.wait(3000ms));
    EXPECT_EQ(w.value.first, SocketError::ProtocolError);
    EXPECT_TRUE(w.value.second.empty());
}

TEST(WazuhDBClientTest, GetAgentGroupsProtocolErrorOnMalformedJson)
{
    const auto path = remoted::test::makeUniqueSocketPath("wdb_gmal");
    FakeUdsServer server(path, [](const std::string&) -> std::string { return "ok {not json"; });

    ControlMetrics metrics;
    WazuhDBClient client(path, 1, 1000, 100, metrics);

    Waiter<std::pair<SocketError, std::vector<std::string>>> w;
    client.getAgentGroups(7, [&](SocketError e, std::vector<std::string> g) { w.complete({e, std::move(g)}); });
    ASSERT_TRUE(w.wait(3000ms));
    EXPECT_EQ(w.value.first, SocketError::ProtocolError);
    EXPECT_TRUE(w.value.second.empty());
}

TEST(WazuhDBClientTest, UpdateKeepaliveSendsGlobalUpdateKeepaliveCommand)
{
    const auto path = remoted::test::makeUniqueSocketPath("wdb_ka");

    std::mutex mu;
    std::string received;
    FakeUdsServer server(path,
                         [&](const std::string& req) -> std::string
                         {
                             {
                                 std::lock_guard<std::mutex> lock(mu);
                                 received = req;
                             }
                             return "ok";
                         });

    ControlMetrics metrics;
    WazuhDBClient client(path, 1, 1000, 100, metrics);

    Waiter<SocketError> w;
    client.updateKeepalive(42, "active", "syncreq", [&](SocketError e) { w.complete(e); });
    ASSERT_TRUE(w.wait(3000ms));
    EXPECT_EQ(w.value, SocketError::None);

    std::string got;
    {
        std::lock_guard<std::mutex> lock(mu);
        got = received;
    }
    // The command format is: global update-keepalive <json>.
    EXPECT_NE(got.find("global update-keepalive "), std::string::npos);
    EXPECT_NE(got.find("\"id\":42"), std::string::npos);
    EXPECT_NE(got.find("\"connection_status\":\"active\""), std::string::npos);
    EXPECT_NE(got.find("\"sync_status\":\"syncreq\""), std::string::npos);
}

TEST(WazuhDBClientTest, UpdateAgentDataIncludesHostInfoFields)
{
    const auto path = remoted::test::makeUniqueSocketPath("wdb_hi");
    std::mutex mu;
    std::string received;
    FakeUdsServer server(path,
                         [&](const std::string& req) -> std::string
                         {
                             std::lock_guard<std::mutex> lock(mu);
                             received = req;
                             return "ok";
                         });

    ControlMetrics metrics;
    WazuhDBClient client(path, 1, 1000, 100, metrics);

    HostInfo host;
    host.hostname = "web01";
    host.architecture = "x86_64";
    host.ip = "10.0.0.1";
    host.osName = "Ubuntu";
    host.osVersion = "24.04";
    host.osPlatform = "ubuntu";
    host.osType = "Linux";

    Waiter<SocketError> w;
    client.updateAgentData(9, "v4.8.0", "active", "synced", &host, [&](SocketError e) { w.complete(e); });
    ASSERT_TRUE(w.wait(3000ms));
    EXPECT_EQ(w.value, SocketError::None);

    std::string got;
    {
        std::lock_guard<std::mutex> lock(mu);
        got = received;
    }
    EXPECT_NE(got.find("global update-agent-data "), std::string::npos);
    EXPECT_NE(got.find("\"id\":9"), std::string::npos);
    EXPECT_NE(got.find("\"version\":\"v4.8.0\""), std::string::npos);
    EXPECT_NE(got.find("\"os_name\":\"Ubuntu\""), std::string::npos);
    EXPECT_NE(got.find("\"os_arch\":\"x86_64\""), std::string::npos);
    EXPECT_NE(got.find("\"os_type\":\"Linux\""), std::string::npos);
    EXPECT_NE(got.find("\"agent_ip\":\"10.0.0.1\""), std::string::npos);
}

TEST(WazuhDBClientTest, UpdateAgentDataParsesOsMajorAndMinorFromVersion)
{
    const auto path = remoted::test::makeUniqueSocketPath("wdb_osver");
    std::mutex mu;
    std::string received;
    FakeUdsServer server(path,
                         [&](const std::string& req) -> std::string
                         {
                             std::lock_guard<std::mutex> lock(mu);
                             received = req;
                             return "ok";
                         });

    ControlMetrics metrics;
    WazuhDBClient client(path, 1, 1000, 100, metrics);

    // Test Ubuntu version format
    HostInfo host1;
    host1.osVersion = "22.04";
    host1.osName = "Ubuntu";
    host1.osPlatform = "ubuntu";
    host1.architecture = "x86_64";
    host1.ip = "10.0.0.1";

    Waiter<SocketError> w1;
    client.updateAgentData(1, "v5.0.0", "active", "synced", &host1, [&](SocketError e) { w1.complete(e); });
    ASSERT_TRUE(w1.wait(3000ms));

    std::string got1;
    {
        std::lock_guard<std::mutex> lock(mu);
        got1 = received;
    }
    EXPECT_NE(got1.find("\"os_major\":\"22\""), std::string::npos) << "Ubuntu 22.04 should parse major=22, got: " << got1;
    EXPECT_NE(got1.find("\"os_minor\":\"04\""), std::string::npos) << "Ubuntu 22.04 should parse minor=04, got: " << got1;

    // Test SUSE version format
    HostInfo host2;
    host2.osVersion = "15-SP7";
    host2.osName = "SUSE";
    host2.osPlatform = "sles";
    host2.architecture = "x86_64";
    host2.ip = "10.0.0.2";

    Waiter<SocketError> w2;
    client.updateAgentData(2, "v5.0.0", "active", "synced", &host2, [&](SocketError e) { w2.complete(e); });
    ASSERT_TRUE(w2.wait(3000ms));

    std::string got2;
    {
        std::lock_guard<std::mutex> lock(mu);
        got2 = received;
    }
    EXPECT_NE(got2.find("\"os_major\":\"15\""), std::string::npos) << "SUSE 15-SP7 should parse major=15, got: " << got2;
    EXPECT_NE(got2.find("\"os_minor\":\"7\""), std::string::npos) << "SUSE 15-SP7 should parse minor=7, got: " << got2;

    // Test version with patch number
    HostInfo host3;
    host3.osVersion = "20.04.5";
    host3.osName = "Ubuntu";
    host3.osPlatform = "ubuntu";
    host3.architecture = "x86_64";
    host3.ip = "10.0.0.3";

    Waiter<SocketError> w3;
    client.updateAgentData(3, "v5.0.0", "active", "synced", &host3, [&](SocketError e) { w3.complete(e); });
    ASSERT_TRUE(w3.wait(3000ms));

    std::string got3;
    {
        std::lock_guard<std::mutex> lock(mu);
        got3 = received;
    }
    EXPECT_NE(got3.find("\"os_major\":\"20\""), std::string::npos) << "Ubuntu 20.04.5 should parse major=20, got: " << got3;
    EXPECT_NE(got3.find("\"os_minor\":\"04\""), std::string::npos) << "Ubuntu 20.04.5 should parse minor=04, got: " << got3;
}

TEST(WazuhDBClientTest, UpdateAgentDataOmitsOsTypeWhenEmpty)
{
    const auto path = remoted::test::makeUniqueSocketPath("wdb_noty");
    std::mutex mu;
    std::string received;
    FakeUdsServer server(path,
                         [&](const std::string& req) -> std::string
                         {
                             std::lock_guard<std::mutex> lock(mu);
                             received = req;
                             return "ok";
                         });

    ControlMetrics metrics;
    WazuhDBClient client(path, 1, 1000, 100, metrics);

    HostInfo host; // all empty strings, including osType.
    Waiter<SocketError> w;
    client.updateAgentData(1, "v4", "active", "synced", &host, [&](SocketError e) { w.complete(e); });
    ASSERT_TRUE(w.wait(3000ms));

    std::string got;
    {
        std::lock_guard<std::mutex> lock(mu);
        got = received;
    }
    EXPECT_EQ(got.find("os_type"), std::string::npos)
        << "os_type must be OMITTED when host.osType is empty; got: " << got;
}

TEST(WazuhDBClientTest, UpdateStatusCodeSerializesInteger)
{
    const auto path = remoted::test::makeUniqueSocketPath("wdb_sc");
    std::mutex mu;
    std::string received;
    FakeUdsServer server(path,
                         [&](const std::string& req) -> std::string
                         {
                             std::lock_guard<std::mutex> lock(mu);
                             received = req;
                             return "ok";
                         });

    ControlMetrics metrics;
    WazuhDBClient client(path, 1, 1000, 100, metrics);

    Waiter<SocketError> w;
    client.updateStatusCode(3, AgentStatusCode::InvalidVersion, "v0", "synced", [&](SocketError e) { w.complete(e); });
    ASSERT_TRUE(w.wait(3000ms));

    std::string got;
    {
        std::lock_guard<std::mutex> lock(mu);
        got = received;
    }
    EXPECT_NE(got.find("global update-status-code "), std::string::npos);
    // InvalidVersion == 1.
    EXPECT_NE(got.find("\"status_code\":1"), std::string::npos);
    EXPECT_NE(got.find("\"version\":\"v0\""), std::string::npos);
}

// -----------------------------------------------------------------------------
// Timeout: server accepts but never replies; client must fail with Timeout.
// The metrics counter must be incremented so we can watchdog on it.
// -----------------------------------------------------------------------------
TEST(WazuhDBClientTest, QueryTimeoutFailsWithTimeoutAndIncrementsMetric)
{
    const auto path = remoted::test::makeUniqueSocketPath("wdb_to");
    FakeUdsServer server(path, [](const std::string&) -> std::string { return "ok"; });
    server.setDropResponses(true);

    ControlMetrics metrics;
    // Short deadline so the test doesn't wait forever.
    WazuhDBClient client(path, 1, /*deadlineMs*/ 100, 100, metrics);

    Waiter<SocketError> w;
    client.query("global anything", [&](SocketError e, const std::string&) { w.complete(e); });
    ASSERT_TRUE(w.wait(3000ms));
    EXPECT_EQ(w.value, SocketError::Timeout);
    EXPECT_GE(metrics.wdbErrorCount.load(), 1U);
}

// -----------------------------------------------------------------------------
// QueueFull: enqueue past maxQueueSize while the only worker is blocked.
// Excess requests must be rejected synchronously with QueueFull.
// -----------------------------------------------------------------------------
TEST(WazuhDBClientTest, QueueFullRejectsSynchronously)
{
    const auto path = remoted::test::makeUniqueSocketPath("wdb_qf");

    // Server blocks the worker: reads a request but never responds.
    FakeUdsServer server(path, [](const std::string&) -> std::string { return ""; });
    server.setDropResponses(true);

    ControlMetrics metrics;
    // 1 worker, queue depth 2. QueueFull is decided synchronously in query()
    // without touching the worker, so the deadline doesn't race the check --
    // we keep it small so the dtor does not have to wait for an in-flight
    // timeout before joining.
    WazuhDBClient client(path, /*poolSize*/ 1, /*deadlineMs*/ 200, /*maxQueueSize*/ 2, metrics);

    // Give the worker time to open the socket, then enqueue a first request
    // that will be popped immediately (worker in flight, wait_for stuck).
    std::this_thread::sleep_for(100ms);

    std::atomic<int> okDispatches {0};
    std::atomic<int> queueFull {0};

    auto submit = [&]()
    {
        client.query("cmd",
                     [&](SocketError err, const std::string&)
                     {
                         if (err == SocketError::QueueFull)
                             queueFull.fetch_add(1);
                         else
                             okDispatches.fetch_add(1);
                     });
    };

    // First submission goes to the worker (dequeued into wait_for).
    submit();
    // Next two fill the queue (size 0 -> 1 -> 2).
    submit();
    submit();
    // Any further submission must be rejected right away.
    submit();
    submit();
    submit();

    // Poll briefly for the QueueFull callbacks to fire (they're synchronous
    // from the caller's thread inside `query`, but scheduling is scheduling).
    for (int i = 0; i < 200 && queueFull.load() < 3; ++i)
    {
        std::this_thread::sleep_for(5ms);
    }
    EXPECT_GE(queueFull.load(), 3);
    EXPECT_GE(metrics.wdbErrorCount.load(), 3U);
}

// -----------------------------------------------------------------------------
// Dtor drains: any pending queue entries are failed with Io so upstream code
// can propagate a real error instead of hanging.
// -----------------------------------------------------------------------------
TEST(WazuhDBClientTest, DtorFailsPendingCallbacksWithIo)
{
    const auto path = remoted::test::makeUniqueSocketPath("wdb_dt");
    FakeUdsServer server(path, [](const std::string&) -> std::string { return "ok"; });
    server.setDropResponses(true);

    ControlMetrics metrics;
    std::atomic<int> io {0};

    {
        // Short deadline so the worker's wait_for on the in-flight request
        // returns quickly and the dtor can proceed to drain the queue.
        WazuhDBClient client(path, /*poolSize*/ 1, /*deadlineMs*/ 200, /*maxQueueSize*/ 10, metrics);
        std::this_thread::sleep_for(100ms);
        // Fill the queue: 1 in flight + several waiting.
        for (int i = 0; i < 5; ++i)
        {
            client.query("cmd",
                         [&](SocketError e, const std::string&)
                         {
                             if (e == SocketError::Io)
                                 io.fetch_add(1);
                         });
        }
        // Falling out of scope destroys client -> pending drained with Io.
    }

    // At least the requests still queued at teardown must have been failed.
    // The in-flight one may also have been failed with Io/Timeout; we assert on
    // the queued ones (>= 4 of the 5) to keep the test deterministic.
    EXPECT_GE(io.load(), 4);
}
