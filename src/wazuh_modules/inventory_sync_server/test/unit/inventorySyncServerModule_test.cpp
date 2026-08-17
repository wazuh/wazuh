/*
 * Wazuh inventory sync server module - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 28, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "inventory_sync_server.h"

#include "testIndexerConnectorFakes.hpp"
#include "testLogRecorder.hpp"
#include <cJSON.h>

#include <gtest/gtest.h>

#include <sys/socket.h>
#include <sys/un.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <mutex>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

using invsync::test::logCallCount;
using invsync::test::LogRecorder;
using invsync::test::testLogCallback;

namespace
{
    std::string uniqueSocketPath(const char* tag)
    {
        static std::atomic<int> counter {0};
        return "/tmp/issm_" + std::string {tag} + "_" + std::to_string(::getpid()) + "_" +
               std::to_string(counter.fetch_add(1)) + ".sock";
    }

    inventory_sync_server_config_t makeConfig(const std::string& socketPath)
    {
        inventory_sync_server_config_t config {};
        std::snprintf(config.cluster_name, sizeof(config.cluster_name), "%s", "test-cluster");
        std::snprintf(config.socket_path, sizeof(config.socket_path), "%s", socketPath.c_str());
        config.io_threads = 1;
        config.drain_timeout = 1;
        // One pipeline worker, deterministically: 0 would resolve to half the machine's cores and
        // the tests that count connector builds (the pipeline builds one per EXTRA worker) would
        // depend on the hardware they run on.
        config.sync_workers = 1;
        return config;
    }

    /// Minimal HTTP/1.1 client for the module's own socket. The transport tests have udsTestClient for
    /// their own server; this exists so these tests can reach the socket the MODULE opens.
    struct ModuleResponse
    {
        int status {0};
        std::string body;
    };

    ModuleResponse sendModuleRequest(const std::string& socketPath,
                                     const std::string& method,
                                     const std::string& target,
                                     const std::string& body,
                                     const std::string& agentId)
    {
        ModuleResponse result;

        const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0)
        {
            return result;
        }

        ::sockaddr_un address {};
        address.sun_family = AF_UNIX;
        std::snprintf(address.sun_path, sizeof(address.sun_path), "%s", socketPath.c_str());
        if (::connect(fd, reinterpret_cast<::sockaddr*>(&address), sizeof(address)) != 0)
        {
            ::close(fd);
            return result;
        }

        std::string request = method + " " + target + " HTTP/1.1\r\nHost: localhost\r\n";
        if (!agentId.empty())
        {
            request += "X-Wazuh-Agent-Id: " + agentId + "\r\n";
        }
        request += "Content-Length: " + std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;

        if (::write(fd, request.data(), request.size()) < 0)
        {
            ::close(fd);
            return result;
        }

        std::string raw;
        std::array<char, 4096> buffer {};
        for (;;)
        {
            const auto read = ::read(fd, buffer.data(), buffer.size());
            if (read <= 0)
            {
                break;
            }
            raw.append(buffer.data(), static_cast<std::size_t>(read));
        }
        ::close(fd);

        if (raw.size() > 12)
        {
            result.status = std::atoi(raw.substr(9, 3).c_str());
        }
        const auto split = raw.find("\r\n\r\n");
        if (split != std::string::npos)
        {
            result.body = raw.substr(split + 4);
        }
        return result;
    }
} // namespace

class InventorySyncServerModuleTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        logCallCount().store(0, std::memory_order_relaxed);
        LogRecorder::clear();
    }

    void TearDown() override
    {
        // Ensure the module is stopped even if a test asserted early.
        inventory_sync_server_stop();
        // An override made by one test must never leak into the next.
        invsync::test::resetIndexerConnectorFactoriesToProduction();
    }
};

TEST_F(InventorySyncServerModuleTest, StartAndStop)
{
    const auto path = uniqueSocketPath("startstop");
    const auto config = makeConfig(path);

    inventory_sync_server_start(testLogCallback, &config);
    EXPECT_TRUE(LogRecorder::waitForMessageContaining("worker thread running"));
    inventory_sync_server_stop();

    EXPECT_GT(logCallCount().load(), 0);
}

TEST_F(InventorySyncServerModuleTest, StopWithoutStartIsSafe)
{
    inventory_sync_server_stop();
    SUCCEED();
}

// A NULL configuration must fall back to defaults without crashing. It binds the real default socket
// path, which may well fail in a test environment -- that is fine and is itself the retry path; what
// matters is that nothing crashes.
TEST_F(InventorySyncServerModuleTest, StartWithNullConfigIsSafe)
{
    inventory_sync_server_start(testLogCallback, nullptr);
    inventory_sync_server_stop();
    EXPECT_GT(logCallCount().load(), 0);
}

TEST_F(InventorySyncServerModuleTest, DoubleStartIsIgnored)
{
    const auto path = uniqueSocketPath("double");
    const auto config = makeConfig(path);

    inventory_sync_server_start(testLogCallback, &config);
    inventory_sync_server_start(testLogCallback, &config);

    EXPECT_TRUE(LogRecorder::waitForMessageContaining("already started"));
    inventory_sync_server_stop();
}

TEST_F(InventorySyncServerModuleTest, StopIsIdempotent)
{
    const auto path = uniqueSocketPath("idem");
    const auto config = makeConfig(path);

    inventory_sync_server_start(testLogCallback, &config);
    inventory_sync_server_stop();
    EXPECT_NO_FATAL_FAILURE(inventory_sync_server_stop());
}

/**
 * The wedge regression. If m_running were set BEFORE the worker thread was created, a throwing
 * std::thread constructor would leave the facade claiming to run with nothing running, and every
 * later start() would be refused as "already started" forever. This pins the invariant from the
 * reachable direction: a clean stop must leave the module startable again.
 */
TEST_F(InventorySyncServerModuleTest, StartStopStartAgainWorks)
{
    const auto path = uniqueSocketPath("restart");
    const auto config = makeConfig(path);

    inventory_sync_server_start(testLogCallback, &config);
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("worker thread running"));
    inventory_sync_server_stop();

    LogRecorder::clear();
    inventory_sync_server_start(testLogCallback, &config);

    EXPECT_TRUE(LogRecorder::waitForMessageContaining("worker thread running"))
        << "the module refused to restart after a clean stop";

    inventory_sync_server_stop();
}

// The socket actually in use has to be diagnosable from wazuh-manager.log alone.
TEST_F(InventorySyncServerModuleTest, StartLogsTheResolvedSocketPath)
{
    invsync::test::installAlwaysAvailableFakeIndexers();

    const auto path = uniqueSocketPath("logpath");
    const auto config = makeConfig(path);

    inventory_sync_server_start(testLogCallback, &config);

    EXPECT_TRUE(LogRecorder::waitForMessageContaining(path)) << "the log must name the socket it bound";
    inventory_sync_server_stop();
}

TEST_F(InventorySyncServerModuleTest, StartCreatesTheConfiguredSocket)
{
    invsync::test::installAlwaysAvailableFakeIndexers();

    const auto path = uniqueSocketPath("created");
    const auto config = makeConfig(path);

    inventory_sync_server_start(testLogCallback, &config);
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("listening on"));
    EXPECT_TRUE(std::filesystem::exists(path));

    inventory_sync_server_stop();
    EXPECT_FALSE(std::filesystem::exists(path)) << "a clean stop must remove the socket file";
}

/**
 * @brief A socket path that can never work is FATAL, reported up front, and names the path.
 *
 * Two changes from what this used to assert, both deliberate:
 *
 *  - start() now returns non-zero instead of entering the retry loop. Nothing an operator does at
 *    runtime fixes a missing parent directory, so retrying every 60 s forever only produced log noise
 *    while modulesd ran on looking healthy with no inventory ingress. modulesd treats non-zero as
 *    fatal and refuses to run.
 *  - the message must NOT name a setting. It used to point at
 *    'inventory_sync_server_socket_path', which does not exist and cannot: internal options carry only
 *    ints, so the path is fixed. Sending an operator to look for it wasted their time.
 */
TEST_F(InventorySyncServerModuleTest, AnUnusableSocketPathIsFatalAndNamesThePathNotASetting)
{
    // Without this, the indexer gate would fail first (no <indexer> configured), and the failure
    // reported would be about the indexer rather than the socket this test means to exercise.
    invsync::test::installAlwaysAvailableFakeIndexers();

    auto config = makeConfig("/proc/self/does-not-exist/inventory-sync.sock");

    EXPECT_NE(0, inventory_sync_server_start(testLogCallback, &config))
        << "an unusable socket path must be reported as fatal, not retried";

    EXPECT_TRUE(LogRecorder::sawMessageContaining("/proc/self/does-not-exist/inventory-sync.sock"))
        << "the failure must name the path";
    EXPECT_FALSE(LogRecorder::sawMessageContaining("inventory_sync_server_socket_path"))
        << "it must not send the operator after a setting that does not exist";

    inventory_sync_server_stop();
}

/// The happy path still returns success, so "non-zero" cannot pass by accident.
TEST_F(InventorySyncServerModuleTest, AUsableSocketPathStartsSuccessfully)
{
    invsync::test::installAlwaysAvailableFakeIndexers();

    auto config = makeConfig(uniqueSocketPath("usable"));

    EXPECT_EQ(0, inventory_sync_server_start(testLogCallback, &config));

    inventory_sync_server_stop();
}

/**
 * The indexer block is BORROWED for the duration of start() only; the module deep-copies what it
 * needs. Freeing it immediately afterwards must be safe.
 *
 * Only genuinely meaningful under ASan, where a retained pointer would be reported as a
 * use-after-free instead of quietly working.
 */
TEST_F(InventorySyncServerModuleTest, IndexerConfigIsCopiedAndNotRetained)
{
    // This test is about the C-ABI's borrow contract, not about really constructing an
    // IndexerConnectorSync (whose CA-file-must-exist check would otherwise reject the fake path
    // used below) -- bypass real construction so it stays fast and deterministic.
    invsync::test::installAlwaysAvailableFakeIndexers();

    const auto path = uniqueSocketPath("indexer");
    auto config = makeConfig(path);

    cJSON* indexer = cJSON_CreateObject();
    cJSON* hosts = cJSON_CreateArray();
    cJSON_AddItemToArray(hosts, cJSON_CreateString("https://127.0.0.1:9200"));
    cJSON_AddItemToArray(hosts, cJSON_CreateString("https://127.0.0.2:9200"));
    cJSON_AddItemToObject(indexer, "hosts", hosts);
    cJSON_AddStringToObject(indexer, "username", "admin");
    cJSON* ssl = cJSON_CreateObject();
    cJSON* authorities = cJSON_CreateArray();
    cJSON_AddItemToArray(authorities, cJSON_CreateString("/etc/certs/root-ca.pem"));
    cJSON_AddItemToObject(ssl, "certificate_authorities", authorities);
    cJSON_AddStringToObject(ssl, "key", "/etc/certs/private.key");
    cJSON_AddItemToObject(indexer, "ssl", ssl);
    config.indexer = indexer;

    inventory_sync_server_start(testLogCallback, &config);

    // Freed while the module is still running: nothing may reach back into it.
    cJSON_Delete(indexer);
    config.indexer = nullptr;

    EXPECT_TRUE(LogRecorder::waitForMessageContaining("listening on"));
    inventory_sync_server_stop();
}

// Counts and set/unset only. The hosts can carry credentials in the URL and the certificate paths
// are not useful in a log line, so neither may be rendered.
TEST_F(InventorySyncServerModuleTest, IndexerSummaryLogsCountsNotSecrets)
{
    // Keeps this test from making a real (if fast) network attempt against the fake hosts below.
    invsync::test::installAlwaysAvailableFakeIndexers();

    const auto path = uniqueSocketPath("secrets");
    auto config = makeConfig(path);

    cJSON* indexer = cJSON_CreateObject();
    cJSON* hosts = cJSON_CreateArray();
    cJSON_AddItemToArray(hosts, cJSON_CreateString("https://user:s3cret@127.0.0.1:9200"));
    cJSON_AddItemToArray(hosts, cJSON_CreateString("https://127.0.0.2:9200"));
    cJSON_AddItemToObject(indexer, "hosts", hosts);
    cJSON* ssl = cJSON_CreateObject();
    cJSON_AddStringToObject(ssl, "key", "/etc/certs/private.key");
    cJSON_AddItemToObject(indexer, "ssl", ssl);
    config.indexer = indexer;

    inventory_sync_server_start(testLogCallback, &config);
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("Indexer configuration received"));

    EXPECT_TRUE(LogRecorder::sawMessageContaining("hosts=2"));
    EXPECT_FALSE(LogRecorder::sawMessageContaining("s3cret")) << "credentials must never be logged";
    EXPECT_FALSE(LogRecorder::sawMessageContaining("/etc/certs/private.key"))
        << "key paths must not be logged, only whether they are set";
    EXPECT_TRUE(LogRecorder::sawMessageContaining("ssl.key=<set>"));

    cJSON_Delete(indexer);
    inventory_sync_server_stop();
}

/**
 * @brief The routes the facade registers are actually reachable, on the socket it actually opens.
 *
 * Nothing exercised this before: no test sent a single byte to the socket the MODULE opens (the
 * transport tests drive their own server with their own routes). So the wiring in startHttpServer()
 * was unverified end to end -- swapping the /stats and /config handlers, or dropping the liveness
 * route, would have passed the entire suite.
 *
 * The liveness handler in particular had never run once.
 */
TEST_F(InventorySyncServerModuleTest, TheRegisteredRoutesAreReachableOnTheModulesOwnSocket)
{
    invsync::test::installAlwaysAvailableFakeIndexers();

    const auto path = uniqueSocketPath("routes");
    auto config = makeConfig(path);

    ASSERT_EQ(0, inventory_sync_server_start(testLogCallback, &config));
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("listening on"));

    // GET / -- the liveness probe, exempt from the byte budget.
    const auto liveness = sendModuleRequest(path, "GET", "/", "", "");
    EXPECT_EQ(200, liveness.status) << liveness.body;
    EXPECT_NE(std::string::npos, liveness.body.find("inventory_sync_server"))
        << "the liveness body must identify this module: " << liveness.body;

    // POST /stateful -- the REAL ingestion endpoint: garbage is rejected by the FlatBuffers
    // verifier with 400, which proves the route is wired to the validator (a stub would 202).
    // The full happy path is exercised in statefulEndpointE2E_test.cpp.
    EXPECT_EQ(400, sendModuleRequest(path, "POST", "/stateful", "not-a-flatbuffer", "007").status);

    // The provisional path is gone; nothing must answer there.
    EXPECT_EQ(404, sendModuleRequest(path, "POST", "/inventory/sync", "payload", "007").status);

    // POST /stats -- indexes for real and answers the protocol's empty acknowledgment.
    {
        const auto response = sendModuleRequest(path, "POST", "/stats", R"({"modules":{"agent":{"a":1}}})", "007");
        ASSERT_EQ(200, response.status) << "/stats -> " << response.body;
        EXPECT_EQ("{}", response.body);
    }

    // POST /config -- indexes for real too: a modules-keyed object in, a bare {} acknowledgment out.
    {
        const auto response = sendModuleRequest(path, "POST", "/config", R"({"modules":{"agent":{"cpu":42}}})", "007");
        ASSERT_EQ(200, response.status) << "/config -> " << response.body;
        EXPECT_EQ("{}", response.body);
    }

    // An unknown path is a 404, which proves routing is matching rather than answering everything.
    EXPECT_EQ(404, sendModuleRequest(path, "POST", "/nope", "x", "007").status);

    inventory_sync_server_stop();
}

/**
 * @brief An agent id that is not valid UTF-8 is rejected instead of crashing the serialization.
 *
 * The agent id is stamped into the document straight from the request header, and headers are raw
 * bytes -- nothing validates them as UTF-8. nlohmann only checks at dump() time, so this is the
 * reachable route into the serialization failure the endpoints' catch block exists for. It answers 400,
 * which is right here: unlike the cluster name (a manager-side value, sanitized at startup), a bad
 * agent id really is the caller's fault.
 */
TEST_F(InventorySyncServerModuleTest, AnAgentIdThatIsNotUtf8IsRejectedRatherThanBreakingSerialization)
{
    invsync::test::installAlwaysAvailableFakeIndexers();

    const auto path = uniqueSocketPath("badid");
    auto config = makeConfig(path);

    ASSERT_EQ(0, inventory_sync_server_start(testLogCallback, &config));
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("listening on"));

    const std::string invalidId = "00\xff"
                                  "7";
    // Each body must be valid for its endpoint's shape (a modules-keyed object for both /stats and
    // /config) so the request gets PAST body validation and actually reaches the id-embedding/
    // serialization step this test means to exercise -- an invalid body would already answer 400 on
    // its own, for the wrong reason.
    for (const auto& [target, body] : {std::pair {"/stats", std::string {R"({"modules":{"agent":{"a":1}}})"}},
                                       std::pair {"/config", std::string {R"({"modules":{"agent":{"cpu":42}}})"}}})
    {
        const auto response = sendModuleRequest(path, "POST", target, body, invalidId);
        EXPECT_EQ(400, response.status) << target << " must not answer 200 with an unserializable id";
    }

    // And the server is still serving afterwards.
    EXPECT_EQ(200, sendModuleRequest(path, "GET", "/", "", "").status);

    inventory_sync_server_stop();
}
