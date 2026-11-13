/*
 * Wazuh inventory sync server module - unit tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// Unit-tests the GET /metrics route policy (D18): the pinned contract (verb/path), the JSON dump
// of a populated registry, and the 503 when the manager is gone.
#include "endpoints/metricsEndpoint.hpp"

#include "common/metricNames.hpp"
#include "indexer/indexerClientSyncAdapter.hpp"
#include "inventorySyncServerTestHooks.hpp"
#include "inventory_sync_server.h"
#include "testIndexerConnectorFakes.hpp"
#include "testLogRecorder.hpp"
#include "testSessionBuilder.hpp"
#include "udsTestClient.hpp"

#include "testRealIndexer.hpp"

#include <indexer_client/metrics.hpp>
#include <indexer_client/runtime.hpp>

#include <wazuh_metrics/manager.hpp>

#include <json.hpp>

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

using invsync::test::LogRecorder;
using wazuh::uds_http::HttpRequest;
using wazuh::uds_http::HttpResponse;
using wazuh::uds_http::IHttpResponder;
namespace metrics_endpoint = invsync::endpoints::metrics;

namespace
{
    class CapturingResponder final : public IHttpResponder
    {
    public:
        void send(HttpResponse response) override
        {
            m_response = std::move(response);
            m_sent = true;
        }

        bool sent() const
        {
            return m_sent;
        }

        const HttpResponse& response() const
        {
            return m_response;
        }

    private:
        HttpResponse m_response {0, "", {}};
        bool m_sent {false};
    };

    std::shared_ptr<const HttpRequest> makeRequest()
    {
        auto request = std::make_shared<HttpRequest>();
        request->method = metrics_endpoint::method();
        request->target = metrics_endpoint::path();
        return request;
    }
} // namespace

TEST(MetricsEndpointTest, ContractIsPinned)
{
    // The facade registers exactly this; a silent drift breaks operators' curl one-liners.
    EXPECT_EQ(wazuh::uds_http::Method::Get, metrics_endpoint::method());
    EXPECT_STREQ("/metrics", metrics_endpoint::path());
}

TEST(MetricsEndpointTest, DumpsThePopulatedRegistry)
{
    const auto manager = std::make_shared<wazuh::metrics::Manager>();
    manager->getOrCreateCounter(invsync::metrics::BULK_FLUSHES, "Group-commit flushes", "count")->add(7);
    manager->getOrCreateHistogram(invsync::metrics::VD_SCAN_DURATION)->observe(1000);

    const auto handler = metrics_endpoint::makeHandler(manager);
    const auto responder = std::make_shared<CapturingResponder>();
    handler(makeRequest(), responder);

    ASSERT_TRUE(responder->sent());
    EXPECT_EQ(200, responder->response().status);

    const auto document = nlohmann::json::parse(responder->response().body);
    EXPECT_EQ("inventory_sync_server", document.at("name").get<std::string>());
    ASSERT_TRUE(document.at("metrics").is_array());

    bool sawFlushes {false};
    bool sawScanDuration {false};
    for (const auto& entry : document.at("metrics"))
    {
        if (entry.at("name") == invsync::metrics::BULK_FLUSHES)
        {
            sawFlushes = true;
            EXPECT_EQ("counter", entry.at("type").get<std::string>());
            EXPECT_EQ(7, entry.at("value").get<int>());
            EXPECT_EQ("count", entry.at("unit").get<std::string>());
        }
        if (entry.at("name") == invsync::metrics::VD_SCAN_DURATION)
        {
            sawScanDuration = true;
            EXPECT_EQ("histogram", entry.at("type").get<std::string>());
            EXPECT_EQ(1, entry.at("summary").at("count").get<int>());
        }
    }
    EXPECT_TRUE(sawFlushes);
    EXPECT_TRUE(sawScanDuration);
}

TEST(MetricsEndpointTest, AnswersServiceUnavailableWhenTheManagerIsGone)
{
    wazuh::uds_http::RouteHandler handler;
    {
        const auto manager = std::make_shared<wazuh::metrics::Manager>();
        handler = metrics_endpoint::makeHandler(manager);
    } // the weak capture expires here

    const auto responder = std::make_shared<CapturingResponder>();
    handler(makeRequest(), responder);

    ASSERT_TRUE(responder->sent());
    EXPECT_EQ(503, responder->response().status);
}

// ---- The buckets' metrics through the module's real GET /metrics ---------------------------

namespace
{
    using namespace std::chrono_literals;

    // The exact prefixes: the bucket name `agent-state` is published sanitized, as `agent_state`.
    constexpr auto BUCKET_PREFIX {"indexer_client.bucket.inventory_sync_server.inventory."};
    constexpr auto AGENT_STATE_PREFIX {"indexer_client.bucket.inventory_sync_server.agent_state."};

    /// The first `value` of the metric named @p name in a /metrics document, and how many entries carry it.
    struct Reading
    {
        std::size_t entries {0};
        double value {0};
    };

    Reading reading(const nlohmann::json& document, const std::string& name)
    {
        Reading result;
        for (const auto& entry : document.at("metrics"))
        {
            if (entry.at("name") == name)
            {
                if (result.entries++ == 0)
                {
                    result.value = entry.at("value").get<double>();
                }
            }
        }
        return result;
    }

    std::string statefulRequest(const std::string& body)
    {
        return "POST /stateful HTTP/1.1\r\nHost: localhost\r\nX-Wazuh-Agent-Id: 001\r\n"
               "Content-Type: application/octet-stream\r\nContent-Length: " +
               std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
    }

    nlohmann::json scrape(const std::string& socketPath)
    {
        const auto response = wazuh::uds_http::test::sendRaw(
            socketPath, "GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        EXPECT_EQ(200, response.status) << response.body;
        return nlohmann::json::parse(response.body, nullptr, false);
    }

    /// One /stateful session of one document; retried while the first health probe has not landed yet
    /// (until a node is Available the connector answers 503).
    bool postASession(const std::string& socketPath)
    {
        const auto body =
            invsync::test::buildSyncDataSession(invsync::test::SessionSpec {}, {invsync::test::ValueSpec {}});
        const auto deadline = std::chrono::steady_clock::now() + 10s;
        while (std::chrono::steady_clock::now() < deadline)
        {
            if (wazuh::uds_http::test::sendRaw(socketPath, statefulRequest(body)).status == 200)
            {
                return true;
            }
            std::this_thread::sleep_for(100ms);
        }
        return false;
    }

    /// POST /stats of agent 001 (the `agent-state` bucket's write route) and an agent deletion, over the real socket.
    int postStats(const std::string& socketPath)
    {
        const std::string body = R"({"modules":{"agent":{"messages":{"count":1}}}})";
        return wazuh::uds_http::test::sendRaw(socketPath,
                                              "POST /stats HTTP/1.1\r\nHost: localhost\r\nX-Wazuh-Agent-Id: 001\r\n"
                                              "Content-Type: application/json\r\nContent-Length: " +
                                                  std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body)
            .status;
    }

    int deleteAgent(const std::string& socketPath, const std::string& agentId)
    {
        const std::string body = "{\"agent_id\":\"" + agentId + "\"}";
        return wazuh::uds_http::test::sendRaw(
                   socketPath,
                   "POST /_internal/agents/delete HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n"
                   "Content-Length: " +
                       std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body)
            .status;
    }

    /// How many entries of a /metrics document start with @p prefix.
    std::size_t entriesWithPrefix(const nlohmann::json& document, const std::string& prefix)
    {
        std::size_t count {0};
        for (const auto& entry : document.at("metrics"))
        {
            count += entry.at("name").get<std::string>().rfind(prefix, 0) == 0 ? 1 : 0;
        }
        return count;
    }

    inventory_sync_server_config_t moduleConfig(const std::string& socketPath, const void* runtime)
    {
        inventory_sync_server_config_t config {};
        std::snprintf(config.cluster_name, sizeof(config.cluster_name), "%s", "test-cluster");
        std::snprintf(config.socket_path, sizeof(config.socket_path), "%s", socketPath.c_str());
        config.io_threads = 1;
        config.drain_timeout = 1;
        config.sync_workers = 1;
        config.vd_workers = 1;
        config.indexer_runtime = runtime;
        return config;
    }
} // namespace

/**
 * With the real Client behind the module, GET /metrics publishes the 52 metrics of EACH of the two buckets by
 * pull -- `inventory` and `agent-state`, under the exact prefixes `indexer_client.bucket.inventory_sync_server.
 * {inventory,agent_state}.` -- plus the sync.indexer.* totals read from the `inventory` bucket: after one
 * session, one /stats and one deletion each bucket accepted its ops and `sync.indexer.bulk.requests` IS the
 * `inventory` bucket's `bulk_requests`. Each name is registered once; a restart rebuilds the Client, so its
 * counters read 0 again until traffic arrives, and nothing registers twice.
 */
TEST(MetricsEndpointTest, PublishesBothBuckets)
{
    invsync::test::RealIndexer real;
    real.startRuntime();
    ASSERT_TRUE(real.runtimeStarted) << real.startError;
    const indexer_client::RuntimeRef ref = real.ref;

    // The module first, then the factories -- also on an early return; the runtime goes with `real`.
    struct Cleanup
    {
        ~Cleanup()
        {
            inventory_sync_server_stop();
            invsync::test::resetIndexerConnectorFactoriesToProduction();
        }
    } cleanup;

    LogRecorder::clear();
    invsync::test::installFakeIndexersOverRealClient();
    const auto socketPath = wazuh::uds_http::test::uniqueSocketPath("bucketmetrics");
    const auto config = moduleConfig(socketPath, &ref);

    inventory_sync_server_start(invsync::test::testLogCallback, &config);
    const bool listening = LogRecorder::waitForMessageContaining("listening on");
    ASSERT_TRUE(listening) << "the module never started listening";
    ASSERT_TRUE(postASession(socketPath)) << "no session was accepted (the indexer never looked available)";
    EXPECT_EQ(200, postStats(socketPath));
    EXPECT_EQ(200, deleteAgent(socketPath, "7"));

    // One scrape is one Client::metrics() call and the snapshot is served for up to 250 ms.
    std::this_thread::sleep_for(400ms);
    const auto document = scrape(socketPath);
    ASSERT_TRUE(document.is_object());

    const auto accepted = reading(document, std::string {BUCKET_PREFIX} + "accepted");
    const auto bucketRequests = reading(document, std::string {BUCKET_PREFIX} + "bulk_requests");
    const auto syncRequests = reading(document, invsync::metrics::INDEXER_BULK_REQUESTS);
    EXPECT_EQ(1U, accepted.entries) << "the inventory bucket's counters are registered once";
    EXPECT_GE(accepted.value, 1) << "the session's document was accepted by the bucket";
    EXPECT_GE(bucketRequests.value, 1);
    EXPECT_EQ(1U, syncRequests.entries);
    EXPECT_EQ(bucketRequests.value, syncRequests.value) << "sync.indexer.bulk.requests reads the inventory bucket";

    const auto agentAccepted = reading(document, std::string {AGENT_STATE_PREFIX} + "accepted");
    EXPECT_EQ(1U, agentAccepted.entries) << "the agent-state bucket's counters are registered once";
    EXPECT_GE(agentAccepted.value, 3) << "the /stats document and the two by-id deletes were accepted";
    EXPECT_EQ(entriesWithPrefix(document, BUCKET_PREFIX), entriesWithPrefix(document, AGENT_STATE_PREFIX))
        << "the same catalog under each bucket's own prefix";
    EXPECT_GT(entriesWithPrefix(document, AGENT_STATE_PREFIX), 0U);
    EXPECT_EQ(0U, entriesWithPrefix(document, "indexer_client.bucket.inventory_sync_server.agent-state."))
        << "the bucket name is published sanitized";

    // A restart builds a new Client: same names, one registration each, counters from 0.
    inventory_sync_server_stop();
    LogRecorder::clear();
    inventory_sync_server_start(invsync::test::testLogCallback, &config);
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("listening on"))
        << "the module did not come back after a restart";
    const auto fresh = scrape(socketPath);
    ASSERT_TRUE(fresh.is_object());
    EXPECT_EQ(1U, reading(fresh, std::string {BUCKET_PREFIX} + "accepted").entries)
        << "a restart must not register the inventory bucket's metrics again";
    EXPECT_EQ(1U, reading(fresh, std::string {AGENT_STATE_PREFIX} + "accepted").entries)
        << "a restart must not register the agent-state bucket's metrics again";
    EXPECT_EQ(0, reading(fresh, std::string {BUCKET_PREFIX} + "accepted").value)
        << "a rebuilt Client starts its counters from 0";
    EXPECT_EQ(0, reading(fresh, std::string {AGENT_STATE_PREFIX} + "accepted").value);
    EXPECT_EQ(1U, reading(fresh, invsync::metrics::INDEXER_BULK_REQUESTS).entries);

    EXPECT_TRUE(postASession(socketPath));
    EXPECT_EQ(200, postStats(socketPath));
    std::this_thread::sleep_for(400ms);
    const auto after = scrape(socketPath);
    ASSERT_TRUE(after.is_object());
    EXPECT_GE(reading(after, std::string {BUCKET_PREFIX} + "accepted").value, 1);
    EXPECT_GE(reading(after, std::string {AGENT_STATE_PREFIX} + "accepted").value, 1);
    EXPECT_EQ(reading(after, std::string {BUCKET_PREFIX} + "bulk_requests").value,
              reading(after, invsync::metrics::INDEXER_BULK_REQUESTS).value);
}

/**
 * The post-deletion sweeper's five counters are published by pull under their frozen names, once each, after a
 * deletion and across a stop + start (the sweeper is rebuilt; the registrations are not).
 */
TEST(MetricsEndpointTest, PublishesSweep)
{
    invsync::test::RealIndexer real;
    real.startRuntime();
    ASSERT_TRUE(real.runtimeStarted) << real.startError;
    const indexer_client::RuntimeRef ref = real.ref;

    struct Cleanup
    {
        ~Cleanup()
        {
            inventory_sync_server_stop();
            invsync::test::resetIndexerConnectorFactoriesToProduction();
        }
    } cleanup;

    LogRecorder::clear();
    invsync::test::installFakeIndexersOverRealClient();
    const auto socketPath = wazuh::uds_http::test::uniqueSocketPath("sweepmetrics");
    const auto config = moduleConfig(socketPath, &ref);

    const std::vector<std::string> names {invsync::metrics::AGENT_DELETE_SWEEP_RUNS,
                                          invsync::metrics::AGENT_DELETE_SWEEP_FAILURES,
                                          invsync::metrics::AGENT_DELETE_SWEEP_RESIDUAL,
                                          invsync::metrics::AGENT_DELETE_SWEEP_DROPPED,
                                          invsync::metrics::AGENT_DELETE_SWEEP_FORGOTTEN};
    EXPECT_EQ(std::vector<std::string>({"sync.agent_delete.sweep.runs",
                                        "sync.agent_delete.sweep.failures",
                                        "sync.agent_delete.sweep.residual",
                                        "sync.agent_delete.sweep.dropped",
                                        "sync.agent_delete.sweep.forgotten"}),
              names)
        << "the names are frozen";

    inventory_sync_server_start(invsync::test::testLogCallback, &config);
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("listening on"));
    ASSERT_TRUE(postASession(socketPath));
    ASSERT_EQ(200, deleteAgent(socketPath, "7"));

    const auto document = scrape(socketPath);
    ASSERT_TRUE(document.is_object());
    for (const auto& name : names)
    {
        EXPECT_EQ(1U, reading(document, name).entries) << name;
        EXPECT_EQ(0, reading(document, name).value) << name << ": nothing is due inside the first window";
    }

    inventory_sync_server_stop();
    LogRecorder::clear();
    inventory_sync_server_start(invsync::test::testLogCallback, &config);
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("listening on"));
    const auto fresh = scrape(socketPath);
    ASSERT_TRUE(fresh.is_object());
    for (const auto& name : names)
    {
        EXPECT_EQ(1U, reading(fresh, name).entries) << name << " must be registered once across a restart";
    }
}

/**
 * The /stats route is wired to the sweeper: a report accepted for an agent whose deletion just completed withdraws it
 * from the pending sweep, and the withdrawal shows in `sync.agent_delete.sweep.forgotten`. A report of an agent with no
 * pending sweep withdraws nothing.
 */
TEST(MetricsEndpointTest, ReportOfDeletedIdWithdrawsItsSweep)
{
    invsync::test::RealIndexer real;
    real.startRuntime();
    ASSERT_TRUE(real.runtimeStarted) << real.startError;
    const indexer_client::RuntimeRef ref = real.ref;

    struct Cleanup
    {
        ~Cleanup()
        {
            inventory_sync_server_stop();
            invsync::test::resetIndexerConnectorFactoriesToProduction();
        }
    } cleanup;

    LogRecorder::clear();
    invsync::test::installFakeIndexersOverRealClient();
    const auto socketPath = wazuh::uds_http::test::uniqueSocketPath("sweepforget");
    const auto config = moduleConfig(socketPath, &ref);

    inventory_sync_server_start(invsync::test::testLogCallback, &config);
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("listening on"));
    ASSERT_TRUE(postASession(socketPath));

    EXPECT_EQ(200, postStats(socketPath)); // Agent 001, nothing pending yet.
    EXPECT_EQ(0, reading(scrape(socketPath), invsync::metrics::AGENT_DELETE_SWEEP_FORGOTTEN).value);

    ASSERT_EQ(200, deleteAgent(socketPath, "1")); // Noted as "001", swept no sooner than a window later.
    EXPECT_EQ(200, postStats(socketPath));        // The same id reports again: the new agent's document.

    const auto document = scrape(socketPath);
    ASSERT_TRUE(document.is_object());
    EXPECT_EQ(1, reading(document, invsync::metrics::AGENT_DELETE_SWEEP_FORGOTTEN).value);
    EXPECT_EQ(0, reading(document, invsync::metrics::AGENT_DELETE_SWEEP_RUNS).value);
}

namespace
{
    /// The process-wide families of the catalog (RuntimeRef::snapshot()), which only this module publishes.
    std::vector<std::string> processNames(const indexer_client::RuntimeRef& ref)
    {
        std::vector<std::string> names;
        indexer_client::forEachMetric(ref.snapshot(),
                                      [&names](std::string_view name, indexer_client::MetricKind, double)
                                      { names.emplace_back(name); });
        return names;
    }

    std::size_t processEntries(const nlohmann::json& document)
    {
        return entriesWithPrefix(document, invsync::metrics::INDEXER_CLIENT_RUNTIME_PREFIX) +
               entriesWithPrefix(document, invsync::metrics::INDEXER_CLIENT_NODE_PREFIX) +
               entriesWithPrefix(document, invsync::metrics::INDEXER_CLIENT_QUERY_PREFIX) +
               entriesWithPrefix(document, invsync::metrics::INDEXER_CLIENT_PIT_PREFIX);
    }
} // namespace

/**
 * GET /metrics publishes the process's runtime -- `indexer_client.{runtime,query,pit}.*` and
 * `indexer_client.node.<i>.*`
 * -- once each, read from RuntimeRef::snapshot() and not from the Client: with the real Client, and with a
 * Client that publishes nothing of its own (the snapshot is taken before the no-Client early return), and across a
 * restart without registering anything twice. The node family is the runtime's one host, `node.0`.
 */
TEST(MetricsEndpointTest, PublishesProcessOnce)
{
    invsync::test::RealIndexer real;
    real.startRuntime();
    ASSERT_TRUE(real.runtimeStarted) << real.startError;
    const indexer_client::RuntimeRef ref = real.ref;

    struct Cleanup
    {
        ~Cleanup()
        {
            inventory_sync_server_stop();
            invsync::test::resetIndexerConnectorFactoriesToProduction();
        }
    } cleanup;

    const auto names = processNames(ref);
    ASSERT_FALSE(names.empty());
    const auto expectProcess = [&names](const nlohmann::json& document, const std::string& when)
    {
        for (const auto& name : names)
        {
            EXPECT_EQ(1U, reading(document, name).entries) << name << " (" << when << ")";
        }
        EXPECT_EQ(names.size(), processEntries(document)) << "nothing else under the process prefixes (" << when << ")";
        EXPECT_EQ(1, reading(document, "indexer_client.runtime.network_threads").value) << when;
        EXPECT_EQ(2, reading(document, "indexer_client.runtime.cpu_threads").value) << when;
        EXPECT_GT(entriesWithPrefix(document, "indexer_client.node.0."), 0U) << when;
        EXPECT_EQ(0U, entriesWithPrefix(document, "indexer_client.node.1.")) << "one host, one node (" << when << ")";
        EXPECT_EQ(0U, entriesWithPrefix(document, "indexer_client.client.")) << when;
        EXPECT_EQ(0U, entriesWithPrefix(document, "indexer_client.bucket.vulnerability_scanner."))
            << "VD's bucket is VD's to publish (" << when << ")";
    };

    // The real Client.
    LogRecorder::clear();
    invsync::test::installFakeIndexersOverRealClient();
    const auto socketPath = wazuh::uds_http::test::uniqueSocketPath("processmetrics");
    const auto config = moduleConfig(socketPath, &ref);
    inventory_sync_server_start(invsync::test::testLogCallback, &config);
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("listening on"));
    const auto document = scrape(socketPath);
    ASSERT_TRUE(document.is_object());
    expectProcess(document, "real client");

    // A Client with no metrics of its own (the fake answers an empty ClientMetrics): the process's values are
    // still there, from the snapshot, and the buckets read 0.
    inventory_sync_server_stop();
    LogRecorder::clear();
    invsync::test::installAlwaysAvailableFakeIndexers();
    inventory_sync_server_start(invsync::test::testLogCallback, &config);
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("listening on"));
    std::this_thread::sleep_for(300ms); // past the 250 ms the slot serves a snapshot for
    const auto noClient = scrape(socketPath);
    ASSERT_TRUE(noClient.is_object());
    expectProcess(noClient, "no client metrics, after a restart");
    EXPECT_EQ(0, reading(noClient, std::string {BUCKET_PREFIX} + "quota_bytes").value);
    EXPECT_EQ(ref.snapshot().queries.conflictRetries,
              static_cast<std::uint64_t>(reading(noClient, invsync::metrics::INDEXER_CONFLICT_RETRIES).value))
        << "sync.indexer.conflict.retries is process-wide too";
}
