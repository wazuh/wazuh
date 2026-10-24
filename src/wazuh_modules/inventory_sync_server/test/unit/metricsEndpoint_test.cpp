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

#include <indexer_client/keyValueConfigSource.hpp>
#include <indexer_client/runtime.hpp>

#include "bulkResponder.hpp"
#include "fakeIndexer.hpp"
#include "healthRules.hpp"

#include <wazuh_metrics/manager.hpp>

#include <json.hpp>

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <memory>
#include <string>
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

// ---- The bucket's metrics through the module's real GET /metrics (CA-E7b-8) ---------------------------

namespace
{
    using namespace std::chrono_literals;

    constexpr auto BUCKET_PREFIX {"indexer_client.bucket.inventory_sync_server.inventory."};

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
 * With the real Client behind the module, GET /metrics publishes the 51 metrics of the `inventory`
 * bucket by pull, plus the sync.indexer.* totals read from the same bucket (I140): after one session
 * the bucket accepted its ops and `sync.indexer.bulk.requests` IS its `bulk_requests`. Each name is
 * registered once; a restart rebuilds the Client, so its counters read 0 again until traffic arrives.
 */
TEST(MetricsEndpointTest, PublishesBucketMetrics)
{
    indexer_client::testing::FakeIndexer fake;
    auto bulk = std::make_shared<indexer_client::testing::BulkResponder>();
    fake.addRule(indexer_client::testing::healthRule("green"));
    fake.addRule(indexer_client::testing::bulkRule(bulk));
    fake.start();

    const std::string text = "wazuh_modules.indexer_client_network_threads=1\n"
                             "wazuh_modules.indexer_client_cpu_threads=2\n"
                             "wazuh_modules.indexer_client_probe_interval_ms=200\n";
    auto source = indexer_client::KeyValueConfigSource::parse(
        text, "{\"hosts\":[\"" + fake.baseUrl() + "\"]}", indexer_client::Credentials {"a", "b"});
    auto started = indexer_client::RuntimeOwner::start(indexer_client::ProcessId::Modulesd, source.value);
    ASSERT_TRUE(started.ok()) << indexer_client::toString(started.cause) << ": " << started.reason;
    const indexer_client::RuntimeRef ref = started.value;

    // The module first, then the runtime it borrowed, then the factories -- also on an early return.
    struct Cleanup
    {
        ~Cleanup()
        {
            inventory_sync_server_stop();
            indexer_client::RuntimeOwner::beginShutdown(std::chrono::steady_clock::now() + 5s);
            indexer_client::RuntimeOwner::shutdown();
            invsync::test::resetIndexerConnectorFactoriesToProduction();
        }
    } cleanup;

    LogRecorder::clear();
    invsync::test::installFakeIndexersOverRealClient();
    const auto socketPath = wazuh::uds_http::test::uniqueSocketPath("bucketmetrics");
    const auto config = moduleConfig(socketPath, &ref);

    inventory_sync_server_start(invsync::test::testLogCallback, &config);
    const bool listening = LogRecorder::waitForMessageContaining("listening on");
    if (listening && postASession(socketPath))
    {
        const auto document = scrape(socketPath);
        ASSERT_TRUE(document.is_object());
        const auto accepted = reading(document, std::string {BUCKET_PREFIX} + "accepted");
        const auto bucketRequests = reading(document, std::string {BUCKET_PREFIX} + "bulk_requests");
        const auto syncRequests = reading(document, invsync::metrics::INDEXER_BULK_REQUESTS);
        EXPECT_EQ(1U, accepted.entries) << "the bucket's counters are registered once";
        EXPECT_GE(accepted.value, 1) << "the session's document was accepted by the bucket";
        EXPECT_GE(bucketRequests.value, 1);
        EXPECT_EQ(1U, syncRequests.entries);
        EXPECT_EQ(bucketRequests.value, syncRequests.value) << "sync.indexer.bulk.requests reads the bucket";

        // A restart builds a new Client: same names, one registration each, counters from 0.
        inventory_sync_server_stop();
        LogRecorder::clear();
        inventory_sync_server_start(invsync::test::testLogCallback, &config);
        if (LogRecorder::waitForMessageContaining("listening on"))
        {
            const auto fresh = scrape(socketPath);
            ASSERT_TRUE(fresh.is_object());
            const auto freshAccepted = reading(fresh, std::string {BUCKET_PREFIX} + "accepted");
            EXPECT_EQ(1U, freshAccepted.entries) << "a restart must not register the bucket's metrics again";
            EXPECT_EQ(0, freshAccepted.value) << "a rebuilt Client starts its counters from 0";
            EXPECT_EQ(1U, reading(fresh, invsync::metrics::INDEXER_BULK_REQUESTS).entries);

            EXPECT_TRUE(postASession(socketPath));
            // One scrape is one Client::metrics() call and the snapshot is served for up to 250 ms (I141b):
            // let the one taken by the scrape above expire.
            std::this_thread::sleep_for(400ms);
            const auto after = scrape(socketPath);
            ASSERT_TRUE(after.is_object());
            EXPECT_GE(reading(after, std::string {BUCKET_PREFIX} + "accepted").value, 1);
            EXPECT_EQ(reading(after, std::string {BUCKET_PREFIX} + "bulk_requests").value,
                      reading(after, invsync::metrics::INDEXER_BULK_REQUESTS).value);
        }
        else
        {
            ADD_FAILURE() << "the module did not come back after a restart";
        }
    }
    else
    {
        ADD_FAILURE() << (listening ? "no session was accepted (the indexer never looked available)"
                                    : "the module never started listening");
    }
}
