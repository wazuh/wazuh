/*
 * Wazuh remoted module - ScanVdHandlerImpl unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * August 10, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Exercises the synchronous admission passthrough against a real VdClient and a real
 * FakeVdServer (see fakeVdServer.hpp) standing in for VD's /offset and /scan endpoints. The
 * handler holds no state and every decision happens inline in handleVdScan's callback, so the
 * assertions are immediate -- there are no background workers left to synchronize with.
 */

#include "common/vdClient.hpp"
#include "fakeVdServer.hpp"
#include "scanvd/scanVdHandler.hpp"
#include "scanvd/scanVdMetrics.hpp"

#include <wazuh_metrics/manager.hpp>

#include <gtest/gtest.h>

#include <chrono>
#include <json.hpp>
#include <memory>
#include <string>

using namespace std::chrono_literals;
using remoted::common::VdClient;
using remoted::endpoints::scanvd::ScanVdOutcome;
using remoted::endpoints::scanvd::ScanVdResponse;
using remoted::scanvd::makeScanVdMetrics;
using remoted::scanvd::ScanVdHandlerImpl;
using remoted::scanvd::ScanVdMetrics;
using remoted::test::FakeVdServer;
using remoted::test::makeUniqueVdSocketPath;

namespace
{
    constexpr auto VDCLIENT_TTL = 30ms;
    constexpr auto VDCLIENT_FAILURE_RETRY = 30ms;

    ScanVdResponse callSync(ScanVdHandlerImpl& handler, uint32_t agentId, uint64_t offset)
    {
        ScanVdResponse result {};
        handler.handleVdScan(agentId, offset, [&result](const ScanVdResponse& r) { result = r; });
        return result;
    }

    /// One test's whole rig: fake VD + real VdClient + metrics + the handler under test.
    struct Rig
    {
        explicit Rig(const std::string& tag)
            : socketPath(makeUniqueVdSocketPath(tag))
            , server(socketPath)
            , vdClient(std::make_shared<VdClient>(socketPath, VDCLIENT_TTL, VDCLIENT_FAILURE_RETRY))
            , metrics(makeScanVdMetrics(metricsManager))
            , handler(vdClient, metrics, socketPath)
        {
            server.setOffset(100);
        }

        std::string socketPath;
        FakeVdServer server;
        std::shared_ptr<VdClient> vdClient;
        wazuh::metrics::Manager metricsManager;
        ScanVdMetrics metrics;
        ScanVdHandlerImpl handler;
    };
} // namespace

TEST(ScanVdHandlerTest, VersionMismatchRejectsWithoutEverTriggeringAScan)
{
    Rig rig {"mismatch"};

    const auto response = callSync(rig.handler, 42, 999);
    EXPECT_EQ(response.outcome, ScanVdOutcome::VersionMismatch);
    EXPECT_EQ(response.currentOffset, 100u);
    EXPECT_EQ(rig.server.scanRequestCount(), 0u) << "a mismatched offset must never reach VD's /scan endpoint";
    EXPECT_EQ(rig.metrics.versionMismatch->get(), 1u);
    EXPECT_EQ(rig.metrics.accepted->get(), 0u);
}

TEST(ScanVdHandlerTest, ZeroAgentIdIsRejectedAsInvalidAgent)
{
    Rig rig {"invalid"};

    const auto response = callSync(rig.handler, 0, 100);
    EXPECT_EQ(response.outcome, ScanVdOutcome::InvalidAgent);
    EXPECT_EQ(rig.server.scanRequestCount(), 0u);
    EXPECT_EQ(rig.metrics.invalidAgent->get(), 1u);
}

TEST(ScanVdHandlerTest, VdQueueingTheScanIsA200AndExactlyOnePost)
{
    Rig rig {"accepted"};
    // VD's contract after the redesign: /scan answers 200 {} at ADMISSION.
    rig.server.setScanHandler([](const httplib::Request&, httplib::Response& res)
                              { res.set_content("{}", "application/json"); });

    const auto response = callSync(rig.handler, 7, 100);
    EXPECT_EQ(response.outcome, ScanVdOutcome::Accepted);
    EXPECT_EQ(rig.server.scanRequestCount(), 1u) << "one request, one POST -- there is no retry machinery";
    EXPECT_EQ(rig.metrics.accepted->get(), 1u);

    // A second request for the same agent is ANOTHER honest passthrough (dedup, if any, is
    // VD's business): two requests, two POSTs.
    EXPECT_EQ(callSync(rig.handler, 7, 100).outcome, ScanVdOutcome::Accepted);
    EXPECT_EQ(rig.server.scanRequestCount(), 2u);
}

TEST(ScanVdHandlerTest, AVdCapacityRejectionPassesThroughAsQueueFull)
{
    Rig rig {"full"};
    rig.server.setScanHandler(
        [](const httplib::Request&, httplib::Response& res)
        {
            res.status = 503;
            res.set_content(R"({"error":"scan_queue_full","retryable":true})", "application/json");
        });

    const auto response = callSync(rig.handler, 7, 100);
    EXPECT_EQ(response.outcome, ScanVdOutcome::VdRejected);
    EXPECT_EQ(response.errorCode, "scan_queue_full") << "the agent-facing body carries VD's actual cause";
    EXPECT_EQ(rig.metrics.queueFull->get(), 1u) << "capacity rejections keep their own counter";
    EXPECT_EQ(rig.metrics.vdError->get(), 0u);
    EXPECT_EQ(rig.metrics.accepted->get(), 0u);
    EXPECT_EQ(rig.server.scanRequestCount(), 1u) << "no retry: the agent's next notify is the retry";
}

TEST(ScanVdHandlerTest, AVdIndexerOutageKeepsItsOwnCounterOffTheRelayWindow)
{
    Rig rig {"idxdown"};
    rig.server.setScanHandler(
        [](const httplib::Request&, httplib::Response& res)
        {
            res.status = 503;
            res.set_content(R"({"error":"indexer_unavailable","retryable":true})", "application/json");
        });

    const auto response = callSync(rig.handler, 7, 100);
    EXPECT_EQ(response.outcome, ScanVdOutcome::VdRejected);
    EXPECT_EQ(response.errorCode, "indexer_unavailable") << "the agent-facing body carries VD's actual cause";
    EXPECT_EQ(rig.metrics.indexerUnavailable->get(), 1u) << "VD's own reported cause keeps its own counter";
    EXPECT_EQ(rig.metrics.vdError->get(), 0u)
        << "an indexer outage must not masquerade as a remoted<->VD relay failure";
    EXPECT_EQ(rig.metrics.queueFull->get(), 0u);
}

TEST(ScanVdHandlerTest, AVdReadinessRejectionPassesItsCodeThrough)
{
    Rig rig {"notready"};
    rig.server.setScanHandler(
        [](const httplib::Request&, httplib::Response& res)
        {
            res.status = 503;
            res.set_content(R"({"error":"feed_not_ready","retryable":true})", "application/json");
        });

    const auto response = callSync(rig.handler, 7, 100);
    EXPECT_EQ(response.outcome, ScanVdOutcome::VdRejected);
    EXPECT_EQ(response.errorCode, "feed_not_ready");
    EXPECT_EQ(rig.metrics.vdError->get(), 1u) << "non-capacity rejections land on vd_error";
    EXPECT_EQ(rig.metrics.queueFull->get(), 0u);
}

TEST(ScanVdHandlerTest, AnUnreachableVdIsAnHonest503NotASilentDrop)
{
    const auto socketPath = makeUniqueVdSocketPath("unreachable");
    // A server only for /offset, torn down before the scan POST: the offset gate passes on the
    // cached value, then the POST hits a dead socket.
    auto server = std::make_unique<FakeVdServer>(socketPath);
    server->setOffset(100);

    auto vdClient = std::make_shared<VdClient>(socketPath, 5s, VDCLIENT_FAILURE_RETRY);
    ASSERT_EQ(vdClient->getOffset(), 100u) << "prime the cache while the server is up";

    wazuh::metrics::Manager metricsManager;
    ScanVdMetrics metrics {makeScanVdMetrics(metricsManager)};
    ScanVdHandlerImpl handler(vdClient, metrics, socketPath);

    server.reset(); // VD goes away

    ScanVdResponse response {};
    handler.handleVdScan(7, 100, [&response](const ScanVdResponse& r) { response = r; });
    EXPECT_EQ(response.outcome, ScanVdOutcome::VdRejected);
    EXPECT_EQ(response.errorCode, "vd_unreachable");
    EXPECT_EQ(metrics.vdError->get(), 1u);
}

TEST(ScanVdHandlerTest, AnUnexpectedVdStatusMapsToVdError)
{
    Rig rig {"weird"};
    rig.server.setScanHandler(
        [](const httplib::Request&, httplib::Response& res)
        {
            res.status = 500;
            res.set_content("not json at all", "text/plain");
        });

    const auto response = callSync(rig.handler, 7, 100);
    EXPECT_EQ(response.outcome, ScanVdOutcome::VdRejected);
    EXPECT_EQ(response.errorCode, "vd_error") << "an unparseable body degrades to the generic code";
    EXPECT_EQ(rig.metrics.vdError->get(), 1u);
}

TEST(ScanVdHandlerTest, TheScanPostCarriesTheAgentIdAsAString)
{
    Rig rig {"body"};
    std::string capturedBody;
    rig.server.setScanHandler(
        [&capturedBody](const httplib::Request& req, httplib::Response& res)
        {
            capturedBody = req.body;
            res.set_content("{}", "application/json");
        });

    ASSERT_EQ(callSync(rig.handler, 42, 100).outcome, ScanVdOutcome::Accepted);
    const auto json = nlohmann::json::parse(capturedBody);
    EXPECT_EQ(json.value("agent_id", std::string {}), "42")
        << "VD's route expects the id as a JSON string -- the wire shape is part of the contract";
}
