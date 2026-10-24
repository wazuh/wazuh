/*
 * Wazuh inventory sync server module - unit tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "inventorySyncServerTestHooks.hpp"
#include "inventory_sync_server.h"

#include "testIndexerConnectorFakes.hpp"
#include "testLogRecorder.hpp"
#include "testRealIndexer.hpp"
#include "testSessionBuilder.hpp"
#include "udsTestClient.hpp"

#include "hashHelper.h"
#include "wazuhCommon.hpp"

#include <gtest/gtest.h>
#include <json.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <string>
#include <thread>
#include <tuple>
#include <unistd.h>
#include <vector>

/*
 * The minimal end-to-end QA of POST /stateful over the module's OWN socket (design doc 12, F2
 * acceptance): every contract code -- 200 (ok and no-op), 400, 403, 404, 409, 413 and the VD
 * 503 + Retry-After -- produced by real HTTP against the real facade wiring, with only the indexer
 * faked.
 */

using invsync::test::LogRecorder;
using invsync::test::SessionSpec;
using invsync::test::testLogCallback;
using invsync::test::ValueSpec;

namespace
{
    std::string uniqueSocketPath(const char* tag)
    {
        static std::atomic<int> counter {0};
        return "/tmp/isse2e_" + std::string {tag} + "_" + std::to_string(::getpid()) + "_" +
               std::to_string(counter.fetch_add(1)) + ".sock";
    }

    inventory_sync_server_config_t makeConfig(const std::string& socketPath)
    {
        inventory_sync_server_config_t config {};
        std::snprintf(config.cluster_name, sizeof(config.cluster_name), "%s", "test-cluster");
        std::snprintf(config.socket_path, sizeof(config.socket_path), "%s", socketPath.c_str());
        config.io_threads = 1;
        config.drain_timeout = 1;
        config.sync_workers = 1;
        config.vd_feed_retry_after_seconds = 77;
        return config;
    }

    /// POST with the authenticated-agent header remoted would set. peerRequest() has no headers
    /// parameter, so the head is assembled here, matching the peer's wire shape.
    std::string statefulRequest(const std::string& body, const std::string& agentId = "001")
    {
        std::string request = "POST /stateful HTTP/1.1\r\nHost: localhost\r\n";
        if (!agentId.empty())
        {
            request += "X-Wazuh-Agent-Id: " + agentId + "\r\n";
        }
        request += "Content-Type: application/octet-stream\r\nContent-Length: " + std::to_string(body.size()) +
                   "\r\nConnection: close\r\n\r\n" + body;
        return request;
    }

    std::string expectedSha1Hex(const std::string& concatenated)
    {
        Utils::HashData hash(Utils::HashType::Sha1);
        hash.update(concatenated.c_str(), concatenated.length());
        const auto digest {hash.hash()};
        return wazuh::hex_encode(digest.data(), digest.size());
    }
} // namespace

class StatefulEndpointE2ETest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        LogRecorder::clear();
        m_events = invsync::test::installAlwaysAvailableFakeIndexers();
        m_path = uniqueSocketPath("stateful");
        const auto config = makeConfig(m_path);
        ASSERT_EQ(0, inventory_sync_server_start(testLogCallback, &config));
        ASSERT_TRUE(LogRecorder::waitForMessageContaining("listening on"));
    }

    void TearDown() override
    {
        inventory_sync_server_stop();
        invsync::test::resetIndexerConnectorFactoriesToProduction();
    }

    std::shared_ptr<invsync::test::ConnectorEvents> m_events;
    std::string m_path;
};

TEST_F(StatefulEndpointE2ETest, AValidDeltaIsAppliedFlushedAndAnswered200)
{
    const auto body = invsync::test::buildSyncDataSession(SessionSpec {}, {invsync::test::ValueSpec {}});
    const auto response = wazuh::uds_http::test::sendRaw(m_path, statefulRequest(body));

    EXPECT_EQ(200, response.status) << response.body;
    EXPECT_EQ(R"({"status":"ok"})", response.body);

    const auto ops = m_events->syncOps();
    ASSERT_EQ(1U, ops.size());
    EXPECT_EQ("bulkIndex", std::get<0>(ops[0]));
    EXPECT_EQ("test-cluster_001_doc-1", std::get<1>(ops[0]));
    EXPECT_EQ(1, m_events->m_syncFlushes.load()) << "the 200 must mean flushed, not just staged";
}

TEST_F(StatefulEndpointE2ETest, AnAllSkippedSessionAnswersNoOp)
{
    ValueSpec outside;
    outside.index = "alerts";
    const auto body = invsync::test::buildSyncDataSession(SessionSpec {}, {outside});
    const auto response = wazuh::uds_http::test::sendRaw(m_path, statefulRequest(body));

    EXPECT_EQ(200, response.status);
    EXPECT_EQ(R"({"status":"ok","noop":true})", response.body);
    EXPECT_TRUE(m_events->syncOps().empty());
}

TEST_F(StatefulEndpointE2ETest, CleansReachTheIndexerAsDeleteByQuery)
{
    const auto body = invsync::test::buildCleansSession(SessionSpec {}, {"wazuh-states-fim-files"});
    const auto response = wazuh::uds_http::test::sendRaw(m_path, statefulRequest(body));

    EXPECT_EQ(200, response.status) << response.body;
    const auto ops = m_events->syncOps();
    ASSERT_EQ(1U, ops.size());
    EXPECT_EQ("deleteByQuery", std::get<0>(ops[0]));
    EXPECT_EQ("wazuh-states-fim-files", std::get<2>(ops[0]));
}

TEST_F(StatefulEndpointE2ETest, ChecksumVerificationAnswers200OnMatchAnd409OnMismatch)
{
    nlohmann::json hit;
    hit["_source"]["checksum"]["hash"]["sha1"] = "abc123";
    hit["sort"] = nlohmann::json::array({"abc123"});
    nlohmann::json page;
    page["hits"]["hits"] = nlohmann::json::array({hit});
    {
        std::lock_guard<std::mutex> lock(m_events->m_mutex);
        m_events->m_searchResponse = page;
    }

    SessionSpec spec;
    spec.mode = invsync::test::fb::Mode_ModuleCheck;

    const auto match =
        wazuh::uds_http::test::sendRaw(m_path,
                                       statefulRequest(invsync::test::buildChecksumSession(
                                           spec, "wazuh-states-inventory-packages", expectedSha1Hex("abc123"))));
    EXPECT_EQ(200, match.status) << match.body;

    const auto mismatch = wazuh::uds_http::test::sendRaw(
        m_path,
        statefulRequest(invsync::test::buildChecksumSession(spec, "wazuh-states-inventory-packages", "deadbeef")));
    EXPECT_EQ(409, mismatch.status);
    EXPECT_EQ(R"({"status":"checksum_mismatch"})", mismatch.body);
}

TEST_F(StatefulEndpointE2ETest, AMetadataSessionRunsItsUpdateByQuery)
{
    SessionSpec spec;
    spec.mode = invsync::test::fb::Mode_MetadataDelta;
    const auto response =
        wazuh::uds_http::test::sendRaw(m_path, statefulRequest(invsync::test::buildBareSession(spec)));

    EXPECT_EQ(200, response.status) << response.body;
    const auto ops = m_events->syncOps();
    ASSERT_EQ(1U, ops.size());
    EXPECT_EQ("executeUpdateByQuery", std::get<0>(ops[0]));
}

TEST_F(StatefulEndpointE2ETest, GarbageIs400AndAForeignIdentityIs403)
{
    EXPECT_EQ(400, wazuh::uds_http::test::sendRaw(m_path, statefulRequest("junk")).status);

    const auto body = invsync::test::buildSyncDataSession(SessionSpec {}, {invsync::test::ValueSpec {}});
    const auto spoofed = wazuh::uds_http::test::sendRaw(m_path, statefulRequest(body, "042"));
    EXPECT_EQ(403, spoofed.status);
    EXPECT_NE(std::string::npos, spoofed.body.find("identity mismatch"));
    EXPECT_TRUE(m_events->syncOps().empty()) << "rejections must never reach the indexer";
}

TEST_F(StatefulEndpointE2ETest, AVDSessionWithTheScannerDisabledIndexesAndAnswers200)
{
    // The PRODUCTION scanner adapter against an uninitialized vulnerability scanner (this test
    // process never starts it): the D22 legitimate-skip row -- the scan is skipped, the inventory
    // still lands, the agent gets its 200.
    SessionSpec spec;
    spec.option = invsync::test::fb::Option_VDSync;
    const auto body = invsync::test::buildSyncDataSession(spec, {invsync::test::ValueSpec {}});
    const auto response = wazuh::uds_http::test::sendRaw(m_path, statefulRequest(body));

    EXPECT_EQ(200, response.status) << response.body;
    const auto ops = m_events->syncOps();
    ASSERT_EQ(1U, ops.size());
    EXPECT_EQ("bulkIndex", std::get<0>(ops[0]));
    EXPECT_EQ(1, m_events->m_syncFlushes.load());
}

TEST_F(StatefulEndpointE2ETest, VdConfiguredEnabledFromConfigReachesTheScannerFactory)
{
    // Pins the chain a silent regression could otherwise revert while every other test stays
    // green: inventory_sync_server_config_t::vd_configured_enabled -> the facade's Phase-A
    // snapshot -> scannerFactory(vdConfiguredEnabled) -> VdScannerAdapter::m_configuredEnabled.
    inventory_sync_server_stop();
    LogRecorder::clear();

    invsync::test::installFakeVdScanner(m_events);

    const auto path = uniqueSocketPath("vdconfigured");
    auto config = makeConfig(path);
    config.vd_configured_enabled = true;
    ASSERT_EQ(0, inventory_sync_server_start(testLogCallback, &config));
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("listening on"));

    EXPECT_TRUE(m_events->m_vdConfiguredEnabled.load());
}

TEST_F(StatefulEndpointE2ETest, AVDSessionWhileTheFeedDownloadsIsRefusedWithRetryAfter)
{
    // Same wiring, FAKE scanner reporting "feed not ready" (D17): rejected without processing.
    inventory_sync_server_stop();
    LogRecorder::clear();

    invsync::test::installFakeVdScanner(m_events);
    m_events->m_vdFeedReady.store(false);

    const auto path = uniqueSocketPath("vdfeed");
    const auto config = makeConfig(path);
    ASSERT_EQ(0, inventory_sync_server_start(testLogCallback, &config));
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("listening on"));

    SessionSpec spec;
    spec.option = invsync::test::fb::Option_VDSync;
    const auto body = invsync::test::buildSyncDataSession(spec, {invsync::test::ValueSpec {}});
    const auto response = wazuh::uds_http::test::sendRaw(path, statefulRequest(body));

    EXPECT_EQ(503, response.status);
    ASSERT_TRUE(response.hasHeader("Retry-After")) << response.raw;
    EXPECT_EQ("77", response.header("Retry-After")) << "the configured value must reach the wire";
    EXPECT_TRUE(m_events->syncOps().empty());
}

/**
 * The offset gate over the REAL wire (design doc's /scan/vd version check, mirrored here for
 * VDFirst/VDSync sessions -- see vdScanLane.cpp's comment right above the check). This is what
 * vdScanLane_test.cpp already covers by calling VdScanLane::tryEnqueue() directly in C++; this
 * pair instead sends a real flatbuffer-encoded session over the real UDS socket through the real
 * facade/routing/decode stack, so a wire-format or routing regression would show up here even if
 * the direct-call unit tests still passed.
 */
TEST_F(StatefulEndpointE2ETest, AVDSessionWithMatchingFeedOffsetIsScannedAndAnswers200OverRealHttp)
{
    inventory_sync_server_stop();
    LogRecorder::clear();

    invsync::test::installFakeVdScanner(m_events);
    m_events->m_vdCurrentOffset.store(500);

    const auto path = uniqueSocketPath("vdoffsetmatch");
    const auto config = makeConfig(path);
    ASSERT_EQ(0, inventory_sync_server_start(testLogCallback, &config));
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("listening on"));

    SessionSpec spec;
    spec.option = invsync::test::fb::Option_VDFirst;
    spec.feedOffset = 500;
    const auto body = invsync::test::buildSyncDataSession(spec, {invsync::test::ValueSpec {}});
    const auto response = wazuh::uds_http::test::sendRaw(path, statefulRequest(body));

    EXPECT_EQ(200, response.status) << response.body;
    const auto ops = m_events->syncOps();
    ASSERT_EQ(2U, ops.size()) << "a matching offset must let the session reach the scanner and the indexer";
    EXPECT_EQ("scan", std::get<0>(ops[0]));
    EXPECT_EQ("bulkIndex", std::get<0>(ops[1]));
}

TEST_F(StatefulEndpointE2ETest, AVDSessionWithMismatchedFeedOffsetIsRejectedWith409OverRealHttp)
{
    inventory_sync_server_stop();
    LogRecorder::clear();

    invsync::test::installFakeVdScanner(m_events);
    m_events->m_vdCurrentOffset.store(500);

    const auto path = uniqueSocketPath("vdoffsetmismatch");
    const auto config = makeConfig(path);
    ASSERT_EQ(0, inventory_sync_server_start(testLogCallback, &config));
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("listening on"));

    SessionSpec spec;
    spec.option = invsync::test::fb::Option_VDFirst;
    spec.feedOffset = 100; // stale relative to m_vdCurrentOffset=500
    const auto body = invsync::test::buildSyncDataSession(spec, {invsync::test::ValueSpec {}});
    const auto response = wazuh::uds_http::test::sendRaw(path, statefulRequest(body));

    EXPECT_EQ(409, response.status) << response.body;
    const auto json = nlohmann::json::parse(response.body);
    EXPECT_EQ("version_mismatch", json.at("error").get<std::string>());
    EXPECT_EQ(500u, json.at("current_version").get<uint64_t>());
    EXPECT_TRUE(m_events->syncOps().empty()) << "a stale-offset VD session must never reach the scanner or the indexer";
}

/// Deletion over the REAL transport, with the bytes the Task Manager's dispatcher puts on the wire:
/// POST, the agent id in the body, and no headers of its own.
static std::string deleteRequestFor(const std::string& body)
{
    return "POST /_internal/agents/delete HTTP/1.1\r\nHost: localhost\r\n"
           "Content-Type: application/json\r\nContent-Length: " +
           std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
}

/*
 * A deletion has TWO halves, and this E2E is where the facade's wiring of both is proved end to end over the REAL
 * transport, the real Client and its two buckets (see AGENT_DELETION_SCOPE_BY_QUERY / _BY_ID); only the indexer is
 * the library's fake, which keeps no documents, so the oracle is the wire:
 *
 *  - by query, on the `inventory` bucket's connector, on the agent's pipeline shard: the states pattern only --
 *    one delete-by-query per deletion;
 *  - by document id, on the `agent-state` bucket's Group, committed by the same worker: ONE `_bulk` holding the
 *    deletes of `wazuh-agent-config` and `wazuh-agent-stats` per deletion.
 *
 * Both halves are done before the 200: the response is the pipeline's, sent at completion.
 */
TEST_F(StatefulEndpointE2ETest, DeleteAgentsWipesTheAgentAcrossBothHalves)
{
    inventory_sync_server_stop();
    invsync::test::resetIndexerConnectorFactoriesToProduction();

    invsync::test::RealIndexer real;
    real.startRuntime();
    ASSERT_TRUE(real.runtimeStarted) << real.startError;
    invsync::test::installFakeIndexersOverRealClient();

    LogRecorder::clear();
    const auto path = uniqueSocketPath("deleteboth");
    auto config = makeConfig(path);
    config.indexer_runtime = &real.ref;
    ASSERT_EQ(0, inventory_sync_server_start(testLogCallback, &config));
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("listening on"));

    // Until the first health probe lands every write answers 503: retry like the dispatcher would.
    const auto deleteUntilOk = [&](const std::string& body)
    {
        wazuh::uds_http::test::Response response;
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds {10};
        do
        {
            response = wazuh::uds_http::test::sendRaw(path, deleteRequestFor(body));
            if (response.status == 200)
            {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds {50});
        } while (std::chrono::steady_clock::now() < deadline);
        return response;
    };

    // Answered at COMPLETION: "ok" is the pipeline's own answer, sent after the flush and the by-id tickets,
    // which is what lets the dispatcher record its task row `completed` and have that mean purged.
    const auto first = deleteUntilOk(R"({"agent_id":"9"})");
    EXPECT_EQ(200, first.status) << first.body;
    EXPECT_EQ(R"({"status":"ok"})", first.body);
    EXPECT_EQ(200, deleteUntilOk(R"({"agent_id":"10"})").status);

    // The by-query half: the states pattern, and NOT the two wazuh-agent-* indices (they are the by-id half's).
    // Canonical like every document _id: the first deletion is agent 9, the second agent 10.
    EXPECT_EQ(0U, real.dbqRequests("wazuh-agent-config").size());
    EXPECT_EQ(0U, real.dbqRequests("wazuh-agent-stats").size());
    const auto byQuery = real.dbqRequests("wazuh-states-*");
    ASSERT_EQ(2U, byQuery.size()) << "one delete-by-query per deletion";
    EXPECT_NE(std::string::npos, byQuery[0].body.find("009")) << byQuery[0].body;
    EXPECT_NE(std::string::npos, byQuery[1].body.find("010")) << byQuery[1].body;

    // The by-id half: each deletion sent its two deletes in ONE `_bulk`, config first, then stats.
    std::vector<std::vector<indexer_client::testing::BulkOp>> byIdBulks;
    for (const auto& request : real.bulk->received())
    {
        if (!request.empty() && request.front().action == "delete")
        {
            byIdBulks.push_back(request);
        }
    }
    ASSERT_EQ(2U, byIdBulks.size());
    ASSERT_EQ(2U, byIdBulks[0].size());
    EXPECT_EQ("wazuh-agent-config", byIdBulks[0][0].index);
    EXPECT_EQ("wazuh-agent-stats", byIdBulks[0][1].index);
    EXPECT_EQ("009", byIdBulks[0][0].id.value_or(""));
    EXPECT_EQ("009", byIdBulks[0][1].id.value_or(""));
    ASSERT_EQ(2U, byIdBulks[1].size());
    EXPECT_EQ("010", byIdBulks[1][0].id.value_or(""));
    EXPECT_EQ("010", byIdBulks[1][1].id.value_or(""));

    // A body naming no usable agent. The header is NOT a fallback -- setting one here would still be
    // a 400, which is the point: the dispatcher never sends one.
    EXPECT_EQ(400, wazuh::uds_http::test::sendRaw(path, deleteRequestFor(R"({"agent_id":"nope"})")).status);

    inventory_sync_server_stop();
}

TEST_F(StatefulEndpointE2ETest, TheProvisionalPathIsGone)
{
    const auto body = invsync::test::buildSyncDataSession(SessionSpec {}, {invsync::test::ValueSpec {}});
    std::string request = "POST /inventory/sync HTTP/1.1\r\nHost: localhost\r\nX-Wazuh-Agent-Id: 1\r\n"
                          "Content-Length: " +
                          std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
    EXPECT_EQ(404, wazuh::uds_http::test::sendRaw(m_path, request).status);
}

/**
 * D5: with no body cap of its own, a session that declares more than the WHOLE in-flight budget is
 * a 413 at headers-complete -- a contract error the agent fixes by splitting, not a 503 it would
 * retry forever. The rejection happens from the DECLARED length: no body bytes are sent at all.
 */
TEST_F(StatefulEndpointE2ETest, DeclaringMoreThanTheWholeBudgetIs413)
{
    inventory_sync_server_stop();
    LogRecorder::clear(); // or the FIRST server's "listening on" satisfies the wait below

    const auto path = uniqueSocketPath("budget");
    auto config = makeConfig(path);
    config.max_inflight_bytes = 4 * 1024 * 1024; // the effective session limit
    ASSERT_EQ(0, inventory_sync_server_start(testLogCallback, &config));
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("listening on"));

    const std::string head = "POST /stateful HTTP/1.1\r\nHost: localhost\r\nX-Wazuh-Agent-Id: 1\r\n"
                             "Content-Length: 16777216\r\nConnection: close\r\n\r\n";
    const auto response = wazuh::uds_http::test::sendRaw(path, head);
    EXPECT_EQ(413, response.status);
}

/*
 * U10: the transport's bounded resources are published as pull metrics through the module's own
 * GET /metrics, resolved live via the facade's weak target -- the acceptance check of the
 * transport extraction (the only wire delta it is allowed to add).
 */
TEST_F(StatefulEndpointE2ETest, TransportDiagnosticsArePublishedOnMetrics)
{
    const std::string head = "GET /metrics HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n"
                             "Connection: close\r\n\r\n";
    const auto response = wazuh::uds_http::test::sendRaw(m_path, head);

    EXPECT_EQ(200, response.status) << response.body;
    EXPECT_NE(std::string::npos, response.body.find("server.budget.available.bytes")) << response.body;
    EXPECT_NE(std::string::npos, response.body.find("server.budget.inflight.requests"));
    EXPECT_NE(std::string::npos, response.body.find("server.sessions.live"));
}

/*
 * E2 route classes, proven through wire behaviour: deletions are CONTROL (empty body by contract,
 * so their 64 KiB class cap answers 413 to an oversized one), while /stateful is DATA (the same
 * declared size sails through admission and fails only later, as FlatBuffers garbage -> 400).
 * A saturated ingest budget can therefore never starve a deletion -- the signed E2 decision.
 */
TEST_F(StatefulEndpointE2ETest, DeletionsAreControlClassAndStatefulIsDataClass)
{
    const std::string oversized(100 * 1024, 'x'); // over Control's 64 KiB, nothing to Data

    const auto rejected = wazuh::uds_http::test::sendRaw(m_path, deleteRequestFor(oversized));
    EXPECT_EQ(413, rejected.status);
    EXPECT_NE(std::string::npos, rejected.body.find("control-class")) << rejected.body;

    const auto accepted = wazuh::uds_http::test::sendRaw(m_path, statefulRequest(oversized));
    EXPECT_EQ(400, accepted.status) << "data class must ADMIT the size; only the payload itself is garbage";

    // And the liveness plane has the tightest cap of all.
    const std::string bigProbe = "GET /metrics HTTP/1.1\r\nHost: localhost\r\nContent-Length: 8192\r\n"
                                 "Connection: close\r\n\r\n" +
                                 std::string(8192, 'y');
    EXPECT_EQ(413, wazuh::uds_http::test::sendRaw(m_path, bigProbe).status);
}
