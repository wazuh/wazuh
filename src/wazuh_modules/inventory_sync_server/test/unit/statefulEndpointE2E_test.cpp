/*
 * Wazuh inventory sync server module - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * August 4, 2026.
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
#include "testSessionBuilder.hpp"
#include "udsTestClient.hpp"

#include "hashHelper.h"
#include "stringHelper.h"

#include <gtest/gtest.h>
#include <json.hpp>

#include <atomic>
#include <cstdio>
#include <string>
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
    std::string statefulRequest(const std::string& body, const std::string& agentId = "1")
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
        return Utils::asciiToHex(hash.hash());
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
    const auto response = invsync::test::sendRaw(m_path, statefulRequest(body));

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
    const auto response = invsync::test::sendRaw(m_path, statefulRequest(body));

    EXPECT_EQ(200, response.status);
    EXPECT_EQ(R"({"status":"ok","noop":true})", response.body);
    EXPECT_TRUE(m_events->syncOps().empty());
}

TEST_F(StatefulEndpointE2ETest, CleansReachTheIndexerAsDeleteByQuery)
{
    const auto body = invsync::test::buildCleansSession(SessionSpec {}, {"wazuh-states-fim-files"});
    const auto response = invsync::test::sendRaw(m_path, statefulRequest(body));

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

    const auto match = invsync::test::sendRaw(m_path,
                                              statefulRequest(invsync::test::buildChecksumSession(
                                                  spec, "wazuh-states-inventory-packages", expectedSha1Hex("abc123"))));
    EXPECT_EQ(200, match.status) << match.body;

    const auto mismatch = invsync::test::sendRaw(
        m_path,
        statefulRequest(invsync::test::buildChecksumSession(spec, "wazuh-states-inventory-packages", "deadbeef")));
    EXPECT_EQ(409, mismatch.status);
    EXPECT_EQ(R"({"status":"checksum_mismatch"})", mismatch.body);
}

TEST_F(StatefulEndpointE2ETest, AMetadataSessionRunsItsUpdateByQuery)
{
    SessionSpec spec;
    spec.mode = invsync::test::fb::Mode_MetadataDelta;
    const auto response = invsync::test::sendRaw(m_path, statefulRequest(invsync::test::buildBareSession(spec)));

    EXPECT_EQ(200, response.status) << response.body;
    const auto ops = m_events->syncOps();
    ASSERT_EQ(1U, ops.size());
    EXPECT_EQ("executeUpdateByQuery", std::get<0>(ops[0]));
}

TEST_F(StatefulEndpointE2ETest, GarbageIs400AndAForeignIdentityIs403)
{
    EXPECT_EQ(400, invsync::test::sendRaw(m_path, statefulRequest("junk")).status);

    const auto body = invsync::test::buildSyncDataSession(SessionSpec {}, {invsync::test::ValueSpec {}});
    const auto spoofed = invsync::test::sendRaw(m_path, statefulRequest(body, "42"));
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
    const auto response = invsync::test::sendRaw(m_path, statefulRequest(body));

    EXPECT_EQ(200, response.status) << response.body;
    const auto ops = m_events->syncOps();
    ASSERT_EQ(1U, ops.size());
    EXPECT_EQ("bulkIndex", std::get<0>(ops[0]));
    EXPECT_EQ(1, m_events->m_syncFlushes.load());
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
    const auto response = invsync::test::sendRaw(path, statefulRequest(body));

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
    const auto response = invsync::test::sendRaw(path, statefulRequest(body));

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
    const auto response = invsync::test::sendRaw(path, statefulRequest(body));

    EXPECT_EQ(409, response.status) << response.body;
    const auto json = nlohmann::json::parse(response.body);
    EXPECT_EQ("version_mismatch", json.at("error").get<std::string>());
    EXPECT_EQ(500u, json.at("current_version").get<uint64_t>());
    EXPECT_TRUE(m_events->syncOps().empty()) << "a stale-offset VD session must never reach the scanner or the indexer";
}

TEST_F(StatefulEndpointE2ETest, DeleteAgentsWipesTheAgentAndBothRoutesServeIt)
{
    // The canonical DELETE /agents (design doc 04) and its POST alias -- the alias is load-bearing:
    // authd's uhttp_* helper only speaks POST, so a route drift would silently orphan deletions.
    const std::string deleteHead = "DELETE /agents HTTP/1.1\r\nHost: localhost\r\nX-Wazuh-Agent-Id: 9\r\n"
                                   "Content-Length: 0\r\nConnection: close\r\n\r\n";
    const auto response = invsync::test::sendRaw(m_path, deleteHead);
    EXPECT_EQ(200, response.status) << response.body;
    EXPECT_EQ(R"({"status":"ok"})", response.body);

    const std::string aliasHead = "POST /agents/delete HTTP/1.1\r\nHost: localhost\r\nX-Wazuh-Agent-Id: 10\r\n"
                                  "Content-Length: 0\r\nConnection: close\r\n\r\n";
    EXPECT_EQ(200, invsync::test::sendRaw(m_path, aliasHead).status);

    // Each deletion deletes across its whole scope: wazuh-states-* plus the two wazuh-agent-*
    // indices, which live outside the state family and used to outlive the agent.
    std::vector<std::string> deletedIndices;
    std::vector<std::string> deletedAgents;
    for (const auto& op : m_events->syncOps())
    {
        if (std::get<0>(op) == "deleteByQuery")
        {
            deletedIndices.push_back(std::get<2>(op));
            deletedAgents.push_back(std::get<1>(op));
        }
    }

    const std::vector<std::string> scope {"wazuh-states-*", "wazuh-agent-config", "wazuh-agent-stats"};
    std::vector<std::string> expectedIndices {scope};
    expectedIndices.insert(expectedIndices.end(), scope.begin(), scope.end());
    EXPECT_EQ(expectedIndices, deletedIndices);
    // Padded like every document _id: the first deletion is agent 9, the second agent 10.
    EXPECT_EQ(std::vector<std::string>({"009", "009", "009", "010", "010", "010"}), deletedAgents);
    EXPECT_GE(m_events->m_syncFlushes.load(), 2) << "each 200 means its delete was flushed";

    const std::string badHead = "DELETE /agents HTTP/1.1\r\nHost: localhost\r\nX-Wazuh-Agent-Id: nope\r\n"
                                "Content-Length: 0\r\nConnection: close\r\n\r\n";
    EXPECT_EQ(400, invsync::test::sendRaw(m_path, badHead).status);
}

TEST_F(StatefulEndpointE2ETest, TheProvisionalPathIsGone)
{
    const auto body = invsync::test::buildSyncDataSession(SessionSpec {}, {invsync::test::ValueSpec {}});
    std::string request = "POST /inventory/sync HTTP/1.1\r\nHost: localhost\r\nX-Wazuh-Agent-Id: 1\r\n"
                          "Content-Length: " +
                          std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
    EXPECT_EQ(404, invsync::test::sendRaw(m_path, request).status);
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
    const auto response = invsync::test::sendRaw(path, head);
    EXPECT_EQ(413, response.status);
}
