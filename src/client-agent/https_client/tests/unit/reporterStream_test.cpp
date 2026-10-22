/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "fakeSysSeams.hpp"
#include "jwtSigner.hpp"
#include "mockCallbackSink.hpp"
#include "mockHttpPerformer.hpp"
#include "reporterStream.hpp"

#include "external/nlohmann/json.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstring>
#include <future>
#include <string>
#include <thread>
#include <vector>

using ::testing::_;
using ::testing::Invoke;
using ::testing::NiceMock;
using ::testing::Return;

namespace
{
    HttpResponse response(TransportStatus status, long code, long retryAfter = 0)
    {
        HttpResponse value;
        value.status = status;
        value.httpCode = code;
        value.retryAfterSeconds = retryAfter;
        return value;
    }

    /// Hands out scripted snapshots; records how many times each was pulled.
    class FakeCollectorSource final : public ICollectorSource
    {
        public:
            std::optional<std::string> collectStats() override
            {
                m_statsCalls++;
                return m_stats;
            }

            std::optional<std::string> collectConfig() override
            {
                m_configCalls++;
                return m_config;
            }

            std::string collectAgentMetadata() override
            {
                m_agentMetadataCalls++;
                return m_agentMetadata;
            }

            std::optional<std::string> m_stats {R"({"uptime":10})"};
            std::optional<std::string> m_config {R"({"client":{"notify_time":10}})"};
            std::string m_agentMetadata;
            int m_statsCalls {0};
            int m_configCalls {0};
            int m_agentMetadataCalls {0};
    };

    class ReporterStreamTest : public ::testing::Test
    {
        protected:
            ReporterStreamTest()
                : m_signer("001", m_keyProvider)
                , m_authGate(m_sink, [] {})
            {
            }

            ModuleConfig makeConfig(bool stats, bool config)
            {
                hc_config_t raw {};
                std::strncpy(raw.server_host, "127.0.0.1", sizeof(raw.server_host) - 1);
                std::strncpy(raw.agent_id, "001", sizeof(raw.agent_id) - 1);
                raw.verify_mode = HC_VERIFY_NONE;
                raw.stats_enabled = stats;
                raw.stats_interval_s = 60;
                raw.config_report_enabled = config;
                raw.config_report_interval_s = 3600;
                return ModuleConfig::fromC(raw);
            }

            /// Runs one tick and returns the body the reporter posted.
            std::string tickAndCaptureBody(ReporterStream& reporter)
            {
                std::string body;
                EXPECT_CALL(m_performer, perform(_))
                .WillOnce(Invoke(
                              [&](const HttpRequestSpec & spec)
                {
                    body.assign(reinterpret_cast<const char*>(spec.body), spec.bodyLength);
                    return response(TransportStatus::Ok, 200);
                }));
                reporter.tick(m_waiter, true);
                return body;
            }

            static constexpr auto AGENT_METADATA =
                R"({"agent":{"name":"web-01","version":"v5.0.0","groups":["default","linux"],)"
                R"("host":{"architecture":"x86_64","hostname":"web-01","os":{"name":"Ubuntu","platform":"ubuntu",)"
                R"("type":"linux","version":"24.04"}}},"cluster":{"name":"from-metadata"}})";

            ConfigKeyProvider m_keyProvider {"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"};
            JwtSigner m_signer;
            FakeClock m_clock;
            ScriptedRandom m_random {{0.0}};
            NiceMock<MockCallbackSink> m_sink;
            AuthGate m_authGate;
            CompressionGate m_compressionGate;
            ClusterIdentity m_cluster;
            FakeCollectorSource m_collectors;
            MockHttpPerformer m_performer;
            FakeWaiter m_waiter;
    };
} // namespace

TEST_F(ReporterStreamTest, DisabledReportersNeverCollectOrSend)
{
    const auto config = makeConfig(false, false);
    ReporterStream reporter
    {
        config, m_performer, m_signer, m_clock, m_random, m_authGate, m_compressionGate, m_cluster, m_collectors};
    EXPECT_FALSE(reporter.anyEnabled());
    EXPECT_CALL(m_performer, perform(_)).Times(0);
    reporter.tick(m_waiter, true);
    EXPECT_EQ(0, m_collectors.m_statsCalls);
    EXPECT_EQ(0, m_collectors.m_configCalls);
}

TEST_F(ReporterStreamTest, StampsAgentIdAndClusterAndPostsToStats)
{
    m_cluster.set("prod");
    const auto config = makeConfig(true, false);
    ReporterStream reporter
    {
        config, m_performer, m_signer, m_clock, m_random, m_authGate, m_compressionGate, m_cluster, m_collectors};

    std::string body;
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & spec)
    {
        EXPECT_EQ("/stats", spec.target);
        EXPECT_EQ(SHORT_REPLY_MAX_RESPONSE_BYTES, spec.maxResponseBytes);
        body.assign(reinterpret_cast<const char*>(spec.body), spec.bodyLength);
        return response(TransportStatus::Ok, 200);
    }));

    reporter.tick(m_waiter, true); // Due immediately at epoch.
    EXPECT_NE(std::string::npos, body.find(R"("agent_id":"001")"));
    EXPECT_NE(std::string::npos, body.find(R"("cluster":{"name":"prod"})"));
    EXPECT_NE(std::string::npos, body.find(R"("uptime":10)"));
}

TEST_F(ReporterStreamTest, StampOverwritesCollectorSuppliedIdentityFields)
{
    m_cluster.set("authoritative");
    m_collectors.m_stats = R"({"agent_id":"WRONG","cluster":"WRONG","x":1})";
    const auto config = makeConfig(true, false);
    ReporterStream reporter
    {
        config, m_performer, m_signer, m_clock, m_random, m_authGate, m_compressionGate, m_cluster, m_collectors};

    std::string body;
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & spec)
    {
        body.assign(reinterpret_cast<const char*>(spec.body), spec.bodyLength);
        return response(TransportStatus::Ok, 200);
    }));

    reporter.tick(m_waiter, true);
    EXPECT_NE(std::string::npos, body.find(R"("agent_id":"001")"));
    EXPECT_EQ(std::string::npos, body.find("WRONG"));
    EXPECT_NE(std::string::npos, body.find(R"("cluster":{"name":"authoritative")"));
}

TEST_F(ReporterStreamTest, StampsAgentMetadataOnStatsAndConfig)
{
    m_cluster.set("authoritative");
    m_collectors.m_agentMetadata = AGENT_METADATA;
    const auto config = makeConfig(true, true);
    ReporterStream reporter
    {
        config, m_performer, m_signer, m_clock, m_random, m_authGate, m_compressionGate, m_cluster, m_collectors};

    std::vector<nlohmann::json> bodies;
    EXPECT_CALL(m_performer, perform(_))
    .Times(2)
    .WillRepeatedly(Invoke(
                        [&](const HttpRequestSpec & spec)
    {
        bodies.push_back(nlohmann::json::parse(
                             std::string(reinterpret_cast<const char*>(spec.body), spec.bodyLength)));
        return response(TransportStatus::Ok, 200);
    }));
    reporter.tick(m_waiter, true); // Both paths are due at epoch.

    ASSERT_EQ(2U, bodies.size());

    for (const auto& body : bodies)
    {
        const auto& agent = body.at("agent");
        EXPECT_EQ(nlohmann::json::array({"default", "linux"}), agent.at("groups"));
        EXPECT_EQ("x86_64", agent.at("host").at("architecture"));
        EXPECT_EQ("web-01", agent.at("host").at("hostname"));
        EXPECT_EQ("24.04", agent.at("host").at("os").at("version"));
        // The metadata's own cluster never replaces the manager-authoritative one.
        EXPECT_EQ("authoritative", body.at("cluster").at("name"));
        EXPECT_EQ("001", body.at("agent_id"));
    }
}

TEST_F(ReporterStreamTest, ReportWithoutAgentMetadataStillGoesOut)
{
    m_collectors.m_agentMetadata = "";
    const auto config = makeConfig(true, false);
    ReporterStream reporter
    {
        config, m_performer, m_signer, m_clock, m_random, m_authGate, m_compressionGate, m_cluster, m_collectors};

    const auto body = nlohmann::json::parse(tickAndCaptureBody(reporter));
    EXPECT_FALSE(body.contains("agent"));
    EXPECT_EQ(10, body.at("uptime"));
}

TEST_F(ReporterStreamTest, MalformedAgentMetadataStillSendsTheReport)
{
    // What a callback output cut by its buffer looks like.
    m_collectors.m_agentMetadata = R"({"agent":{"groups":["default","li)";
    const auto config = makeConfig(true, false);
    ReporterStream reporter
    {
        config, m_performer, m_signer, m_clock, m_random, m_authGate, m_compressionGate, m_cluster, m_collectors};

    const auto body = nlohmann::json::parse(tickAndCaptureBody(reporter));
    EXPECT_FALSE(body.contains("agent"));
    EXPECT_EQ(10, body.at("uptime"));
}

TEST_F(ReporterStreamTest, AgentMetadataWithoutAnAgentObjectIsNotStamped)
{
    m_collectors.m_agentMetadata = R"({"agent":["default"],"cluster":{"name":"c"}})";
    const auto config = makeConfig(true, false);
    ReporterStream reporter
    {
        config, m_performer, m_signer, m_clock, m_random, m_authGate, m_compressionGate, m_cluster, m_collectors};

    EXPECT_FALSE(nlohmann::json::parse(tickAndCaptureBody(reporter)).contains("agent"));
}

TEST_F(ReporterStreamTest, CollectorSuppliedAgentIsNeverForwarded)
{
    m_collectors.m_stats = R"({"agent":{"groups":["WRONG"]},"uptime":10})";

    {
        m_collectors.m_agentMetadata = "";
        const auto config = makeConfig(true, false);
        ReporterStream reporter
        {
            config, m_performer, m_signer, m_clock, m_random, m_authGate, m_compressionGate, m_cluster, m_collectors};
        EXPECT_EQ(std::string::npos, tickAndCaptureBody(reporter).find("WRONG"));
    }

    {
        m_collectors.m_agentMetadata = AGENT_METADATA;
        const auto config = makeConfig(true, false);
        ReporterStream reporter
        {
            config, m_performer, m_signer, m_clock, m_random, m_authGate, m_compressionGate, m_cluster, m_collectors};
        const auto body = nlohmann::json::parse(tickAndCaptureBody(reporter));
        EXPECT_EQ(nlohmann::json::array({"default", "linux"}), body.at("agent").at("groups"));
    }
}

TEST_F(ReporterStreamTest, AgentMetadataIsReadFreshOnEveryPush)
{
    m_collectors.m_agentMetadata = R"({"agent":{"groups":["before"]}})";
    const auto config = makeConfig(true, false);
    ReporterStream reporter
    {
        config, m_performer, m_signer, m_clock, m_random, m_authGate, m_compressionGate, m_cluster, m_collectors};

    EXPECT_EQ("before", nlohmann::json::parse(tickAndCaptureBody(reporter)).at("agent").at("groups")[0]);

    m_collectors.m_agentMetadata = R"({"agent":{"groups":["after"]}})";
    m_clock.advance(std::chrono::seconds {60});
    EXPECT_EQ("after", nlohmann::json::parse(tickAndCaptureBody(reporter)).at("agent").at("groups")[0]);
    EXPECT_EQ(2, m_collectors.m_agentMetadataCalls);
}

TEST_F(ReporterStreamTest, NullCollectorReturnSkipsWithoutSending)
{
    m_collectors.m_stats = std::nullopt;
    const auto config = makeConfig(true, false);
    ReporterStream reporter
    {
        config, m_performer, m_signer, m_clock, m_random, m_authGate, m_compressionGate, m_cluster, m_collectors};
    EXPECT_CALL(m_performer, perform(_)).Times(0);
    reporter.tick(m_waiter, true);
    EXPECT_EQ(1, m_collectors.m_statsCalls); // Collected, then skipped.
}

TEST_F(ReporterStreamTest, NullCollectorReturnRetriesSoonNotAfterFullInterval)
{
    // Models the startup race: the reporter's gate opens on registration, but the
    // local modules (logcollector/syscheck/...) have not unlocked yet, so the
    // collector comes back empty on the first attempt. It must retry on the same
    // short backoff as a send failure, not wait out the full (60 s here) interval.
    m_collectors.m_stats = std::nullopt;
    const auto config = makeConfig(true, false);
    ReporterStream reporter
    {
        config, m_performer, m_signer, m_clock, m_random, m_authGate, m_compressionGate, m_cluster, m_collectors};
    EXPECT_CALL(m_performer, perform(_)).Times(0);

    reporter.tick(m_waiter, true); // First attempt: nothing collected yet.
    EXPECT_EQ(1, m_collectors.m_statsCalls);

    m_clock.advance(std::chrono::milliseconds {1}); // Far short of the 60 s interval.
    reporter.tick(m_waiter, true);
    EXPECT_EQ(2, m_collectors.m_statsCalls); // Retried already, not stuck for an hour/interval.
}

TEST_F(ReporterStreamTest, NonObjectCollectorReturnIsSkipped)
{
    m_collectors.m_stats = R"(["not","an","object"])";
    const auto config = makeConfig(true, false);
    ReporterStream reporter
    {
        config, m_performer, m_signer, m_clock, m_random, m_authGate, m_compressionGate, m_cluster, m_collectors};
    EXPECT_CALL(m_performer, perform(_)).Times(0);
    reporter.tick(m_waiter, true);
}

TEST_F(ReporterStreamTest, UnregisteredOrPausedSkipsAndKeepsDueness)
{
    const auto config = makeConfig(true, false);
    ReporterStream reporter
    {
        config, m_performer, m_signer, m_clock, m_random, m_authGate, m_compressionGate, m_cluster, m_collectors};
    EXPECT_CALL(m_performer, perform(_)).Times(0);
    reporter.tick(m_waiter, false); // Not registered.
    m_authGate.reportAuthFailure();
    reporter.tick(m_waiter, true); // Registered but paused.
    EXPECT_EQ(0, m_collectors.m_statsCalls);
}

TEST_F(ReporterStreamTest, IntervalGovernsTheNextSend)
{
    const auto config = makeConfig(true, false);
    ReporterStream reporter
    {
        config, m_performer, m_signer, m_clock, m_random, m_authGate, m_compressionGate, m_cluster, m_collectors};
    EXPECT_CALL(m_performer, perform(_)).WillRepeatedly(Return(response(TransportStatus::Ok, 200)));

    reporter.tick(m_waiter, true); // Sends (due at epoch).
    EXPECT_EQ(1, m_collectors.m_statsCalls);
    reporter.tick(m_waiter, true); // Too soon: not due.
    EXPECT_EQ(1, m_collectors.m_statsCalls);
    m_clock.advance(std::chrono::seconds {60}); // Reach the interval.
    reporter.tick(m_waiter, true);
    EXPECT_EQ(2, m_collectors.m_statsCalls);
}

TEST_F(ReporterStreamTest, BackPressureDefersOnlyThatPath)
{
    const auto config = makeConfig(true, true);
    ReporterStream reporter
    {
        config, m_performer, m_signer, m_clock, m_random, m_authGate, m_compressionGate, m_cluster, m_collectors};
    // Both due at epoch: stats 503 (Retry-After 5), config 200.
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Return(response(TransportStatus::Ok, 503, 5))) // /stats first.
    .WillOnce(Return(response(TransportStatus::Ok, 200)));   // /config.
    reporter.tick(m_waiter, true);
    EXPECT_EQ(1, m_collectors.m_statsCalls);
    EXPECT_EQ(1, m_collectors.m_configCalls);

    // Immediately after, neither is due (config on its 3600 s interval, stats
    // deferred by the Retry-After) -> no send.
    EXPECT_CALL(m_performer, perform(_)).Times(0);
    reporter.tick(m_waiter, true);
}

TEST_F(ReporterStreamTest, StampFollowsTheSignerIdentityAfterAReenroll)
{
    // Same rule as the /stateless H line: the stamped agent_id is the signer's
    // live id, not the id the module was created with.
    const auto config = makeConfig(true, false);
    ReporterStream reporter
    {
        config, m_performer, m_signer, m_clock, m_random, m_authGate, m_compressionGate, m_cluster, m_collectors};
    m_signer.setAgentId("002");

    std::string body;
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & spec)
    {
        body.assign(reinterpret_cast<const char*>(spec.body), spec.bodyLength);
        return response(TransportStatus::Ok, 200);
    }));

    reporter.tick(m_waiter, true);
    EXPECT_NE(std::string::npos, body.find(R"("agent_id":"002")"));
    EXPECT_EQ(std::string::npos, body.find(R"("agent_id":"001")"));
}

TEST_F(ReporterStreamTest, ForceConfigReportNowDuringInFlightSendIsNotLost)
{
    // A force landing while runPath() is blocked in perform() must survive that send's own
    // post-send reschedule once it returns, not get silently clobbered by it.
    const auto config = makeConfig(false, true);
    ReporterStream reporter
    {
        config, m_performer, m_signer, m_clock, m_random, m_authGate, m_compressionGate, m_cluster, m_collectors};

    std::promise<void> insideSend;
    std::promise<void> proceed;
    auto insideSendFuture = insideSend.get_future();
    auto proceedFuture = proceed.get_future();

    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec&)
    {
        insideSend.set_value();
        proceedFuture.wait(); // Held open until the test below has forced a concurrent notify.
        return response(TransportStatus::Ok, 200);
    }));

    std::thread sender([&] { reporter.tick(m_waiter, true); }); // Due immediately at epoch.
    insideSendFuture.wait();

    // The concurrent notify this test exists to protect: lands while runPath() is still
    // blocked above, mid-send.
    reporter.forceConfigReportNow();
    proceed.set_value();
    sender.join();

    EXPECT_EQ(1, m_collectors.m_configCalls);

    // Nowhere near the 3600 s interval: the next tick only collects again if the forced
    // due-now survived the post-send reschedule instead of being overwritten by it.
    m_clock.advance(std::chrono::milliseconds {1});
    EXPECT_CALL(m_performer, perform(_)).WillOnce(Return(response(TransportStatus::Ok, 200)));
    reporter.tick(m_waiter, true);
    EXPECT_EQ(2, m_collectors.m_configCalls);
}
