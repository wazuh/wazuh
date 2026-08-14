/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 21, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "fakeSysSeams.hpp"
#include "mockCallbackSink.hpp"
#include "mockHttpPerformer.hpp"
#include "reporterStream.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstring>
#include <string>
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

            std::optional<std::string> m_stats {R"({"uptime":10})"};
            std::optional<std::string> m_config {R"({"client":{"notify_time":10}})"};
            int m_statsCalls {0};
            int m_configCalls {0};
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

            ConfigKeyProvider m_keyProvider {"000102030405060708090a0b0c0d0e0f"};
            CmacSigner m_signer;
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
    ReporterStream reporter {config, m_performer, m_signer, m_clock, m_random, m_authGate, m_compressionGate,
                             m_cluster, m_collectors};
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
    ReporterStream reporter {config, m_performer, m_signer, m_clock, m_random, m_authGate, m_compressionGate,
                             m_cluster, m_collectors};

    std::string body;
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & spec)
    {
        EXPECT_EQ("/stats", spec.target);
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
    ReporterStream reporter {config, m_performer, m_signer, m_clock, m_random, m_authGate, m_compressionGate,
                             m_cluster, m_collectors};

    std::string body;
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Invoke([&](const HttpRequestSpec & spec)
    {
        body.assign(reinterpret_cast<const char*>(spec.body), spec.bodyLength);
        return response(TransportStatus::Ok, 200);
    }));

    reporter.tick(m_waiter, true);
    EXPECT_NE(std::string::npos, body.find(R"("agent_id":"001")"));
    EXPECT_EQ(std::string::npos, body.find("WRONG"));
    EXPECT_NE(std::string::npos, body.find(R"("cluster":{"name":"authoritative")"));
}

TEST_F(ReporterStreamTest, NullCollectorReturnSkipsWithoutSending)
{
    m_collectors.m_stats = std::nullopt;
    const auto config = makeConfig(true, false);
    ReporterStream reporter {config, m_performer, m_signer, m_clock, m_random, m_authGate, m_compressionGate,
                             m_cluster, m_collectors};
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
    ReporterStream reporter {config, m_performer, m_signer, m_clock, m_random, m_authGate, m_compressionGate,
                             m_cluster, m_collectors};
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
    ReporterStream reporter {config, m_performer, m_signer, m_clock, m_random, m_authGate, m_compressionGate,
                             m_cluster, m_collectors};
    EXPECT_CALL(m_performer, perform(_)).Times(0);
    reporter.tick(m_waiter, true);
}

TEST_F(ReporterStreamTest, UnregisteredOrPausedSkipsAndKeepsDueness)
{
    const auto config = makeConfig(true, false);
    ReporterStream reporter {config, m_performer, m_signer, m_clock, m_random, m_authGate, m_compressionGate,
                             m_cluster, m_collectors};
    EXPECT_CALL(m_performer, perform(_)).Times(0);
    reporter.tick(m_waiter, false); // Not registered.
    m_authGate.reportAuthFailure();
    reporter.tick(m_waiter, true); // Registered but paused.
    EXPECT_EQ(0, m_collectors.m_statsCalls);
}

TEST_F(ReporterStreamTest, IntervalGovernsTheNextSend)
{
    const auto config = makeConfig(true, false);
    ReporterStream reporter {config, m_performer, m_signer, m_clock, m_random, m_authGate, m_compressionGate,
                             m_cluster, m_collectors};
    EXPECT_CALL(m_performer, perform(_)).WillRepeatedly(Return(response(TransportStatus::Ok, 200)));

    reporter.tick(m_waiter, true);             // Sends (due at epoch).
    EXPECT_EQ(1, m_collectors.m_statsCalls);
    reporter.tick(m_waiter, true);             // Too soon: not due.
    EXPECT_EQ(1, m_collectors.m_statsCalls);
    m_clock.advance(std::chrono::seconds {60}); // Reach the interval.
    reporter.tick(m_waiter, true);
    EXPECT_EQ(2, m_collectors.m_statsCalls);
}

TEST_F(ReporterStreamTest, BackPressureDefersOnlyThatPath)
{
    const auto config = makeConfig(true, true);
    ReporterStream reporter {config, m_performer, m_signer, m_clock, m_random, m_authGate, m_compressionGate,
                             m_cluster, m_collectors};
    // Both due at epoch: stats 503 (Retry-After 5), config 200.
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Return(response(TransportStatus::Ok, 503, 5)))  // /stats first.
    .WillOnce(Return(response(TransportStatus::Ok, 200)));    // /config.
    reporter.tick(m_waiter, true);
    EXPECT_EQ(1, m_collectors.m_statsCalls);
    EXPECT_EQ(1, m_collectors.m_configCalls);

    // Immediately after, neither is due (config on its 3600 s interval, stats
    // deferred by the Retry-After) -> no send.
    EXPECT_CALL(m_performer, perform(_)).Times(0);
    reporter.tick(m_waiter, true);
}
