/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * September 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "caBundleFetcher.hpp"

#include "mocks/mockFsProbe.hpp"
#include "mocks/mockHttpPerformer.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using ::testing::_;
using ::testing::NiceMock;
using ::testing::Return;

namespace
{
    constexpr std::int64_t HELD = 1789000010;
    constexpr std::int64_t PUBLISHED = 1789000012;

    const LogFn TEST_LOG {"https-client-test"}; // Sink unset: LOGFN_* are no-ops.

    /// Advances only when told to, so a due time is reached deliberately rather than by waiting.
    class SteppedClock : public IClock
    {
        public:
            std::time_t wallSeconds() const override
            {
                return 1789000000;
            }

            std::chrono::steady_clock::time_point steadyNow() const override
            {
                return m_now;
            }

            void advance(std::chrono::milliseconds by)
            {
                m_now += by;
            }

        private:
            std::chrono::steady_clock::time_point m_now {std::chrono::steady_clock::now()};
    };

    /// Always the top of the jitter window, so the delay is known and long.
    class MaxRandom : public IRandom
    {
        public:
            double uniform01() override
            {
                return 1.0;
            }
    };

    ModuleConfig makeConfig()
    {
        ModuleConfig config;
        config.serverHost = "manager.example.com";
        config.serverPort = 1517;
        config.agentId = "001";
        config.verifyMode = HC_VERIFY_FULL;
        config.caPath = "etc/certs/root-ca.pem";
        config.notifyIntervalS = 10;
        return config;
    }

    HttpResponse bundleResponse(long code, std::string body, std::int64_t generation)
    {
        HttpResponse response;
        response.status = TransportStatus::Ok;
        response.httpCode = code;
        response.body = std::move(body);
        response.caGeneration = generation;
        return response;
    }

    /// Records what reached the consumer and answers with whatever the test wants.
    struct Installs
    {
        std::vector<std::pair<std::string, std::int64_t>> calls;
        bool answer {true};
    };

    class Fixture
    {
        public:
            Fixture()
                : m_config(makeConfig())
                , m_state(HELD)
                , m_fetcher(m_config, m_performer, m_fsProbe, m_clock, m_random, m_state,
                            [this](const std::string & pem, std::int64_t generation)
            {
                m_installs.calls.emplace_back(pem, generation);
                return m_installs.answer;
            },
            TEST_LOG)
            {
                ON_CALL(m_fsProbe, isReadableFile(_)).WillByDefault(Return(true));
            }

            /// Arms a refresh, sits out the jitter window, and runs the attempt.
            void runDueRefresh(std::int64_t advertised = PUBLISHED)
            {
                m_state.observe(advertised);
                m_fetcher.tick(m_waiter);            // Schedules the wait.
                m_clock.advance(std::chrono::seconds {3600});
                m_fetcher.tick(m_waiter);            // Performs it.
            }

            NiceMock<MockHttpPerformer> m_performer;
            NiceMock<MockFsProbe> m_fsProbe;
            SteppedClock m_clock;
            MaxRandom m_random;
            ModuleConfig m_config;
            CaPublicationState m_state;
            Installs m_installs;
            Waiter m_waiter;
            CaBundleFetcher m_fetcher;
    };
}

TEST(CaBundleFetcher, NothingPendingSendsNothing)
{
    Fixture f;
    EXPECT_CALL(f.m_performer, perform(_)).Times(0);

    f.m_fetcher.tick(f.m_waiter);
    f.m_clock.advance(std::chrono::seconds {3600});
    f.m_fetcher.tick(f.m_waiter);

    EXPECT_TRUE(f.m_installs.calls.empty());
}

/* Rule 7: the first attempt waits out a random delay, so a fleet that all saw the same notify
 * does not arrive at the rate limit together. */
TEST(CaBundleFetcher, TheFirstTickOnlySchedulesTheWait)
{
    Fixture f;
    EXPECT_CALL(f.m_performer, perform(_)).Times(0);

    f.m_state.observe(PUBLISHED);
    f.m_fetcher.tick(f.m_waiter);
}

TEST(CaBundleFetcher, AVettedBundleIsInstalledAndBecomesTheLocalPublication)
{
    Fixture f;
    EXPECT_CALL(f.m_performer, perform(_))
    .WillOnce(Return(bundleResponse(200, "-----BEGIN CERTIFICATE-----\nAA\n", PUBLISHED)));

    f.runDueRefresh();

    ASSERT_EQ(1u, f.m_installs.calls.size());
    EXPECT_EQ(PUBLISHED, f.m_installs.calls[0].second);
    EXPECT_EQ(PUBLISHED, f.m_state.local());
    EXPECT_EQ(0, f.m_state.pending());
}

/* Rule 5.1: notifies keep arriving during the wait, and what gets fetched is the highest seen --
 * not the one that happened to arm it. */
TEST(CaBundleFetcher, TheHighestPublicationSeenDuringTheWaitIsTheOneFetched)
{
    Fixture f;
    EXPECT_CALL(f.m_performer, perform(_))
    .WillOnce(Return(bundleResponse(200, "PEM", PUBLISHED + 5)));

    f.m_state.observe(PUBLISHED);
    f.m_fetcher.tick(f.m_waiter);       // Schedules against PUBLISHED.
    f.m_state.observe(PUBLISHED + 5);   // ...and the manager publishes again.
    f.m_clock.advance(std::chrono::seconds {3600});
    f.m_fetcher.tick(f.m_waiter);

    ASSERT_EQ(1u, f.m_installs.calls.size());
    EXPECT_EQ(PUBLISHED + 5, f.m_installs.calls[0].second);
}

/* Rule 6, for each refusal in rule 5.3: nothing is installed and the target stays armed, so the
 * next due moment retries rather than the agent forgetting it was told. */
class CaBundleFetcherRefusal : public ::testing::TestWithParam<HttpResponse>
{
};

TEST_P(CaBundleFetcherRefusal, NothingIsInstalledAndTheTargetStaysArmed)
{
    Fixture f;
    EXPECT_CALL(f.m_performer, perform(_)).WillOnce(Return(GetParam()));

    f.runDueRefresh();

    EXPECT_TRUE(f.m_installs.calls.empty());
    EXPECT_EQ(HELD, f.m_state.local());
    EXPECT_EQ(PUBLISHED, f.m_state.pending());
}

INSTANTIATE_TEST_SUITE_P(
    EveryDiscardReason, CaBundleFetcherRefusal,
    ::testing::Values(
        // No servable bundle on that node.
        bundleResponse(404, R"({"error":"not_found"})", 0),
        // Its bundle does not sign the certificate it serves.
        bundleResponse(503, R"({"error":"ca_mismatch"})", 0),
        // Rate limited.
        bundleResponse(429, "", 0),
        // A body at the client's cap was cut off in transit.
        bundleResponse(200, std::string(8192, 'x'), PUBLISHED),
        // The node served a bundle it does not vouch for.
        bundleResponse(200, "PEM", 0),
        // A lagging node behind a load balancer, answering with an older bundle.
        bundleResponse(200, "PEM", HELD),
        // 200 with nothing in it.
        bundleResponse(200, "", PUBLISHED)));

/* The consumer has the last word: the module cannot parse X.509, so a body it could not turn
 * into a trust store leaves the module's own notion of the installed publication alone. */
TEST(CaBundleFetcher, AConsumerRefusalLeavesTheStateUntouched)
{
    Fixture f;
    f.m_installs.answer = false;
    EXPECT_CALL(f.m_performer, perform(_))
    .WillOnce(Return(bundleResponse(200, "not a certificate", PUBLISHED)));

    f.runDueRefresh();

    ASSERT_EQ(1u, f.m_installs.calls.size());
    EXPECT_EQ(HELD, f.m_state.local());
    EXPECT_EQ(PUBLISHED, f.m_state.pending());
}

/* Verification is the entire basis for trusting the answer, so there is no refresh without it:
 * under 'none' there is nothing to verify against, and under 'system' the trust store is the
 * OS's rather than the agent's to replace. */
TEST(CaBundleFetcher, NoRefreshWhenVerificationIsOffOrDelegatedToTheOs)
{
    for (const hc_verify_mode_t mode :
            {
                HC_VERIFY_NONE, HC_VERIFY_SYSTEM
            })
    {
        Fixture f;
        f.m_config.verifyMode = mode;
        EXPECT_CALL(f.m_performer, perform(_)).Times(0);

        f.runDueRefresh();

        EXPECT_TRUE(f.m_installs.calls.empty());
        EXPECT_EQ(0, f.m_state.pending()); // Abandoned: retrying cannot help.
    }
}
