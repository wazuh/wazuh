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
        // The default is fail-closed, so the ordinary fixture opts in; the agent that may not
        // refresh has its own case below.
        config.caRefreshAllowed = true;
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

    /// A rate limiter's answer: 429 plus the Retry-After it wants honoured (#39280 bounds
    /// /cacerts to 50 req/s per node, so a rotating fleet meets this for real).
    HttpResponse rateLimited(long retryAfterSeconds)
    {
        HttpResponse response;
        response.status = TransportStatus::Ok;
        response.httpCode = 429;
        response.retryAfterSeconds = retryAfterSeconds;
        return response;
    }

    /// A manager that was never reached: no HTTP status, nothing served. Distinct from a 4xx/5xx
    /// because the ceiling on adoption attempts is about load the manager has to carry.
    HttpResponse unreachable()
    {
        HttpResponse response;
        response.status = TransportStatus::ConnectFail;
        response.httpCode = 0;
        return response;
    }

    /// A fetch cut short by the shutdown flag.
    HttpResponse abortedFetch()
    {
        HttpResponse response;
        response.status = TransportStatus::Aborted;
        response.httpCode = 0;
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

        // Left armed, deliberately. Clearing it would return the state to "nothing pending", so
        // the next notify would arm it again -- and arming is what ControlStream logs. On a ten
        // second keepalive that was an INFO line every ten seconds for the life of an agent that
        // was never going to refresh anything.
        EXPECT_EQ(PUBLISHED, f.m_state.pending());
        EXPECT_FALSE(f.m_state.observe(PUBLISHED)); // So the next notify says nothing.
    }
}

/* An operator's own <certificate_authorities> is not this feature's to rewrite. The usual such
 * path is root-owned and outside etc/certs, so the agent could not replace it after the
 * privilege drop even if it should -- and every attempt would be retried, by every agent, for
 * as long as the manager kept advertising. */
TEST(CaBundleFetcher, NoRefreshWhenTheTrustStoreIsNotTheAgentsOwn)
{
    Fixture f;
    f.m_config.caRefreshAllowed = false;
    EXPECT_CALL(f.m_performer, perform(_)).Times(0);

    f.runDueRefresh();

    EXPECT_TRUE(f.m_installs.calls.empty());
    EXPECT_EQ(PUBLISHED, f.m_state.pending()); // Armed but never acted on, so it stays quiet.
}

/* The ceiling on a publication that will not install. Without it the ramp retries forever: at
 * the 60 s cap that is about one request every thirty seconds per agent, which a fleet turns
 * into a permanent load its manager cannot shed -- Retry-After is itself capped. */
TEST(CaBundleFetcher, APublicationThatNeverInstallsIsEventuallyAbandoned)
{
    Fixture f;
    f.m_installs.answer = false; // The consumer refuses every time, as an unwritable store does.
    ON_CALL(f.m_performer, perform(_))
    .WillByDefault(Return(bundleResponse(200, "PEM", PUBLISHED)));

    f.m_state.observe(PUBLISHED);

    // 20 x 2 min stays well inside ABANDON_COOLDOWN, so this measures the ceiling itself rather
    // than the ceiling plus however many cooldowns the loop happened to step over.
    for (int attempt = 0; attempt < 20; attempt++)
    {
        f.m_clock.advance(std::chrono::minutes {2});
        f.m_fetcher.tick(f.m_waiter);
    }

    // Five attempts, then silence -- not one per tick for the rest of the agent's life.
    EXPECT_EQ(5u, f.m_installs.calls.size());
    // The store is untouched and the agent keeps using it.
    EXPECT_EQ(HELD, f.m_state.local());
}

/* Giving up is a cooldown, not a verdict for the life of the process. A rotation advertises the
 * SAME publication until the manager publishes another, so an abandonment that never lifted would
 * be an agent that has quietly stopped following CA rotations -- it would lose the manager at the
 * next one, having said so exactly once, when it gave up. */
TEST(CaBundleFetcher, AnAbandonedPublicationIsTriedAgainOnceTheCooldownLifts)
{
    Fixture f;
    f.m_installs.answer = false;
    ON_CALL(f.m_performer, perform(_))
    .WillByDefault(Return(bundleResponse(200, "PEM", PUBLISHED)));

    f.m_state.observe(PUBLISHED);

    for (int attempt = 0; attempt < 20; attempt++)
    {
        f.m_clock.advance(std::chrono::minutes {2});
        f.m_fetcher.tick(f.m_waiter);
    }

    ASSERT_EQ(5u, f.m_installs.calls.size());

    // Whatever refused it stops being true -- an operator makes the store writable.
    f.m_installs.answer = true;
    f.m_clock.advance(std::chrono::hours {2});
    f.m_fetcher.tick(f.m_waiter);   // Cooldown is up: schedules the wait again.
    f.m_clock.advance(std::chrono::minutes {2});
    f.m_fetcher.tick(f.m_waiter);   // ...and performs it.

    EXPECT_EQ(6u, f.m_installs.calls.size());
    EXPECT_EQ(PUBLISHED, f.m_state.local());
}

/* The ceiling is charged for answers, not for attempts. A manager that was never reached costs it
 * nothing to refuse, so bounding those buys nothing -- and charging for them is what let a manager
 * RESTART, which is exactly when a rotation gets published, spend the whole budget in under a
 * minute: the ramp is full jitter over [0, base << n] from a 1 s base. The agent would then never
 * adopt the new CA, because a rotation keeps advertising the publication it just gave up on. */
TEST(CaBundleFetcher, AManagerThatWasNeverReachedDoesNotSpendTheBudget)
{
    Fixture f;
    ON_CALL(f.m_performer, perform(_)).WillByDefault(Return(unreachable()));

    f.m_state.observe(PUBLISHED);

    // Far more than MAX_ADOPTION_ATTEMPTS, and inside one cooldown window either way.
    for (int attempt = 0; attempt < 20; attempt++)
    {
        f.m_clock.advance(std::chrono::minutes {2});
        f.m_fetcher.tick(f.m_waiter);
    }

    EXPECT_TRUE(f.m_installs.calls.empty());   // Nothing ever came back to install.

    // The manager returns, still advertising the same publication, and the agent adopts it.
    ON_CALL(f.m_performer, perform(_))
    .WillByDefault(Return(bundleResponse(200, "PEM", PUBLISHED)));
    f.m_clock.advance(std::chrono::minutes {2});
    f.m_fetcher.tick(f.m_waiter);

    ASSERT_EQ(1u, f.m_installs.calls.size());
    EXPECT_EQ(PUBLISHED, f.m_state.local());
}

/* A shutdown is not a refusal: the request was cut short on its way out, so nothing was learned
 * about the publication and nothing is charged for it. */
TEST(CaBundleFetcher, AFetchAbortedByShutdownDoesNotSpendTheBudget)
{
    Fixture f;
    ON_CALL(f.m_performer, perform(_)).WillByDefault(Return(abortedFetch()));

    f.m_state.observe(PUBLISHED);

    for (int attempt = 0; attempt < 20; attempt++)
    {
        f.m_clock.advance(std::chrono::minutes {2});
        f.m_fetcher.tick(f.m_waiter);
    }

    ON_CALL(f.m_performer, perform(_))
    .WillByDefault(Return(bundleResponse(200, "PEM", PUBLISHED)));
    // Two ticks, not one: an abort clears the due time outright rather than re-arming it on the
    // ramp, because a shutdown is not something to back off from. The next start re-jitters.
    f.m_clock.advance(std::chrono::minutes {2});
    f.m_fetcher.tick(f.m_waiter);   // Schedules the wait again.
    f.m_clock.advance(std::chrono::minutes {2});
    f.m_fetcher.tick(f.m_waiter);   // ...and performs it.

    ASSERT_EQ(1u, f.m_installs.calls.size());
    EXPECT_EQ(PUBLISHED, f.m_state.local());
}

/* Giving up is per publication, not for good: the next one the manager publishes is a different
 * bundle, and whatever made the last one unusable may not apply to it. */
TEST(CaBundleFetcher, AHigherPublicationIsTriedAfterOneWasAbandoned)
{
    Fixture f;
    f.m_installs.answer = false;
    ON_CALL(f.m_performer, perform(_))
    .WillByDefault(Return(bundleResponse(200, "PEM", PUBLISHED)));

    f.m_state.observe(PUBLISHED);

    // 20 x 2 min stays well inside ABANDON_COOLDOWN, so this measures the ceiling itself rather
    // than the ceiling plus however many cooldowns the loop happened to step over.
    for (int attempt = 0; attempt < 20; attempt++)
    {
        f.m_clock.advance(std::chrono::minutes {2});
        f.m_fetcher.tick(f.m_waiter);
    }

    ASSERT_EQ(5u, f.m_installs.calls.size());

    f.m_installs.answer = true;
    ON_CALL(f.m_performer, perform(_))
    .WillByDefault(Return(bundleResponse(200, "PEM", PUBLISHED + 1)));

    f.m_state.observe(PUBLISHED + 1);
    f.m_clock.advance(std::chrono::seconds {3600});
    f.m_fetcher.tick(f.m_waiter);
    f.m_clock.advance(std::chrono::seconds {3600});
    f.m_fetcher.tick(f.m_waiter);

    EXPECT_EQ(PUBLISHED + 1, f.m_state.local());
}

/* Retry-After is not merely parsed, it defers the next attempt. Nothing asserted this before:
 * every 429 test proved the trust store was untouched and the target stayed armed, so deleting
 * the comparison against the ramp would have left the suite entirely green.
 *
 * The ramp here is milliseconds and the header asks for 30 s, so the header is what decides. */
TEST(CaBundleFetcher, RetryAfterDefersTheNextAttemptBeyondTheRamp)
{
    // The ramp is the fixture's: MaxRandom over a 1000 ms base, so the first retry is due in
    // exactly 1 s. Backoff copies base/cap in the fetcher's constructor, so it cannot be
    // retuned through m_config here -- 30 s against 1 s is contrast enough.
    Fixture f;

    EXPECT_CALL(f.m_performer, perform(_))
    .WillOnce(Return(rateLimited(30)))
    .WillOnce(Return(bundleResponse(200, "PEM", PUBLISHED)));

    f.runDueRefresh();                              // First attempt: 429.
    EXPECT_TRUE(f.m_installs.calls.empty());

    // Well past the ramp, nowhere near what the server asked for: nothing may go out yet.
    f.m_clock.advance(std::chrono::seconds {5});
    f.m_fetcher.tick(f.m_waiter);
    EXPECT_TRUE(f.m_installs.calls.empty());

    // Past the server's window: the attempt is due again.
    f.m_clock.advance(std::chrono::seconds {26});
    f.m_fetcher.tick(f.m_waiter);
    ASSERT_EQ(1u, f.m_installs.calls.size());
    EXPECT_EQ(PUBLISHED, f.m_installs.calls[0].second);
}

/* ...but only up to MAX_AGENT_DELAY. The value arrives from the network and nothing else bounds
 * it, and because a refused target stays armed rather than being dropped, an unbounded delay
 * would not postpone the refresh so much as end it. A day's Retry-After must not outlive the cap. */
TEST(CaBundleFetcher, AnAbsurdRetryAfterIsCappedAtTheAgentMaximum)
{
    Fixture f;

    EXPECT_CALL(f.m_performer, perform(_))
    .WillOnce(Return(rateLimited(86400)))           // A full day.
    .WillOnce(Return(bundleResponse(200, "PEM", PUBLISHED)));

    f.runDueRefresh();
    EXPECT_TRUE(f.m_installs.calls.empty());

    // Just inside the cap: still waiting, so the cap is a real delay and not a bypass.
    f.m_clock.advance(std::chrono::seconds {59});
    f.m_fetcher.tick(f.m_waiter);
    EXPECT_TRUE(f.m_installs.calls.empty());

    // Just past it: the agent comes back, a day early.
    f.m_clock.advance(std::chrono::seconds {2});
    f.m_fetcher.tick(f.m_waiter);
    ASSERT_EQ(1u, f.m_installs.calls.size());
    EXPECT_EQ(PUBLISHED, f.m_state.local());
}

/* A header that is absent, zero or negative is not a delay at all: the ordinary ramp decides,
 * and a negative value must never subtract from it or fire the attempt immediately. The ramp
 * here is the fixture's 1 s, so the assertions straddle that rather than the server's value. */
TEST(CaBundleFetcher, AnAbsentOrNegativeRetryAfterLeavesTheRampInCharge)
{
    for (const long header :
            {
                0L, -1L, -86400L
            })
    {
        Fixture f;

        EXPECT_CALL(f.m_performer, perform(_))
        .WillOnce(Return(rateLimited(header)))
        .WillOnce(Return(bundleResponse(200, "PEM", PUBLISHED)));

        f.runDueRefresh();
        ASSERT_TRUE(f.m_installs.calls.empty()) << "header " << header;

        // Inside the 1 s ramp: a negative header must not have pulled the due time backwards.
        f.m_clock.advance(std::chrono::milliseconds {500});
        f.m_fetcher.tick(f.m_waiter);
        EXPECT_TRUE(f.m_installs.calls.empty()) << "header " << header;

        // Past it: the ordinary ramp, neither shortened nor extended by the header.
        f.m_clock.advance(std::chrono::milliseconds {600});
        f.m_fetcher.tick(f.m_waiter);
        EXPECT_EQ(1u, f.m_installs.calls.size()) << "header " << header;
    }
}
