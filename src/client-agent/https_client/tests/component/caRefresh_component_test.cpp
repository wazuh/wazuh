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

/*
 * The #39321 CA refresh over the real curl path against a real TLS listener,
 * verified for real. The unit suite drives CaBundleFetcher against a mocked
 * IHttpPerformer and so can only prove what the class does with a response it
 * was handed; nothing there establishes that Wazuh-CA-Generation survives an
 * actual HTTP round trip, or that a refresh can complete at all over a
 * connection the agent verified against its own trust store.
 *
 * That last point is the reason this file exists rather than more unit tests.
 * A refresh runs under HC_VERIFY_FULL by design -- verification is the entire
 * basis for trusting the answer -- so the one code path that matters in
 * production is the one a mock cannot reach. Here the fake manager's listener
 * certificate is CA:TRUE with SAN IP:127.0.0.1, written to a file that ca_path
 * points at, so the handshake really is verified and a bundle really does
 * arrive across it.
 *
 * Ports live below 32768 deliberately: net.ipv4.ip_local_port_range starts at
 * 32768, and a fixed listener port inside it loses races against the many
 * short-lived TLS connections this suite opens. That failure does not look
 * like a port problem -- the child never listens, the parent burns
 * FakeManager::waitUntilReady()'s full 300s budget, and the run fails on
 * whatever it asserts first.
 */

#include "caBundleFetcher.hpp"
#include "caPublicationState.hpp"
#include "curlHandle.hpp"
#include "curlPerformer.hpp"
#include "fakeManager.hpp"
#include "moduleConfig.hpp"

#include <gtest/gtest.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <unistd.h>

namespace
{
    constexpr std::int64_t HELD = 1789000010;
    constexpr std::int64_t PUBLISHED = 1789000012;

    const LogFn TEST_LOG {"https-client-test"}; // Sink unset: LOGFN_* are no-ops.

    /// Bottom of the jitter window, so a refresh becomes due on the tick after it is armed.
    /// The window itself is unit-tested; waiting one out here would only buy real seconds.
    class NoJitter final : public IRandom
    {
        public:
            double uniform01() override
            {
                return 0.0;
            }
    };

    /// FakeManager takes thirteen positional arguments before the one this suite cares about.
    /// Spelling them out at every call site would read as noise and would quietly shift the
    /// wrong way the next time one is inserted, so they are pinned here once.
    FakeManager caManager(uint16_t port, CaBundleOptions bundle)
    {
        return FakeManager {port, "", /*tls=*/true, 0, {}, 0, 0, {}, {}, 0, 0, {}, 0, bundle};
    }

    /// The ordinary case: a node advertising and serving the same publication.
    CaBundleOptions publishing(std::int64_t generation, int certificates)
    {
        CaBundleOptions bundle;
        bundle.advertisedGeneration = generation;
        bundle.servedGeneration = generation;
        bundle.bundleCertificates = certificates;
        return bundle;
    }

    std::string writeCaFile(const std::string& pem, const char* tag)
    {
        const std::string path =
            ::testing::TempDir() + "hc_ca_refresh_" + tag + "_" + std::to_string(::getpid()) + ".pem";
        std::FILE* file = std::fopen(path.c_str(), "wb");

        if (file == nullptr)
        {
            return {};
        }

        std::fwrite(pem.data(), 1, pem.size(), file);
        std::fclose(file);
        return path;
    }

    ModuleConfig verifiedConfig(uint16_t port, const std::string& caPath)
    {
        hc_config_t config {};
        std::strncpy(config.server_host, "127.0.0.1", sizeof(config.server_host) - 1);
        config.server_port = port;
        std::strncpy(config.agent_id, "001", sizeof(config.agent_id) - 1);
        config.verify_mode = HC_VERIFY_FULL; // Peer AND hostname, against the file below.
        std::strncpy(config.ca_path, caPath.c_str(), sizeof(config.ca_path) - 1);
        // These fixtures verify against a temp file rather than the installed anchor, so the
        // bridge's "is this the agent's own trust store" test would say no. What is under test
        // here is the refresh itself, not that decision (caBundleFetcher_test covers it), so the
        // permission is granted explicitly.
        config.ca_refresh_allowed = true;
        config.request_timeout_ms = 5000;
        // A ramp of effectively zero: the ramp is unit-tested, and what this suite wants from
        // a retry is only that it happens and reaches the server again.
        config.backoff_base_ms = 1;
        config.backoff_cap_ms = 5;
        config.notify_interval_s = 1;
        return ModuleConfig::fromC(config);
    }

    /// Everything a refresh needs, wired to a fake manager that is already running, plus the
    /// record of what crossed the install boundary.
    class Refresher final
    {
        public:
            Refresher(uint16_t port, const std::string& caPath, std::int64_t local = HELD)
                : m_config(verifiedConfig(port, caPath))
                , m_performer(m_config, defaultCurlHandleFactory())
                , m_state(local)
                , m_fetcher(m_config, m_performer, m_fsProbe, m_clock, m_random, m_state,
                            [this](const std::string & pem, std::int64_t generation)
            {
                m_installed.emplace_back(pem, generation);
                return m_consumerAccepts;
            },
            TEST_LOG)
            {
            }

            /// Arms the target, lets the (zero-length) jitter window pass, and runs `attempts`
            /// refreshes. Each attempt is one tick, because a failed one re-arms immediately
            /// on the near-zero ramp configured above.
            void run(std::int64_t advertised, int attempts = 1)
            {
                m_state.observe(advertised);
                m_fetcher.tick(m_waiter); // Schedules the wait.

                for (int attempt = 0; attempt < attempts; attempt++)
                {
                    m_fetcher.tick(m_waiter);
                }
            }

            std::vector<std::pair<std::string, std::int64_t>> m_installed;
            bool m_consumerAccepts {true};

            ModuleConfig m_config;
            CurlPerformer m_performer;
            FsProbe m_fsProbe;
            SystemClock m_clock;
            NoJitter m_random;
            CaPublicationState m_state;
            Waiter m_waiter;
            CaBundleFetcher m_fetcher;
    };

    /// How many certificates a PEM holds, counted by encapsulation boundary rather than by
    /// parsing: this module links no X.509 reader, which is the whole reason the bytes are
    /// handed to the C side to validate.
    size_t certificateCount(const std::string& pem)
    {
        constexpr std::string_view BEGIN {"-----BEGIN CERTIFICATE-----"};
        size_t count = 0;

        for (size_t at = pem.find(BEGIN); at != std::string::npos; at = pem.find(BEGIN, at + BEGIN.size()))
        {
            count++;
        }

        return count;
    }

    /// The fake manager runs in a forked child, so the only way to learn how many times
    /// /cacerts was actually reached is to ask it.
    int cacertsAttempts(uint16_t port)
    {
        httplib::Client peek {std::string {"https://127.0.0.1:"} + std::to_string(port)};
        peek.enable_server_certificate_verification(false);
        const auto result = peek.Get("/peek/cacerts");
        return result && !result->body.empty() ? std::stoi(result->body) : -1;
    }
} // namespace

// The whole path: a bundle of three certificates published at PUBLISHED, fetched over a
// handshake the agent verified against its own anchor, and handed to the consumer byte for
// byte. Three certificates rather than one because that is what a rotation actually
// publishes -- the outgoing anchor beside the incoming one -- and because a single
// certificate would not distinguish "delivered the bundle" from "delivered a certificate".
TEST(CaRefreshComponentTest, AdoptsAPublishedBundleOverAVerifiedConnection)
{
    constexpr uint16_t port = 24930;
    auto manager = caManager(port, publishing(PUBLISHED, /*certificates=*/3));
    const std::string caPath = writeCaFile(manager.tlsCaPem(), "adopt");
    ASSERT_FALSE(caPath.empty());

    Refresher refresher {port, caPath};
    refresher.run(PUBLISHED);

    ASSERT_EQ(1U, refresher.m_installed.size());
    EXPECT_EQ(PUBLISHED, refresher.m_installed[0].second);
    EXPECT_EQ(manager.cacertsPem(), refresher.m_installed[0].first);
    // All three certificates really did travel, so the bundle was not truncated to its first.
    EXPECT_EQ(3U, certificateCount(refresher.m_installed[0].first));
    // The publication is adopted, so nothing is left armed.
    EXPECT_EQ(PUBLISHED, refresher.m_state.local());
    EXPECT_EQ(0, refresher.m_state.pending());

    std::remove(caPath.c_str());
}

// The negative twin of the test above: same server, same bundle, but the agent is pointed at
// an unrelated CA. Without this, "adopted over a verified connection" would be indistinguishable
// from "adopted over a connection nobody verified".
TEST(CaRefreshComponentTest, RefusesABundleFromAnUntrustedManager)
{
    constexpr uint16_t port = 24931;
    auto manager = caManager(port, publishing(PUBLISHED, /*certificates=*/2));
    // The bundle the route serves is a perfectly good PEM -- and entirely the wrong anchor for
    // the certificate the listener presents.
    const std::string wrongCaPath = writeCaFile(manager.cacertsPem(), "untrusted");
    ASSERT_FALSE(wrongCaPath.empty());

    Refresher refresher {port, wrongCaPath};
    refresher.run(PUBLISHED);

    EXPECT_TRUE(refresher.m_installed.empty());
    EXPECT_EQ(HELD, refresher.m_state.local());
    EXPECT_EQ(PUBLISHED, refresher.m_state.pending()); // Still armed: it will try again.

    std::remove(wrongCaPath.c_str());
}

// Rule 5.3's lagging-node case, over the wire rather than in a mock: a node behind a load
// balancer answers with a bundle other than the one just advertised. The header is what
// catches it, and the header only exists if it survives the round trip.
TEST(CaRefreshComponentTest, RefusesABundleServedAtAnotherPublication)
{
    constexpr uint16_t port = 24932;
    auto lagging = publishing(PUBLISHED, /*certificates=*/2);
    lagging.servedGeneration = PUBLISHED - 1; // What the node actually holds.
    auto manager = caManager(port, lagging);
    const std::string caPath = writeCaFile(manager.tlsCaPem(), "lagging");
    ASSERT_FALSE(caPath.empty());

    Refresher refresher {port, caPath};
    refresher.run(PUBLISHED);

    EXPECT_EQ(1, cacertsAttempts(port)); // It really did ask, and really did refuse the answer.
    EXPECT_TRUE(refresher.m_installed.empty());
    EXPECT_EQ(HELD, refresher.m_state.local());
    EXPECT_EQ(PUBLISHED, refresher.m_state.pending());

    std::remove(caPath.c_str());
}

// A node that serves the bundle but vouches for nothing. Distinct from the case above: there
// is no publication to disagree with, which is what a manager predating the feature looks like.
TEST(CaRefreshComponentTest, RefusesABundleServedWithoutAPublicationHeader)
{
    constexpr uint16_t port = 24933;
    auto silent = publishing(PUBLISHED, /*certificates=*/2);
    silent.servedGeneration = 0; // No Wazuh-CA-Generation header at all.
    auto manager = caManager(port, silent);
    const std::string caPath = writeCaFile(manager.tlsCaPem(), "noheader");
    ASSERT_FALSE(caPath.empty());

    Refresher refresher {port, caPath};
    refresher.run(PUBLISHED);

    EXPECT_EQ(1, cacertsAttempts(port));
    EXPECT_TRUE(refresher.m_installed.empty());
    EXPECT_EQ(HELD, refresher.m_state.local());

    std::remove(caPath.c_str());
}

class CaRefreshStatusTest : public ::testing::TestWithParam<std::pair<uint16_t, int>>
{
};

// 404 (this node publishes no bundle), 503 (its bundle does not sign what it serves) and 429
// (the rate limit) all mean the same thing to the trust store: nothing. Each is driven through
// the real HTTP stack rather than asserted about a synthesised response.
TEST_P(CaRefreshStatusTest, AnErrorStatusLeavesTheTrustStoreAloneAndStaysArmed)
{
    const auto [port, status] = GetParam();
    // 429 carries the Retry-After a real rate limiter would send.
    const int retryAfter = status == 429 ? 1 : 0;
    auto failing = publishing(PUBLISHED, /*certificates=*/2);
    failing.forcedStatus = status;
    failing.retryAfterSeconds = retryAfter;
    auto manager = caManager(port, failing);
    const std::string caPath = writeCaFile(manager.tlsCaPem(), "status");
    ASSERT_FALSE(caPath.empty());

    Refresher refresher {port, caPath};
    refresher.run(PUBLISHED);

    EXPECT_EQ(1, cacertsAttempts(port));
    EXPECT_TRUE(refresher.m_installed.empty());
    EXPECT_EQ(HELD, refresher.m_state.local());
    EXPECT_EQ(PUBLISHED, refresher.m_state.pending());

    std::remove(caPath.c_str());
}

INSTANTIATE_TEST_SUITE_P(CacertsErrors,
                         CaRefreshStatusTest,
                         ::testing::Values(std::make_pair(uint16_t {24934}, 404),
                                           std::make_pair(uint16_t {24935}, 503),
                                           std::make_pair(uint16_t {24936}, 429)));

// The point of keeping the target armed: a refusal is not the end of the rotation. Two 503s,
// then the node recovers and the agent adopts on the third attempt without anything re-arming
// it -- no further notify arrives in this test.
TEST(CaRefreshComponentTest, RetriesAfterAFailureAndAdoptsWhenTheNodeRecovers)
{
    constexpr uint16_t port = 24937;
    auto flaky = publishing(PUBLISHED, /*certificates=*/2);
    flaky.forcedStatus = 503;
    flaky.forcedStatusFirstNAttempts = 2;
    auto manager = caManager(port, flaky);
    const std::string caPath = writeCaFile(manager.tlsCaPem(), "recover");
    ASSERT_FALSE(caPath.empty());

    Refresher refresher {port, caPath};
    refresher.run(PUBLISHED, /*attempts=*/3);

    EXPECT_EQ(3, cacertsAttempts(port));
    ASSERT_EQ(1U, refresher.m_installed.size());
    EXPECT_EQ(PUBLISHED, refresher.m_installed[0].second);
    EXPECT_EQ(PUBLISHED, refresher.m_state.local());
    EXPECT_EQ(0, refresher.m_state.pending());

    std::remove(caPath.c_str());
}

// The consumer has the last word: the module cannot parse X.509, so a body that satisfies
// everything the module can see still installs nothing if the C side rejects it. The bytes
// reached the boundary; the trust store did not move.
TEST(CaRefreshComponentTest, AConsumerThatRefusesLeavesThePublicationUnadopted)
{
    constexpr uint16_t port = 24938;
    auto manager = caManager(port, publishing(PUBLISHED, /*certificates=*/2));
    const std::string caPath = writeCaFile(manager.tlsCaPem(), "refused");
    ASSERT_FALSE(caPath.empty());

    Refresher refresher {port, caPath};
    refresher.m_consumerAccepts = false;
    refresher.run(PUBLISHED);

    ASSERT_EQ(1U, refresher.m_installed.size()); // It did reach the consumer.
    EXPECT_EQ(HELD, refresher.m_state.local());  // And was not adopted.
    EXPECT_EQ(PUBLISHED, refresher.m_state.pending());

    std::remove(caPath.c_str());
}
