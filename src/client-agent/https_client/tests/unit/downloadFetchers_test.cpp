/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/*
 * What the two /download fetchers ask for (#38514): the config download offers zstd and the WPK
 * download offers nothing. A WPK is already compressed, and #40900's manager never encodes one,
 * so the offer would only buy decoding nobody needs. What curl does with the offer is covered by
 * configDownload_component_test.cpp.
 */

#include "configFetcher.hpp"
#include "digest.hpp"
#include "fakeSysSeams.hpp"
#include "https_client.h"
#include "jwtSigner.hpp"
#include "keyProvider.hpp"
#include "mockCallbackSink.hpp"
#include "mockHttpPerformer.hpp"
#include "wpkFetcher.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <functional>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

using ::testing::_;
using ::testing::DoAll;
using ::testing::Invoke;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::SaveArg;

namespace
{
    /// A 404: not retried, so each fetch() hands exactly one spec to the performer.
    HttpResponse notFound()
    {
        HttpResponse response;
        response.status = TransportStatus::Ok;
        response.httpCode = 404;
        return response;
    }

    class DownloadFetchersTest : public ::testing::Test
    {
        protected:
            DownloadFetchersTest()
                : m_signer("001", m_keyProvider)
                , m_config(makeConfig())
                , m_spoolFactory(::testing::TempDir())
                , m_authGate(m_sink, [] {})
            , m_configFetcher(m_config, m_performer, m_signer, m_clock, m_random, m_spoolFactory, m_authGate,
                              m_compressionGate)
            , m_wpkFetcher(m_config, m_performer, m_signer, m_clock, m_random, m_spoolFactory, m_authGate,
                           m_compressionGate)
            {
            }

            static ModuleConfig makeConfig()
            {
                hc_config_t config {};
                std::strncpy(config.server_host, "127.0.0.1", sizeof(config.server_host) - 1);
                std::strncpy(config.agent_id, "001", sizeof(config.agent_id) - 1);
                config.verify_mode = HC_VERIFY_NONE;
                return ModuleConfig::fromC(config);
            }

            /// The spec the performer received for the one attempt `fetch` makes.
            template<typename Fetch>
            HttpRequestSpec sentBy(Fetch fetch)
            {
                HttpRequestSpec sent;
                EXPECT_CALL(m_performer, perform(_)).WillOnce(DoAll(SaveArg<0>(&sent), Return(notFound())));
                EXPECT_EQ(nullptr, fetch());
                return sent;
            }

            ConfigKeyProvider m_keyProvider {"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"};
            JwtSigner m_signer;
            ModuleConfig m_config;
            FakeClock m_clock;
            ScriptedRandom m_random {{0.0}};
            NiceMock<MockCallbackSink> m_sink;
            MockHttpPerformer m_performer;
            TempSpoolFactory m_spoolFactory;
            AuthGate m_authGate;
            CompressionGate m_compressionGate;
            FakeWaiter m_waiter;
            ConfigFetcher m_configFetcher;
            WpkFetcher m_wpkFetcher;
    };
} // namespace

TEST_F(DownloadFetchersTest, TheConfigDownloadOffersZstd)
{
    const auto sent = sentBy([this]
    {
        return m_configFetcher.fetch("0123abcd", "cfg-token", m_waiter);
    });

    EXPECT_EQ("/download", sent.target);
    EXPECT_EQ("zstd", sent.acceptEncoding);
}

TEST_F(DownloadFetchersTest, TheWpkDownloadOffersNoEncoding)
{
    const auto sent = sentBy([this]
    {
        return m_wpkFetcher.fetch("wazuh_agent.wpk", "0123abcd", m_waiter);
    });

    EXPECT_EQ("/download", sent.target);
    EXPECT_TRUE(sent.acceptEncoding.empty());
}

namespace
{
    // LOGLEVEL_WARNING / LOGLEVEL_DEBUG as the agent defines them (loggerHelper.h).
    constexpr int WARNING_LEVEL {2};
    constexpr int DEBUG_LEVEL {0};

    /// The module's log lines while captureModuleLog() is the agent's log callback and a
    /// ConfigDownloadLogTest runs. A C log callback carries no user data, so they live here.
    struct ModuleLog
    {
        std::mutex mutex;
        std::vector<std::pair<int, std::string>> lines;
        std::atomic<bool> recording {false}; ///< The callback outlives the test: off between tests.
    };

    ModuleLog g_moduleLog;

    void captureModuleLog(const int level, const char*, const char*, const int, const char*, const char* message,
                          va_list args)
    {
        if (!g_moduleLog.recording.load())
        {
            return;
        }

        char line[1024];
        std::vsnprintf(line, sizeof(line), message, args);
        const std::lock_guard<std::mutex> lock(g_moduleLog.mutex);
        g_moduleLog.lines.emplace_back(level, line);
    }

    /// Points the module's log at captureModuleLog() through an hc_enroll() its transport check
    /// rejects before any network I/O: the one entry point that installs a callback without a
    /// running handle. The module keeps forwarding to it until another call installs another,
    /// which is why recording is switched on only for the test.
    void captureTheModuleLog()
    {
        hc_config_t config {};
        std::strncpy(config.server_host, "127.0.0.1", sizeof(config.server_host) - 1);
        config.server_port = 9;
        config.verify_mode = HC_VERIFY_FULL;
        hc_enroll_request_t request {};
        request.log = captureModuleLog;
        hc_enroll_result_t result {};
        hc_enroll(&config, &request, &result);

        g_moduleLog.recording.store(true); // After the enrollment's own rejection.
    }

    void stopCapturingTheModuleLog()
    {
        g_moduleLog.recording.store(false);
        const std::lock_guard<std::mutex> lock(g_moduleLog.mutex);
        g_moduleLog.lines.clear();
    }

    std::vector<std::string> loggedAt(int level, const std::string& needle)
    {
        const std::lock_guard<std::mutex> lock(g_moduleLog.mutex);
        std::vector<std::string> found;

        for (const auto& [lineLevel, text] : g_moduleLog.lines)
        {
            if (lineLevel == level && text.find(needle) != std::string::npos)
            {
                found.push_back(text);
            }
        }

        return found;
    }

    HttpResponse failedAttempt(TransportStatus status, std::string curlError, bool decodingFailed)
    {
        HttpResponse response;
        response.status = status;
        response.curlError = std::move(curlError);
        response.contentDecodingFailed = decodingFailed;
        return response;
    }

    const HttpResponse UNDECODABLE = failedAttempt(TransportStatus::OtherError, "(61) Unrecognized content encoding type", true);

    constexpr auto UNDECODABLE_WARNING = "could not be decoded";

    /// What ConfigFetcher logs about failed config downloads.
    class ConfigDownloadLogTest : public DownloadFetchersTest
    {
        protected:
            void SetUp() override
            {
                captureTheModuleLog();
                EXPECT_CALL(m_performer, perform(_)).WillRepeatedly(Invoke([this](const HttpRequestSpec & spec)
                {
                    return m_reply(spec);
                }));
            }

            void TearDown() override
            {
                stopCapturingTheModuleLog();
            }

            void answer(const HttpResponse& response)
            {
                m_reply = [response](const HttpRequestSpec&)
                {
                    return response;
                };
            }

            /// A 200 that writes `merged` where the fetcher spools the download.
            void deliver(const std::string& merged)
            {
                m_reply = [merged](const HttpRequestSpec & spec)
                {
                    std::ofstream {spec.responseFilePath, std::ios::binary} << merged;
                    HttpResponse response;
                    response.status = TransportStatus::Ok;
                    response.httpCode = 200;
                    return response;
                };
            }

            /// One fetch() that runs its retry, as the control thread does when it isn't stopping.
            std::shared_ptr<SpoolFile> fetch(const std::string& expectedHash = "0123abcd")
            {
                m_waiter.script({true});
                return m_configFetcher.fetch(expectedHash, "cfg-token", m_waiter);
            }

            std::function<HttpResponse(const HttpRequestSpec&)> m_reply;
    };
} // namespace

// It comes back the same on every notify, so one line per window, counting the ones it stands for.
TEST_F(ConfigDownloadLogTest, AnUndecodableDownloadWarnsOncePerWindow)
{
    answer(UNDECODABLE);

    fetch();
    fetch();
    EXPECT_EQ(1u, loggedAt(WARNING_LEVEL, UNDECODABLE_WARNING).size());

    m_clock.advance(std::chrono::seconds {91});
    fetch();
    const auto warnings = loggedAt(WARNING_LEVEL, UNDECODABLE_WARNING);
    ASSERT_EQ(2u, warnings.size());
    EXPECT_NE(std::string::npos, warnings.back().find("(1 more suppressed in the last 90s)")) << warnings.back();
}

// After a download that worked, a decoding failure is a new incident, reported at once.
TEST_F(ConfigDownloadLogTest, ADeliveredDownloadReArmsTheWarning)
{
    const std::string merged = "#merged.mg\n";

    answer(UNDECODABLE);
    fetch();
    deliver(merged);
    EXPECT_NE(nullptr, fetch(sha256Hex(merged.data(), merged.size())));
    answer(UNDECODABLE);
    fetch();

    EXPECT_EQ(2u, loggedAt(WARNING_LEVEL, UNDECODABLE_WARNING).size());
}

TEST_F(ConfigDownloadLogTest, ARefusedCodingIsWarnedAboutWithTheRefusal)
{
    answer(failedAttempt(TransportStatus::OtherError,
                         "(23) Failed writing header; refused Content-Encoding 'zstd, zstd': more than one coding", true));

    fetch();

    const auto warnings = loggedAt(WARNING_LEVEL, UNDECODABLE_WARNING);
    ASSERT_EQ(1u, warnings.size());
    EXPECT_NE(std::string::npos, warnings.front().find("refused Content-Encoding 'zstd, zstd'")) << warnings.front();
}

// Stopping during the wait before the retry isn't a decoding problem to warn about.
TEST_F(ConfigDownloadLogTest, AShutdownBeforeTheRetryIsNotWarnedAbout)
{
    answer(UNDECODABLE);

    m_configFetcher.fetch("0123abcd", "cfg-token", m_waiter); // The waiter says stop.

    EXPECT_TRUE(loggedAt(WARNING_LEVEL, UNDECODABLE_WARNING).empty());
    EXPECT_FALSE(loggedAt(DEBUG_LEVEL, "failed (Interrupted)").empty());
}

// The next notify usually fixes these, so they stay out of the default log level.
TEST_F(ConfigDownloadLogTest, OtherFailedDownloadsStayAtDebugLevel)
{
    answer(failedAttempt(TransportStatus::Timeout, "(28) Operation timed out", false));

    fetch();

    EXPECT_TRUE(loggedAt(WARNING_LEVEL, UNDECODABLE_WARNING).empty());
    EXPECT_FALSE(loggedAt(DEBUG_LEVEL, "Config download for resource 'cfg-token' failed").empty());
}

