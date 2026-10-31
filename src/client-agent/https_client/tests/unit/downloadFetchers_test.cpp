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
#include "fakeSysSeams.hpp"
#include "jwtSigner.hpp"
#include "keyProvider.hpp"
#include "mockCallbackSink.hpp"
#include "mockHttpPerformer.hpp"
#include "wpkFetcher.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstring>

using ::testing::_;
using ::testing::DoAll;
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
