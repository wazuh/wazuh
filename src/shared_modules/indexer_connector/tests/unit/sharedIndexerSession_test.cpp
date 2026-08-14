/*
 * Wazuh Indexer Connector - shared monitor / transport tests (selector, transport, sync connector)
 * Copyright (C) 2015, Wazuh Inc.
 * July 30, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "sharedIndexerSession_test.hpp"

#include "indexerConnectorSyncImpl.hpp"
#include "indexerTransport.hpp"
#include <filesystem>
#include <fstream>
#include <stdexcept>

using shared_session_test::baseConfig;
using shared_session_test::hosts;

using SharedMonitorTest = SharedMonitorTestBase;

/**
 * The whole point of the shared-monitor constructor: adopting a monitor must cost no health-check
 * I/O at all. A selector that quietly built its own would double the count here.
 */
TEST_F(SharedMonitorTest, AdoptingAMonitorPerformsNoAdditionalHealthChecks)
{
    auto monitor = makeSharedMonitor();
    const auto afterMonitor = m_healthChecks.load();
    ASSERT_EQ(static_cast<int>(hosts().size()), afterMonitor);

    const auto selector = makeSelectorOver(monitor);

    EXPECT_EQ(afterMonitor, m_healthChecks.load());
    EXPECT_TRUE(selector->isAvailable());
}

TEST_F(SharedMonitorTest, SeveralSelectorsOverOneMonitorStillCheckHealthOnlyOnce)
{
    auto monitor = makeSharedMonitor();

    const auto first = makeSelectorOver(monitor);
    const auto second = makeSelectorOver(monitor);

    EXPECT_EQ(static_cast<int>(hosts().size()), m_healthChecks.load())
        << "the monitor's single startup round must not be repeated per selector";
    EXPECT_TRUE(first->isAvailable());
    EXPECT_TRUE(second->isAvailable());
}

TEST_F(SharedMonitorTest, AdoptingANullMonitorIsRejected)
{
    EXPECT_THROW(({ TServerSelector<MockHTTPRequest> selector(nullptr, hosts()); }), std::runtime_error);
}

/// A selector whose monitor does not know the requested host would throw std::out_of_range on the
/// first getNext(); this pins that the monitor's map really is what gates availability.
TEST_F(SharedMonitorTest, AHostTheMonitorDoesNotKnowIsRejectedOnUse)
{
    auto monitor = makeSharedMonitor();
    TServerSelector<MockHTTPRequest> selector {monitor, {"http://localhost:19999"}};

    EXPECT_THROW(selector.getNext(), std::out_of_range);
}

/// Half of the "N connectors, one health-check round" guarantee: a connector handed a pre-built
/// selector must not build one of its own.
TEST_F(SharedMonitorTest, ASyncConnectorGivenASharedSelectorRunsNoHealthChecksOfItsOwn)
{
    auto monitor = makeSharedMonitor();
    const auto afterMonitor = m_healthChecks.load();
    ASSERT_EQ(static_cast<int>(hosts().size()), afterMonitor);

    IndexerConnectorSyncImpl<TServerSelector<MockHTTPRequest>, MockHTTPRequest> connector {
        baseConfig(), nullptr, m_mockHttpRequest.get(), makeSelectorOver(monitor), "", SecureCommunication {}};

    EXPECT_EQ(afterMonitor, m_healthChecks.load());
    EXPECT_TRUE(connector.isAvailable());
}

/**
 * Pins that an injected SecureCommunication really replaces the ssl/keystore block rather than being
 * merged with it: a CA path that does not exist would throw if that block still ran.
 */
TEST_F(SharedMonitorTest, AnInjectedSecureCommunicationSkipsTheSslAndKeystoreBlock)
{
    auto config = baseConfig();
    config["ssl"]["certificate_authorities"] = {"/nonexistent/definitely-not-a-real-ca.pem"};

    auto monitor = makeSharedMonitor();

    EXPECT_NO_THROW(({
        IndexerConnectorSyncImpl<TServerSelector<MockHTTPRequest>, MockHTTPRequest> connector(
            config, nullptr, m_mockHttpRequest.get(), makeSelectorOver(monitor), "", SecureCommunication {});
    }));
}

/// Without an injected SecureCommunication the same configuration must still be rejected -- the
/// validation is skipped only because someone else already did it, never dropped outright.
TEST_F(SharedMonitorTest, WithoutAnInjectedSecureCommunicationABadCaPathStillThrows)
{
    auto config = baseConfig();
    config["ssl"]["certificate_authorities"] = {"/nonexistent/definitely-not-a-real-ca.pem"};

    auto monitor = makeSharedMonitor();

    EXPECT_THROW(({
                     IndexerConnectorSyncImpl<TServerSelector<MockHTTPRequest>, MockHTTPRequest> connector(
                         config, nullptr, m_mockHttpRequest.get(), makeSelectorOver(monitor));
                 }),
                 IndexerConnectorException);
}

/// `hosts` is now checked before anything else, so a hosts-less configuration is rejected without
/// reaching the ssl block -- which is what keeps it from opening `queue/keystore` on that path.
TEST_F(SharedMonitorTest, AMissingHostsListIsRejectedBeforeTheCaPathIsEvenLookedAt)
{
    nlohmann::json config;
    config["ssl"]["certificate_authorities"] = {"/nonexistent/definitely-not-a-real-ca.pem"};

    try
    {
        IndexerConnectorSyncImpl<TServerSelector<MockHTTPRequest>, MockHTTPRequest> connector(
            config, nullptr, m_mockHttpRequest.get());
        FAIL() << "a configuration without hosts must be rejected";
    }
    catch (const IndexerConnectorException& e)
    {
        EXPECT_STREQ("No hosts found in the configuration", e.what());
    }
}

class BuildSecureCommunicationTest : public ::testing::Test
{
};

TEST_F(BuildSecureCommunicationTest, ANonexistentSingleCaFileThrows)
{
    nlohmann::json config;
    config["ssl"]["certificate_authorities"] = {"/nonexistent/definitely-not-a-real-ca.pem"};

    EXPECT_THROW(buildSecureCommunication(config, LogFn {"test"}), IndexerConnectorException);
}

TEST_F(BuildSecureCommunicationTest, AnExistingCaFileIsAccepted)
{
    const auto path = std::filesystem::temp_directory_path() / "indexer_connector_test_ca.pem";
    {
        std::ofstream file {path};
        file << "not a real certificate, only its existence is checked here\n";
    }

    nlohmann::json config;
    config["ssl"]["certificate_authorities"] = {path.string()};

    EXPECT_NO_THROW(buildSecureCommunication(config, LogFn {"test"}));

    std::filesystem::remove(path);
}

/// `hosts` is deliberately NOT this function's business -- callers check it first, before anything
/// here can open the keystore.
TEST_F(BuildSecureCommunicationTest, AMissingHostsListIsNotThisFunctionsConcern)
{
    EXPECT_NO_THROW(buildSecureCommunication(nlohmann::json::object(), LogFn {"test"}));
}
