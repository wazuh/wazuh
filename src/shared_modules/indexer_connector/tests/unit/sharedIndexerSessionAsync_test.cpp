/*
 * Wazuh Indexer Connector - shared monitor tests (async connector)
 * Copyright (C) 2015, Wazuh Inc.
 * July 30, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "sharedIndexerSession_test.hpp"

#include "indexerConnectorAsyncImpl.hpp"

using shared_session_test::baseConfig;
using shared_session_test::hosts;

// Separate translation unit from sharedIndexerSession_test.cpp -- see the layout note in
// sharedIndexerSession_test.hpp: the two Impl headers cannot coexist in one TU.
using SharedMonitorAsyncTest = SharedMonitorTestBase;

/// The other half of the "N connectors, one health-check round" guarantee: the async connector, like
/// the sync one, must run no health checks of its own when handed a pre-built selector.
TEST_F(SharedMonitorAsyncTest, AnAsyncConnectorGivenASharedSelectorRunsNoHealthChecksOfItsOwn)
{
    auto monitor = makeSharedMonitor();
    const auto afterMonitor = m_healthChecks.load();
    ASSERT_EQ(static_cast<int>(hosts().size()), afterMonitor);

    IndexerConnectorAsyncImpl<TServerSelector<MockHTTPRequest>, MockHTTPRequest> connector {
        baseConfig(), nullptr, m_mockHttpRequest.get(), makeSelectorOver(monitor), "", SecureCommunication {}};

    EXPECT_EQ(afterMonitor, m_healthChecks.load());
    EXPECT_TRUE(connector.isAvailable());
}

TEST_F(SharedMonitorAsyncTest, AnInjectedSecureCommunicationSkipsTheSslAndKeystoreBlock)
{
    auto config = baseConfig();
    config["ssl"]["certificate_authorities"] = {"/nonexistent/definitely-not-a-real-ca.pem"};

    auto monitor = makeSharedMonitor();

    EXPECT_NO_THROW(({
        IndexerConnectorAsyncImpl<TServerSelector<MockHTTPRequest>, MockHTTPRequest> connector(
            config, nullptr, m_mockHttpRequest.get(), makeSelectorOver(monitor), "", SecureCommunication {});
    }));
}

TEST_F(SharedMonitorAsyncTest, WithoutAnInjectedSecureCommunicationABadCaPathStillThrows)
{
    auto config = baseConfig();
    config["ssl"]["certificate_authorities"] = {"/nonexistent/definitely-not-a-real-ca.pem"};

    auto monitor = makeSharedMonitor();

    EXPECT_THROW(({
                     IndexerConnectorAsyncImpl<TServerSelector<MockHTTPRequest>, MockHTTPRequest> connector(
                         config, nullptr, m_mockHttpRequest.get(), makeSelectorOver(monitor));
                 }),
                 IndexerConnectorException);
}

TEST_F(SharedMonitorAsyncTest, AMissingHostsListIsRejectedBeforeTheCaPathIsEvenLookedAt)
{
    nlohmann::json config;
    config["ssl"]["certificate_authorities"] = {"/nonexistent/definitely-not-a-real-ca.pem"};

    try
    {
        IndexerConnectorAsyncImpl<TServerSelector<MockHTTPRequest>, MockHTTPRequest> connector(
            config, nullptr, m_mockHttpRequest.get());
        FAIL() << "a configuration without hosts must be rejected";
    }
    catch (const IndexerConnectorException& e)
    {
        EXPECT_STREQ("No hosts found in the configuration", e.what());
    }
}
