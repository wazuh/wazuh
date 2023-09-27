/*
 * Wazuh Indexer Connector - ServerSelector tests
 * Copyright (C) 2015, Wazuh Inc.
 * September 08, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "serverSelector_test.hpp"
#include "serverSelector.hpp"
#include <chrono>
#include <memory>
#include <string>
#include <thread>

// Healt check interval for the servers
constexpr auto SERVER_SELECTOR_HEALTH_CHECK_INTERVAL {5u};

/**
 * @brief Test instantiation with valid servers.
 *
 */
TEST_F(ServerSelectorTest, TestInstantiation)
{
    EXPECT_NO_THROW(m_selector = std::make_shared<ServerSelector>(m_servers, SERVER_SELECTOR_HEALTH_CHECK_INTERVAL));
}

/**
 * @brief Test instantiation without servers.
 *
 */
TEST_F(ServerSelectorTest, TestInstantiationWithoutServers)
{
    m_servers.clear();

    // It doesn't throw an exception because the class ServerSelector accepts vector without servers
    EXPECT_NO_THROW(m_selector = std::make_shared<ServerSelector>(m_servers, SERVER_SELECTOR_HEALTH_CHECK_INTERVAL));
}

/**
 * @brief Test instantiation and getNext server before health check.
 *
 */
TEST_F(ServerSelectorTest, TestGetNextBeforeHealthCheck)
{
    const auto hostGreenServer {m_servers.at(0)};
    const auto hostRedServer {m_servers.at(1)};

    std::string nextServer;

    EXPECT_NO_THROW(m_selector = std::make_shared<ServerSelector>(m_servers, SERVER_SELECTOR_HEALTH_CHECK_INTERVAL));

    // It doesn't throw an exception because all servers are available before health check
    EXPECT_NO_THROW(nextServer = m_selector->getNext());
    EXPECT_EQ(nextServer, hostGreenServer);

    // It doesn't throw an exception because all servers are available before health check
    EXPECT_NO_THROW(nextServer = m_selector->getNext());
    EXPECT_EQ(nextServer, hostRedServer);
}

/**
 * @brief Test instantiation and getNext server before and after health check.
 *
 */
TEST_F(ServerSelectorTest, TestGetNextBeforeAndAfterHealthCheck)
{
    const auto hostGreenServer {m_servers.at(0)};
    const auto hostRedServer {m_servers.at(1)};

    std::string nextServer;

    EXPECT_NO_THROW(m_selector = std::make_shared<ServerSelector>(m_servers, SERVER_SELECTOR_HEALTH_CHECK_INTERVAL));

    // It doesn't throw an exception because all servers are available before health check
    EXPECT_NO_THROW(nextServer = m_selector->getNext());
    EXPECT_EQ(nextServer, hostGreenServer);

    // It doesn't throw an exception because all servers are available before health check
    EXPECT_NO_THROW(nextServer = m_selector->getNext());
    EXPECT_EQ(nextServer, hostRedServer);

    // Interval to check the health of the servers
    std::this_thread::sleep_for(std::chrono::seconds(SERVER_SELECTOR_HEALTH_CHECK_INTERVAL + 5));

    // next server will be the green because it's available
    EXPECT_NO_THROW(nextServer = m_selector->getNext());
    EXPECT_EQ(nextServer, hostGreenServer);

    // next server will be the green because the red server isn't available
    EXPECT_NO_THROW(nextServer = m_selector->getNext());
    EXPECT_EQ(nextServer, hostGreenServer);
}

/**
 * @brief Test instantiation and getNext when there are no available servers.
 *
 */
TEST_F(ServerSelectorTest, TestGextNextWhenThereAreNoAvailableServers)
{
    const auto hostRedServer {m_servers.at(1)};

    m_servers.clear();
    m_servers.emplace_back(hostRedServer);

    std::string nextServer;

    EXPECT_NO_THROW(m_selector = std::make_shared<ServerSelector>(m_servers, SERVER_SELECTOR_HEALTH_CHECK_INTERVAL));

    // It doesn't throw an exception because all servers are available before health check
    EXPECT_NO_THROW(nextServer = m_selector->getNext());
    EXPECT_EQ(nextServer, hostRedServer);

    // Interval to check the health of the servers
    std::this_thread::sleep_for(std::chrono::seconds(SERVER_SELECTOR_HEALTH_CHECK_INTERVAL + 5));

    // It throws an exception because there are no available servers
    EXPECT_THROW(nextServer = m_selector->getNext(), std::runtime_error);
}
