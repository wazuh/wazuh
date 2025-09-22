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

namespace Log
{
    std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>
        GLOBAL_LOG_FUNCTION;
}; // namespace Log

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
    const auto hostYellowServer {m_servers.at(2)};

    std::string nextServer;

    EXPECT_NO_THROW(m_selector = std::make_shared<ServerSelector>(m_servers, SERVER_SELECTOR_HEALTH_CHECK_INTERVAL));

    // It doesn't throw an exception because the green and yellow servers are available
    EXPECT_NO_THROW(nextServer = m_selector->getNext());
    EXPECT_EQ(nextServer, hostGreenServer);

    // It doesn't throw an exception because the green and yellow servers are available
    EXPECT_NO_THROW(nextServer = m_selector->getNext());
    EXPECT_EQ(nextServer, hostYellowServer);
}

/**
 * @brief Test instantiation and getNext server before and after health check.
 *
 */
TEST_F(ServerSelectorTest, TestGetNextBeforeAndAfterHealthCheck)
{
    const auto hostGreenServer {m_servers.at(0)};
    const auto hostYellowServer {m_servers.at(2)};

    std::string nextServer;

    EXPECT_NO_THROW(m_selector = std::make_shared<ServerSelector>(m_servers, SERVER_SELECTOR_HEALTH_CHECK_INTERVAL));

    // It doesn't throw an exception because yellow and green servers are available before health check
    EXPECT_NO_THROW(nextServer = m_selector->getNext());
    EXPECT_EQ(nextServer, hostGreenServer);

    // It doesn't throw an exception because the green and yellow servers are available
    EXPECT_NO_THROW(nextServer = m_selector->getNext());
    EXPECT_EQ(nextServer, hostYellowServer);

    // Interval to check the health of the servers
    std::this_thread::sleep_for(std::chrono::seconds(SERVER_SELECTOR_HEALTH_CHECK_INTERVAL + 5));

    // Next server will be the green because is the next available server
    EXPECT_NO_THROW(nextServer = m_selector->getNext());
    EXPECT_EQ(nextServer, hostGreenServer);

    // Next server will be the yellow because the red server isn't available
    EXPECT_NO_THROW(nextServer = m_selector->getNext());
    EXPECT_EQ(nextServer, hostYellowServer);
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

    // It throws an exception because there are no available servers
    EXPECT_THROW(nextServer = m_selector->getNext(), std::runtime_error);
}
