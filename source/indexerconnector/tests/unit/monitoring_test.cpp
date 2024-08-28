/*
 * Wazuh Indexer Connector - Monitoring tests
 * Copyright (C) 2015, Wazuh Inc.
 * September 08, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "base/logging.hpp"
#include "fakeOpenSearchServer.hpp"
#include "monitoring.hpp"
#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <thread>

/**
 * @brief Runs unit tests for Monitoring class
 */
class MonitoringTest : public ::testing::Test
{
protected:
    inline static std::unique_ptr<FakeOpenSearchServer>
        m_fakeOpenSearchGreenServer; ///< pointer to FakeOpenSearchServer class

    inline static std::unique_ptr<FakeOpenSearchServer>
        m_fakeOpenSearchRedServer; ///< pointer to FakeOpenSearchServer class

    std::shared_ptr<Monitoring> m_monitoring; ///< pointer to Monitoring class

    std::vector<std::string> m_servers; ///< Servers

    /**
     * @brief Sets initial conditions for each test case.
     */
    // cppcheck-suppress unusedFunction
    void SetUp() override
    {
        logging::testInit();
        // Register the host and port of the green server
        m_servers.emplace_back("http://localhost:9209");
        // Register the host and port of the red server
        m_servers.emplace_back("http://localhost:9210");
    }

    /**
     * @brief Creates the fakeOpenSearchServers for the runtime of the test suite
     */
    // cppcheck-suppress unusedFunction
    static void SetUpTestSuite()
    {
        const std::string host {"localhost"};

        if (!m_fakeOpenSearchGreenServer)
        {
            m_fakeOpenSearchGreenServer = std::make_unique<FakeOpenSearchServer>(host, 9209, "green");
        }

        if (!m_fakeOpenSearchRedServer)
        {
            m_fakeOpenSearchRedServer = std::make_unique<FakeOpenSearchServer>(host, 9210, "red");
        }
    }

    /**
     * @brief Resets fakeOpenSearchServers causing the shutdown of the test server.
     */
    // cppcheck-suppress unusedFunction
    static void TearDownTestSuite()
    {
        m_fakeOpenSearchGreenServer.reset();
        m_fakeOpenSearchRedServer.reset();
    }
};

// Healt check interval for the servers
constexpr auto MONITORING_HEALTH_CHECK_INTERVAL {5u};

/**
 * @brief Test instantiation and check the availability of valid servers.
 *
 */
TEST_F(MonitoringTest, TestInstantiationWithValidServers)
{
    const auto hostGreenServer {m_servers.at(0)};
    const auto hostRedServer {m_servers.at(1)};

    EXPECT_NO_THROW(m_monitoring = std::make_shared<Monitoring>(m_servers, MONITORING_HEALTH_CHECK_INTERVAL));

    // All servers are available the first time.
    EXPECT_TRUE(m_monitoring->isAvailable(hostGreenServer));
    EXPECT_TRUE(m_monitoring->isAvailable(hostRedServer));

    // Interval to check the health of the servers
    std::this_thread::sleep_for(std::chrono::seconds(MONITORING_HEALTH_CHECK_INTERVAL + 5));

    // It's true because the green server is available
    EXPECT_TRUE(m_monitoring->isAvailable(hostGreenServer));

    // It's false because the red server isn't available
    EXPECT_FALSE(m_monitoring->isAvailable(hostRedServer));
}

/**
 * @brief Test instantiation without servers.
 *
 */
TEST_F(MonitoringTest, TestInstantiationWithoutServers)
{
    m_servers.clear();

    // It doesn't throw an exception because the class Monitoring accepts vector without servers
    EXPECT_NO_THROW(m_monitoring = std::make_shared<Monitoring>(m_servers, MONITORING_HEALTH_CHECK_INTERVAL));
}

/**
 * @brief Test instantiation and check the availability of an invalid server.
 *
 */
TEST_F(MonitoringTest, TestInvalidServer)
{
    const auto invalidServer {"http://localhost:9400"};

    m_servers.clear();
    m_servers.emplace_back(invalidServer);

    EXPECT_NO_THROW(m_monitoring = std::make_shared<Monitoring>(m_servers, MONITORING_HEALTH_CHECK_INTERVAL));

    // All servers are available the first time
    EXPECT_TRUE(m_monitoring->isAvailable(invalidServer));

    // Interval to check the health of the servers
    std::this_thread::sleep_for(std::chrono::seconds(MONITORING_HEALTH_CHECK_INTERVAL + 5));

    // It's false because the server isn't valid
    EXPECT_FALSE(m_monitoring->isAvailable(invalidServer));
}

/**
 * @brief Test instantiation and check the availability of an unregistered server.
 *
 */
TEST_F(MonitoringTest, TestCheckIfAnUnregisteredServerIsAvailable)
{
    const auto unregisteredServer {"http://localhost:9400"};
    const auto hostGreenServer {m_servers.at(0)};
    const auto hostRedServer {m_servers.at(1)};

    EXPECT_NO_THROW(m_monitoring = std::make_shared<Monitoring>(m_servers, MONITORING_HEALTH_CHECK_INTERVAL));

    // All servers are available the first time
    EXPECT_TRUE(m_monitoring->isAvailable(hostGreenServer));
    EXPECT_TRUE(m_monitoring->isAvailable(hostRedServer));

    // Interval to check the health of the servers
    std::this_thread::sleep_for(std::chrono::seconds(MONITORING_HEALTH_CHECK_INTERVAL + 5));

    // It's true because the green server is available
    EXPECT_TRUE(m_monitoring->isAvailable(hostGreenServer));

    // It's false because the red server isn't available
    EXPECT_FALSE(m_monitoring->isAvailable(hostRedServer));

    // It throws an exception because this is an unregistered server
    EXPECT_THROW(m_monitoring->isAvailable(unregisteredServer), std::out_of_range);
}
