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

#include "monitoring_test.hpp"
#include "monitoring.hpp"
#include <chrono>
#include <memory>
#include <thread>

// Healt check interval for the servers
constexpr auto MONITORING_HEALTH_CHECK_INTERVAL {5u};

namespace Log
{
    std::function<void(
        const int, const std::string&, const std::string&, const int, const std::string&, const std::string&, va_list)>
        GLOBAL_LOG_FUNCTION;
}; // namespace Log

/**
 * @brief Test instantiation and check the availability of valid servers.
 *
 */
TEST_F(MonitoringTest, TestInstantiationWithValidServers)
{
    const auto hostGreenServer {m_servers.at(0)};
    const auto hostRedServer {m_servers.at(1)};

    std::vector<std::string> serverLogs;
    Log::assignLogFunction(
        [&](const int,
            const std::string& tag,
            const std::string& file,
            const int line,
            const std::string&,
            const std::string& str,
            va_list args)
        {
            char formattedStr[MAXLEN] = {0};
            vsnprintf(formattedStr, MAXLEN, str.c_str(), args);
            serverLogs.emplace_back(formattedStr);
        });

    EXPECT_NO_THROW(m_monitoring = std::make_shared<Monitoring>(m_servers, MONITORING_HEALTH_CHECK_INTERVAL));

    // All servers are available the first time.
    EXPECT_TRUE(m_monitoring->isAvailable(hostGreenServer));
    EXPECT_TRUE(m_monitoring->isAvailable(hostRedServer));

    // Interval to check the health of the servers
    std::this_thread::sleep_for(std::chrono::seconds(MONITORING_HEALTH_CHECK_INTERVAL + 5));

    // Only two log messages are expected.
    EXPECT_EQ(serverLogs.size(), 2);
    EXPECT_TRUE(std::find(serverLogs.begin(),
                          serverLogs.end(),
                          "Cluster health status 'GREEN' for server 'http://localhost:9209'") != serverLogs.end());
    EXPECT_TRUE(std::find(serverLogs.begin(),
                          serverLogs.end(),
                          "Cluster health status 'RED' for server 'http://localhost:9210'") != serverLogs.end());

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

    std::string logMessage;
    Log::assignLogFunction(
        [&](const int,
            const std::string& tag,
            const std::string& file,
            const int line,
            const std::string&,
            const std::string& str,
            va_list args)
        {
            char formattedStr[MAXLEN] = {0};
            vsnprintf(formattedStr, MAXLEN, str.c_str(), args);
            logMessage = formattedStr;
        });

    EXPECT_NO_THROW(m_monitoring = std::make_shared<Monitoring>(m_servers, MONITORING_HEALTH_CHECK_INTERVAL));

    // All servers are available the first time
    EXPECT_TRUE(m_monitoring->isAvailable(invalidServer));

    // Interval to check the health of the servers
    std::this_thread::sleep_for(std::chrono::seconds(MONITORING_HEALTH_CHECK_INTERVAL + 5));

    EXPECT_STREQ(logMessage.c_str(), "Couldn't connect to server (Status code: -1)");

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

/**
 * @brief Test instantiation and check the bad response of a server.
 *
 */
TEST_F(MonitoringTest, TestHTTPError)
{
    const auto invalidServer {"http://localhost:9211"};

    m_servers.clear();
    m_servers.emplace_back(invalidServer);

    std::string logMessage;
    Log::assignLogFunction(
        [&](const int,
            const std::string& tag,
            const std::string& file,
            const int line,
            const std::string&,
            const std::string& str,
            va_list args)
        {
            char formattedStr[MAXLEN] = {0};
            vsnprintf(formattedStr, MAXLEN, str.c_str(), args);
            logMessage = formattedStr;
        });

    EXPECT_NO_THROW(m_monitoring = std::make_shared<Monitoring>(m_servers, MONITORING_HEALTH_CHECK_INTERVAL));

    // All servers are available the first time
    EXPECT_TRUE(m_monitoring->isAvailable(invalidServer));

    // Interval to check the health of the servers
    std::this_thread::sleep_for(std::chrono::seconds(MONITORING_HEALTH_CHECK_INTERVAL + 5));

    EXPECT_STREQ(logMessage.c_str(), "HTTP response code said error (Status code: 503)");

    // It's false because the server isn't valid
    EXPECT_FALSE(m_monitoring->isAvailable(invalidServer));
}

/**
 * @brief Test instantiation and check the bad response of a server.
 *
 */
TEST_F(MonitoringTest, TestBadResponseFromServer)
{
    const auto invalidServer {"http://localhost:9212"};

    m_servers.clear();
    m_servers.emplace_back(invalidServer);

    std::string logMessage;
    Log::assignLogFunction(
        [&](const int,
            const std::string& tag,
            const std::string& file,
            const int line,
            const std::string&,
            const std::string& str,
            va_list args)
        {
            char formattedStr[MAXLEN] = {0};
            vsnprintf(formattedStr, MAXLEN, str.c_str(), args);
            logMessage = formattedStr;
        });

    EXPECT_NO_THROW(m_monitoring = std::make_shared<Monitoring>(m_servers, MONITORING_HEALTH_CHECK_INTERVAL));

    // All servers are available the first time
    EXPECT_TRUE(m_monitoring->isAvailable(invalidServer));

    // Interval to check the health of the servers
    std::this_thread::sleep_for(std::chrono::seconds(MONITORING_HEALTH_CHECK_INTERVAL + 5));

    EXPECT_STREQ(logMessage.c_str(), "Invalid response from /_cat/health?v: Wrong response message from server");

    // It's false because the server isn't valid
    EXPECT_FALSE(m_monitoring->isAvailable(invalidServer));
}
