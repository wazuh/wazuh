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

#include "mocks/MockHTTPRequest.hpp"
#include "monitoring.hpp"
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <thread>

// Healt check interval for the servers
constexpr auto MONITORING_HEALTH_CHECK_INTERVAL {1u};
constexpr auto MONITORING_HEALTH_CHECK_INTERVAL_ZERO {0u};

/**
 * @brief Runs unit tests for Monitoring class
 */
class MonitoringTest : public ::testing::Test
{
protected:
    MockHTTPRequest m_mockHttpRequest; ///< Mock HTTP request object

    using TestMonitoring = TMonitoring<MockHTTPRequest>;
};

/**
 * @brief Test instantiation and check the availability of valid servers.
 *
 */
TEST_F(MonitoringTest, TestInstantiationWithValidServers)
{
    std::vector<std::string> servers;
    servers.emplace_back("http://localhost:9000");
    servers.emplace_back("http://localhost:9110");
    servers.emplace_back("http://localhost:9200");

    const auto& hostGreenServer {servers.at(0)};
    const auto& hostRedServer {servers.at(1)};
    const auto& hostYellowServer {servers.at(2)};

    // Set up mock expectations for different server responses
    EXPECT_CALL(m_mockHttpRequest, get(::testing::_, ::testing::_, ::testing::_))
        .WillRepeatedly(::testing::Invoke(
            [](const auto& requestParams, const auto& postParams, const auto& /*configParams*/)
            {
                const auto& url = std::get<TRequestParameters<std::string>>(requestParams).url.url();
                if (url.find("localhost:9000") != std::string::npos)
                {
                    // Green server - healthy response
                    postParams.onSuccess(R"([{"status":"green"}])");
                }
                else if (url.find("localhost:9110") != std::string::npos)
                {
                    // Red server - unhealthy response
                    postParams.onError("Connection failed", 503);
                }
                else if (url.find("localhost:9200") != std::string::npos)
                {
                    // Yellow server - warning but available
                    postParams.onSuccess(R"([{"status":"yellow"}])");
                }
                else if (url.find("localhost:9300") != std::string::npos)
                {
                    // Green server with delay - healthy response
                    postParams.onSuccess(R"([{"status":"green"}])");
                }
            }));

    std::shared_ptr<TestMonitoring> monitoring;
    EXPECT_NO_THROW(monitoring = std::make_shared<TestMonitoring>(
                        servers, MONITORING_HEALTH_CHECK_INTERVAL, SecureCommunication {}, &m_mockHttpRequest));

    // All servers have their corresponding status the first time
    EXPECT_TRUE(monitoring->isAvailable(hostGreenServer));
    EXPECT_FALSE(monitoring->isAvailable(hostRedServer));
    EXPECT_TRUE(monitoring->isAvailable(hostYellowServer));
}

/**
 * @brief Test instantiation without servers.
 *
 */
TEST_F(MonitoringTest, TestInstantiationWithoutServers)
{
    std::vector<std::string> servers;

    // No HTTP calls should be made for empty server list
    EXPECT_CALL(m_mockHttpRequest, get(::testing::_, ::testing::_, ::testing::_)).Times(0);

    // It doesn't throw an exception because the class Monitoring accepts vector without servers
    std::shared_ptr<TestMonitoring> monitoring;
    EXPECT_NO_THROW(monitoring = std::make_shared<TestMonitoring>(
                        servers, MONITORING_HEALTH_CHECK_INTERVAL, SecureCommunication {}, &m_mockHttpRequest));
}

/**
 * @brief Test instantiation and check the availability of an unregistered server.
 *
 */
TEST_F(MonitoringTest, TestCheckIfAnUnregisteredServerIsAvailable)
{
    std::vector<std::string> servers;
    servers.emplace_back("http://localhost:9000");
    servers.emplace_back("http://localhost:9110");
    servers.emplace_back("http://localhost:9200");
    servers.emplace_back("http://localhost:9300");

    const auto unregisteredServer {"http://localhost:1000"};
    const auto& hostGreenServer {servers.at(0)};
    const auto& hostRedServer {servers.at(1)};

    // Set up mock expectations for registered servers
    EXPECT_CALL(m_mockHttpRequest, get(::testing::_, ::testing::_, ::testing::_))
        .WillRepeatedly(::testing::Invoke(
            [](const auto& requestParams, const auto& postParams, const auto& /*configParams*/)
            {
                const auto& url = std::get<TRequestParameters<std::string>>(requestParams).url.url();
                if (url.find("localhost:9000") != std::string::npos)
                {
                    // Green server - healthy response
                    postParams.onSuccess(R"([{"status":"green"}])");
                }
                else if (url.find("localhost:9110") != std::string::npos)
                {
                    // Red server - unhealthy response
                    postParams.onError("Connection failed", 503);
                }
                else
                {
                    // Other servers return success by default
                    postParams.onSuccess(R"([{"status":"green"}])");
                }
            }));

    std::shared_ptr<TestMonitoring> monitoring;
    EXPECT_NO_THROW(monitoring = std::make_shared<TestMonitoring>(
                        servers, MONITORING_HEALTH_CHECK_INTERVAL, SecureCommunication {}, &m_mockHttpRequest));

    // All servers have their corresponding status the first time
    EXPECT_TRUE(monitoring->isAvailable(hostGreenServer));
    EXPECT_FALSE(monitoring->isAvailable(hostRedServer));

    // It throws an exception because this is an unregistered server
    EXPECT_THROW(monitoring->isAvailable(unregisteredServer), std::out_of_range);
}

/**
 * @brief Test instantiation and check an HTTP error.
 *
 */
TEST_F(MonitoringTest, TestHTTPError)
{
    const auto errorServer {"http://localhost:9400"};

    std::vector<std::string> servers;
    servers.emplace_back(errorServer);

    // Set up mock to simulate HTTP error
    EXPECT_CALL(m_mockHttpRequest, get(::testing::_, ::testing::_, ::testing::_))
        .WillRepeatedly(::testing::Invoke(
            [](const auto& /*requestParams*/, const auto& postParams, const auto& /*configParams*/)
            {
                // Simulate HTTP error (503 Service Unavailable)
                postParams.onError("Service Unavailable", 503);
            }));

    std::shared_ptr<TestMonitoring> monitoring;
    EXPECT_NO_THROW(monitoring = std::make_shared<TestMonitoring>(
                        servers, MONITORING_HEALTH_CHECK_INTERVAL, SecureCommunication {}, &m_mockHttpRequest));

    // All servers have their corresponding status the first time
    EXPECT_FALSE(monitoring->isAvailable(errorServer));
}

/**
 * @brief Test instantiation and check the bad response of a server.
 *
 */
TEST_F(MonitoringTest, TestBadResponseFromServer)
{
    const auto badResponseServer {"http://localhost:9500"};

    std::vector<std::string> servers;
    servers.emplace_back(badResponseServer);

    // Set up mock to simulate bad response (malformed JSON)
    EXPECT_CALL(m_mockHttpRequest, get(::testing::_, ::testing::_, ::testing::_))
        .WillRepeatedly(::testing::Invoke(
            [](const auto& /*requestParams*/, const auto& postParams, const auto& /*configParams*/)
            {
                // Simulate malformed JSON that cannot be parsed
                postParams.onSuccess("{ invalid json }");
            }));

    std::shared_ptr<TestMonitoring> monitoring;
    EXPECT_ANY_THROW(monitoring = std::make_shared<TestMonitoring>(
                         servers, MONITORING_HEALTH_CHECK_INTERVAL, SecureCommunication {}, &m_mockHttpRequest));
}

/**
 * @brief Test JSON response with missing status field.
 *
 */
TEST_F(MonitoringTest, TestMissingStatusField)
{
    const auto serverWithMissingField {"http://localhost:9600"};

    std::vector<std::string> servers;
    servers.emplace_back(serverWithMissingField);

    // Set up mock to simulate response without status field
    EXPECT_CALL(m_mockHttpRequest, get(::testing::_, ::testing::_, ::testing::_))
        .WillRepeatedly(::testing::Invoke(
            [](const auto& /*requestParams*/, const auto& postParams, const auto& /*configParams*/)
            {
                // JSON response without status field
                postParams.onSuccess(R"([{"cluster":"test","node.total":"1"}])");
            }));

    std::shared_ptr<TestMonitoring> monitoring;
    EXPECT_NO_THROW(monitoring = std::make_shared<TestMonitoring>(
                        servers, MONITORING_HEALTH_CHECK_INTERVAL, SecureCommunication {}, &m_mockHttpRequest));

    // Should be false because status field is missing
    EXPECT_FALSE(monitoring->isAvailable(serverWithMissingField));
}

/**
 * @brief Test different HTTP status codes.
 *
 */
TEST_F(MonitoringTest, TestDifferentHTTPStatusCodes)
{
    const auto server404 {"http://localhost:9700"};
    const auto server500 {"http://localhost:9800"};

    std::vector<std::string> servers;
    servers.emplace_back(server404);
    servers.emplace_back(server500);

    // Set up mock to simulate different HTTP errors
    EXPECT_CALL(m_mockHttpRequest, get(::testing::_, ::testing::_, ::testing::_))
        .WillRepeatedly(::testing::Invoke(
            [](const auto& requestParams, const auto& postParams, const auto& /*configParams*/)
            {
                const auto& url = std::get<TRequestParameters<std::string>>(requestParams).url.url();
                if (url.find("localhost:9700") != std::string::npos)
                {
                    // 404 Not Found
                    postParams.onError("Not Found", 404);
                }
                else if (url.find("localhost:9800") != std::string::npos)
                {
                    // 500 Internal Server Error
                    postParams.onError("Internal Server Error", 500);
                }
            }));

    std::shared_ptr<TestMonitoring> monitoring;
    EXPECT_NO_THROW(monitoring = std::make_shared<TestMonitoring>(
                        servers, MONITORING_HEALTH_CHECK_INTERVAL, SecureCommunication {}, &m_mockHttpRequest));

    // Both servers should be unavailable due to HTTP errors
    EXPECT_FALSE(monitoring->isAvailable(server404));
    EXPECT_FALSE(monitoring->isAvailable(server500));
}

/**
 * @brief Test red cluster status.
 *
 */
TEST_F(MonitoringTest, TestRedClusterStatus)
{
    const auto redServer {"http://localhost:9900"};

    std::vector<std::string> servers;
    servers.emplace_back(redServer);

    // Set up mock to simulate red cluster status
    EXPECT_CALL(m_mockHttpRequest, get(::testing::_, ::testing::_, ::testing::_))
        .WillRepeatedly(::testing::Invoke(
            [](const auto& /*requestParams*/, const auto& postParams, const auto& /*configParams*/)
            {
                // Red cluster status - should be unavailable
                postParams.onSuccess(R"([{"status":"red","cluster":"test"}])");
            }));

    std::shared_ptr<TestMonitoring> monitoring;
    EXPECT_NO_THROW(monitoring = std::make_shared<TestMonitoring>(
                        servers, MONITORING_HEALTH_CHECK_INTERVAL, SecureCommunication {}, &m_mockHttpRequest));

    // Should be false because red status indicates unavailable
    EXPECT_FALSE(monitoring->isAvailable(redServer));
}

/**
 * @brief Test change server status from green to red.
 *
 */
TEST_F(MonitoringTest, TestChangeServerStatusFromGreenToRed)
{
    const auto greenServer {"http://localhost:1000"};
    const auto redServer {"http://localhost:1010"};

    std::vector<std::string> servers;
    servers.emplace_back(greenServer);
    servers.emplace_back(redServer);

    std::atomic<uint32_t> callCount {0};
    std::atomic<uint32_t> phase {0};

    // Set up mock to simulate green server status
    EXPECT_CALL(m_mockHttpRequest, get(::testing::_, ::testing::_, ::testing::_))
        .WillRepeatedly(::testing::Invoke(
            [&callCount, &phase, &redServer](
                const auto& requestParams, const auto& postParams, const auto& /*configParams*/)
            {
                callCount++;
                if (phase == 0)
                {
                    postParams.onSuccess(R"([{"status":"green"}])");
                }
                else if (phase == 1)
                {
                    if (std::get<TRequestParameters<std::string>>(requestParams).url.url().find(redServer) !=
                        std::string::npos)
                    {
                        postParams.onSuccess(R"([{"status":"red"}])");
                    }
                    else
                    {
                        postParams.onSuccess(R"([{"status":"green"}])");
                    }
                }
            }));

    std::shared_ptr<TestMonitoring> monitoring;
    EXPECT_NO_THROW(monitoring = std::make_shared<TestMonitoring>(
                        servers, MONITORING_HEALTH_CHECK_INTERVAL_ZERO, SecureCommunication {}, &m_mockHttpRequest));

    // Should be true because green server is available
    EXPECT_TRUE(monitoring->isAvailable(greenServer));
    EXPECT_TRUE(monitoring->isAvailable(redServer));

    phase = 1;
    callCount = 0;
    while (callCount < 3)
    {
        std::this_thread::yield();
    }

    // Should be false because red server is unavailable
    EXPECT_FALSE(monitoring->isAvailable(redServer));

    // Should be true because green server is still available
    EXPECT_TRUE(monitoring->isAvailable(greenServer));
}
