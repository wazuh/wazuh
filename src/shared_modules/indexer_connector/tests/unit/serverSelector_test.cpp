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
#include "monitoring.hpp"
#include <memory>
#include <stdexcept>
#include <string>

// Health check interval for the servers
constexpr auto SERVER_SELECTOR_HEALTH_CHECK_INTERVAL = 1u;
constexpr auto SERVER_SELECTOR_HEALTH_CHECK_INTERVAL_ZERO = 0u;
constexpr auto SERVER_SELECTOR_HEALTH_CHECK_INTERVAL_INFINITE = std::numeric_limits<uint32_t>::max();

namespace Log
{
    std::function<void(
        const int, const std::string&, const std::string&, const int, const std::string&, const std::string&, va_list)>
        GLOBAL_LOG_FUNCTION;
}; // namespace Log

/**
 * @brief Test instantiation with valid servers.
 */
TEST_F(ServerSelectorTest, TestInstantiation)
{
    std::vector<std::string> servers;
    servers.emplace_back("http://localhost:9209");
    servers.emplace_back("http://localhost:9210");
    servers.emplace_back("http://localhost:9211");

    // Setup mock to simulate health check responses (green and yellow servers available)
    setupHealthCheckMocks("green", "red", "yellow");

    // Test that creating the server selector doesn't throw
    std::shared_ptr<TestServerSelector> selector;
    EXPECT_NO_THROW(
        selector = std::make_shared<TestServerSelector>(
            servers, SERVER_SELECTOR_HEALTH_CHECK_INTERVAL, SecureCommunication {}, m_mockHttpRequest.get()));
}

/**
 * @brief Test instantiation without servers.
 */
TEST_F(ServerSelectorTest, TestInstantiationWithoutServers)
{
    // Empty servers list (simulating empty server configuration)
    std::vector<std::string> servers;

    // Even with empty servers, selector creation should not throw
    std::shared_ptr<TestServerSelector> selector;
    EXPECT_NO_THROW(
        selector = std::make_shared<TestServerSelector>(
            servers, SERVER_SELECTOR_HEALTH_CHECK_INTERVAL, SecureCommunication {}, m_mockHttpRequest.get()));

    EXPECT_THROW(selector->getNext(), std::runtime_error);
}

/**
 * @brief Test getNext server before health check.
 */
TEST_F(ServerSelectorTest, TestGetNextBeforeHealthCheck)
{
    std::vector<std::string> servers;
    servers.emplace_back("http://localhost:9209");
    servers.emplace_back("http://localhost:9210");
    servers.emplace_back("http://localhost:9211");

    const auto server1 = servers.at(0);
    const auto server3 = servers.at(2);

    // Setup mock to simulate green and yellow servers available, red server down
    setupHealthCheckMocks("green", "red", "yellow");

    // Create selector
    std::shared_ptr<TestServerSelector> selector;
    EXPECT_NO_THROW(
        selector = std::make_shared<TestServerSelector>(
            servers, SERVER_SELECTOR_HEALTH_CHECK_INTERVAL_INFINITE, SecureCommunication {}, m_mockHttpRequest.get()));

    std::string nextServer;

    // Test first call returns green server (available)
    EXPECT_NO_THROW(nextServer = selector->getNext());
    EXPECT_EQ(nextServer, server1);

    // Test second call returns yellow server (available, red is skipped)
    EXPECT_NO_THROW(nextServer = selector->getNext());
    EXPECT_EQ(nextServer, server3);
}

/**
 * @brief Test getNext server before and after health check completion.
 */
TEST_F(ServerSelectorTest, TestGetNextBeforeAndAfterHealthCheck)
{
    std::vector<std::string> servers;
    servers.emplace_back("http://localhost:9209");
    servers.emplace_back("http://localhost:9210");
    servers.emplace_back("http://localhost:9211");

    const auto server1 = servers.at(0);
    const auto server3 = servers.at(2);

    std::atomic<int> phase {1};
    std::atomic<int> callCount {0};

    EXPECT_CALL(*m_mockHttpRequest, get(testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::Invoke(
            [&phase, &callCount](auto requestParams, const auto& postParams, auto /*configParams*/)
            {
                // Extract the URL to determine which server is being checked
                std::string url;
                if (std::holds_alternative<TRequestParameters<std::string>>(requestParams))
                {
                    url = std::get<TRequestParameters<std::string>>(requestParams).url.url();
                }
                else
                {
                    url = std::get<TRequestParameters<nlohmann::json>>(requestParams).url.url();
                }

                std::string response;

                if (int currentPhase = phase.load(); currentPhase == 1)
                {
                    // Phase 1: green and yellow servers available, red server down
                    if (url.find("9209") != std::string::npos)
                    {
                        response = R"([{"status":"green"}])";
                    }
                    else if (url.find("9210") != std::string::npos)
                    {
                        response = R"([{"status":"red"}])";
                    }
                    else if (url.find("9211") != std::string::npos)
                    {
                        response = R"([{"status":"yellow"}])";
                    }
                    callCount++;
                }
                else if (currentPhase == 2)
                {
                    // Phase 2: all servers down
                    if (url.find("9209") != std::string::npos || url.find("9210") != std::string::npos ||
                        url.find("9211") != std::string::npos)
                    {
                        response = R"([{"status":"red"}])";
                    }
                    callCount++;
                }
                else if (currentPhase == 3)
                {
                    // Phase 3: only server 1 available
                    if (url.find("9209") != std::string::npos)
                    {
                        response = R"([{"status":"green"}])";
                    }
                    else if (url.find("9210") != std::string::npos || url.find("9211") != std::string::npos)
                    {
                        response = R"([{"status":"red"}])";
                    }
                    callCount++;
                }

                if (!response.empty())
                {
                    postParams.onSuccess(response);
                }
                else
                {
                    postParams.onError("Server not found", 404);
                }
            }));

    // Create selector with a short interval for quick health checks
    std::shared_ptr<TestServerSelector> selector;
    EXPECT_NO_THROW(
        selector = std::make_shared<TestServerSelector>(
            servers, SERVER_SELECTOR_HEALTH_CHECK_INTERVAL_ZERO, SecureCommunication {}, m_mockHttpRequest.get()));

    std::string nextServer;

    while (callCount < 2)
    {
        std::this_thread::yield();
    }

    // Before health check - green and yellow servers are available
    EXPECT_NO_THROW(nextServer = selector->getNext());
    EXPECT_EQ(nextServer, server1);

    EXPECT_NO_THROW(nextServer = selector->getNext());
    EXPECT_EQ(nextServer, server3);

    EXPECT_NO_THROW(nextServer = selector->getNext());
    EXPECT_EQ(nextServer, server1);

    EXPECT_NO_THROW(nextServer = selector->getNext());
    EXPECT_EQ(nextServer, server3);

    phase = 2;
    callCount = 0;

    while (callCount < 2)
    {
        std::this_thread::yield();
    }

    // After health check all servers are down
    EXPECT_THROW(nextServer = selector->getNext(), std::runtime_error);

    phase = 3;
    callCount = 0;
    while (callCount < 2)
    {
        std::this_thread::yield();
    }

    // After health check server 1 is available
    EXPECT_NO_THROW(nextServer = selector->getNext());
    EXPECT_EQ(nextServer, server1);

    EXPECT_NO_THROW(nextServer = selector->getNext());
    EXPECT_EQ(nextServer, server1);
}

/**
 * @brief Test getNext when there are no available servers.
 */
TEST_F(ServerSelectorTest, TestGetNextWhenThereAreNoAvailableServers)
{
    const auto hostRedServer = "http://localhost:9210";

    // Create servers with only red server (which will be down)
    std::vector<std::string> servers;
    servers.emplace_back(hostRedServer);

    // Setup mock to simulate only red server (down)
    setupHealthCheckMocks("red", "red", "red");

    // Create selector with only the red server
    std::shared_ptr<TestServerSelector> selector;
    EXPECT_NO_THROW(
        selector = std::make_shared<TestServerSelector>(
            servers, SERVER_SELECTOR_HEALTH_CHECK_INTERVAL, SecureCommunication {}, m_mockHttpRequest.get()));

    // Test that exception is thrown when no servers are available
    EXPECT_THROW(selector->getNext(), std::runtime_error);
}
