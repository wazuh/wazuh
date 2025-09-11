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
#include "trampolineHTTPRequest.hpp"
#include <chrono>
#include <memory>
#include <string>
#include <thread>

namespace
{
// Generalized lambda for simulating HTTP responses based on server health status
auto mockHTTPRequestLambda = [](RequestParameters requestParameters,
                                PostRequestParameters postRequestParameters,
                                ConfigurationParameters /*configurationParameters*/) -> void
{
    const auto& url = requestParameters.url.url();

    if (url == GREEN_SERVER + "/_cat/health")
    {
        const auto response = nlohmann::json::array({{{"epoch", "1726271464"},
                                                      {"timestamp", "23:51:04"},
                                                      {"cluster", "wazuh-cluster"},
                                                      {"status", "green"},
                                                      {"node.total", "1"},
                                                      {"node.data", "1"},
                                                      {"discovered_cluster_manager", "true"},
                                                      {"shards", "166"},
                                                      {"pri", "166"},
                                                      {"relo", "0"},
                                                      {"init", "0"},
                                                      {"unassign", "0"},
                                                      {"pending_tasks", "0"},
                                                      {"max_task_wait_time", "-"},
                                                      {"active_shards_percent", "100.0%"}}})
                                  .dump();
        postRequestParameters.onSuccess(response);
    }
    else if (url == YELLOW_SERVER + "/_cat/health")
    {
        const auto response = nlohmann::json::array({{{"epoch", "1726271464"},
                                                      {"timestamp", "23:51:04"},
                                                      {"cluster", "wazuh-cluster"},
                                                      {"status", "yellow"},
                                                      {"node.total", "1"},
                                                      {"node.data", "1"},
                                                      {"discovered_cluster_manager", "true"},
                                                      {"shards", "166"},
                                                      {"pri", "166"},
                                                      {"relo", "0"},
                                                      {"init", "0"},
                                                      {"unassign", "0"},
                                                      {"pending_tasks", "0"},
                                                      {"max_task_wait_time", "-"},
                                                      {"active_shards_percent", "100.0%"}}})
                                  .dump();
        postRequestParameters.onSuccess(response);
    }
    else if (url == RED_SERVER + "/_cat/health")
    {
        const auto response = nlohmann::json::array({{{"epoch", "1726271464"},
                                                      {"timestamp", "23:51:04"},
                                                      {"cluster", "wazuh-cluster"},
                                                      {"status", "red"},
                                                      {"node.total", "1"},
                                                      {"node.data", "1"},
                                                      {"discovered_cluster_manager", "true"},
                                                      {"shards", "166"},
                                                      {"pri", "166"},
                                                      {"relo", "0"},
                                                      {"init", "0"},
                                                      {"unassign", "0"},
                                                      {"pending_tasks", "0"},
                                                      {"max_task_wait_time", "-"},
                                                      {"active_shards_percent", "100.0%"}}})
                                  .dump();
        postRequestParameters.onSuccess(response);
    }
    else
    {
        postRequestParameters.onError("Unknown server", 404);
    }
};

} // namespace

/**
 * @brief Test instantiation with valid servers.
 *
 */
TEST_F(ServerSelectorTest, TestInstantiation)
{
    // Instantiate the Server Selector object
    auto m_selector = std::make_shared<TServerSelector<TMonitoring<TrampolineHTTPRequest>>>(
        m_servers, MONITORING_HEALTH_CHECK_INTERVAL);
    EXPECT_NO_THROW(m_selector);
}

/**
 * @brief Test instantiation without servers.
 *
 */
TEST_F(ServerSelectorTest, TestInstantiationWithoutServers)
{
    m_servers.clear();

    // It doesn't throw an exception because the class ServerSelector accepts vector without servers
    // Instantiate the Server Selector object
    auto m_selector = std::make_shared<TServerSelector<TMonitoring<TrampolineHTTPRequest>>>(
        m_servers, MONITORING_HEALTH_CHECK_INTERVAL);
    EXPECT_NO_THROW(m_selector);
}

/**
 * @brief Test instantiation and getNext server before health check.
 *
 */
TEST_F(ServerSelectorTest, TestGetNextBeforeHealthCheck)
{
    // Set up the expectations for the MockHTTPRequest
    EXPECT_CALL(*spHTTPRequest, get(::testing::_, ::testing::_, ::testing::_))
        .WillRepeatedly(::testing::Invoke(mockHTTPRequestLambda));

    std::string nextServer;

    // Instantiate the Server Selector object
    auto m_selector = std::make_shared<TServerSelector<TMonitoring<TrampolineHTTPRequest>>>(
        m_servers, MONITORING_HEALTH_CHECK_INTERVAL);
    EXPECT_NO_THROW(m_selector);

    // It doesn't throw an exception because there are available servers before health check
    EXPECT_NO_THROW(nextServer = m_selector->getNext());
    EXPECT_EQ(nextServer, GREEN_SERVER);

    EXPECT_NO_THROW(nextServer = m_selector->getNext());
    EXPECT_EQ(nextServer, YELLOW_SERVER);
}

/**
 * @brief Test instantiation and getNext server before and after health check.
 *
 */
TEST_F(ServerSelectorTest, TestGetNextBeforeAndAfterHealthCheck)
{
    // Set up the expectations for the MockHTTPRequest
    EXPECT_CALL(*spHTTPRequest, get(::testing::_, ::testing::_, ::testing::_))
        .WillRepeatedly(::testing::Invoke(mockHTTPRequestLambda));

    std::string nextServer;

    // Instantiate the Server Selector object
    auto m_selector = std::make_shared<TServerSelector<TMonitoring<TrampolineHTTPRequest>>>(
        m_servers, MONITORING_HEALTH_CHECK_INTERVAL);
    EXPECT_NO_THROW(m_selector);

    // We expect to iterate over the green and yellow server
    EXPECT_NO_THROW(nextServer = m_selector->getNext());
    EXPECT_EQ(nextServer, GREEN_SERVER);

    EXPECT_NO_THROW(nextServer = m_selector->getNext());
    EXPECT_EQ(nextServer, YELLOW_SERVER);

    EXPECT_NO_THROW(nextServer = m_selector->getNext());
    EXPECT_EQ(nextServer, GREEN_SERVER);

    // Interval to check the health of the servers
    std::this_thread::sleep_for(std::chrono::milliseconds(MONITORING_HEALTH_CHECK_INTERVAL * 2));

    EXPECT_NO_THROW(nextServer = m_selector->getNext());
    EXPECT_EQ(nextServer, YELLOW_SERVER);

    EXPECT_NO_THROW(nextServer = m_selector->getNext());
    EXPECT_EQ(nextServer, GREEN_SERVER);
}

/**
 * @brief Test instantiation and getNext when there are no available servers.
 *
 */
TEST_F(ServerSelectorTest, TestGextNextWhenThereAreNoAvailableServers)
{
    m_servers.clear();
    m_servers.emplace_back(RED_SERVER);

    // Set up the expectations for the MockHTTPRequest
    EXPECT_CALL(*spHTTPRequest, get(::testing::_, ::testing::_, ::testing::_))
        .WillRepeatedly(::testing::Invoke(mockHTTPRequestLambda));

    // Instantiate the Server Selector object
    auto m_selector = std::make_shared<TServerSelector<TMonitoring<TrampolineHTTPRequest>>>(
        m_servers, MONITORING_HEALTH_CHECK_INTERVAL);
    EXPECT_NO_THROW(m_selector);

    // Throw an exception because there are no available servers
    EXPECT_THROW(m_selector->getNext(), std::runtime_error);

    // Interval to check the health of the servers
    std::this_thread::sleep_for(std::chrono::milliseconds(MONITORING_HEALTH_CHECK_INTERVAL * 2));

    // Throw an exception because there are no available servers
    EXPECT_THROW(m_selector->getNext(), std::runtime_error);
}
