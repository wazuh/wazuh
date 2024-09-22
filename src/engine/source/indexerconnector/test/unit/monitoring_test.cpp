/*
 * Wazuh Indexer Connector - Monitoring tests
 * Copyright (C) 2015, Wazuh Inc.
 * August 30, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "monitoring_test.hpp"
#include "IURLRequest.hpp"
#include "trampolineHTTPRequest.hpp"
#include <httpRequest/mockHttpRequest.hpp>
#include <thread>

namespace
{
auto mockHTTPRequestLambda = [](RequestParameters requestParameters,
                                PostRequestParameters postRequestParameters,
                                ConfigurationParameters /*configurationParameters*/) -> void
{
    const auto url = requestParameters.url.url();

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
 * @brief Test to check the availability of an unregistered server.
 *
 * This test sets up mock responses for registered servers (green and red),
 * and verifies the behavior when an unregistered server is queried.
 */
TEST_F(MonitoringTest, TestCheckIfAnUnregisteredServerIsAvailable)
{
    // Set up the expectations for the MockHTTPRequest with the generalized lambda
    EXPECT_CALL(*spHTTPRequest, get(::testing::_, ::testing::_, ::testing::_))
        .WillRepeatedly(::testing::Invoke(mockHTTPRequestLambda));

    const std::string unregisteredServer {"http://localhost:9500"};

    // Instantiate the Monitoring object
    auto monitoring = std::make_shared<TMonitoring<TrampolineHTTPRequest>>(m_servers, MONITORING_HEALTH_CHECK_INTERVAL);

    std::this_thread::sleep_for(std::chrono::milliseconds(MONITORING_HEALTH_CHECK_INTERVAL * 2));

    // Ensure no exceptions during instantiation
    EXPECT_NO_THROW(monitoring);

    // Verify availability of registered servers
    EXPECT_TRUE(monitoring->isAvailable(GREEN_SERVER));
    EXPECT_TRUE(monitoring->isAvailable(YELLOW_SERVER));
    EXPECT_FALSE(monitoring->isAvailable(RED_SERVER));

    // Check server health status after interval
    std::this_thread::sleep_for(std::chrono::milliseconds(MONITORING_HEALTH_CHECK_INTERVAL * 2));

    EXPECT_TRUE(monitoring->isAvailable(GREEN_SERVER));
    EXPECT_TRUE(monitoring->isAvailable(YELLOW_SERVER));
    EXPECT_FALSE(monitoring->isAvailable(RED_SERVER));

    // Unregistered server should throw an exception
    EXPECT_THROW(monitoring->isAvailable(unregisteredServer), std::out_of_range);
}

/**
 * @brief Test to verify the instantiation and availability of valid servers (green and red).
 *
 * This test checks that Monitoring correctly tracks server availability based on responses.
 */
TEST_F(MonitoringTest, TestInstantiationWithGreenRedServers)
{
    // Set up the expectations for the MockHTTPRequest with the generalized lambda
    EXPECT_CALL(*spHTTPRequest, get(::testing::_, ::testing::_, ::testing::_))
        .WillRepeatedly(::testing::Invoke(mockHTTPRequestLambda));

    // Instantiate the Monitoring object
    auto monitoring = std::make_shared<TMonitoring<TrampolineHTTPRequest>>(m_servers, MONITORING_HEALTH_CHECK_INTERVAL);

    // Ensure no exceptions during instantiation
    EXPECT_NO_THROW(monitoring);

    // Verify availability of green, yellow and red servers
    EXPECT_TRUE(monitoring->isAvailable(GREEN_SERVER));
    EXPECT_TRUE(monitoring->isAvailable(YELLOW_SERVER));
    EXPECT_FALSE(monitoring->isAvailable(RED_SERVER));

    // Check server health status after interval
    std::this_thread::sleep_for(std::chrono::milliseconds(MONITORING_HEALTH_CHECK_INTERVAL * 2));

    EXPECT_TRUE(monitoring->isAvailable(GREEN_SERVER));
    EXPECT_TRUE(monitoring->isAvailable(YELLOW_SERVER));
    EXPECT_FALSE(monitoring->isAvailable(RED_SERVER));
}

/**
 * @brief Test to verify instantiation without any servers.
 *
 * This test checks that Monitoring can be instantiated with an empty server list.
 */
TEST_F(MonitoringTest, TestInstantiationWithoutServers)
{
    m_servers.clear(); // Clear all servers

    // Instantiate Monitoring object without servers
    auto monitoring = std::make_shared<TMonitoring<TrampolineHTTPRequest>>(m_servers, MONITORING_HEALTH_CHECK_INTERVAL);

    // Ensure no exceptions during instantiation with an empty server list
    EXPECT_NO_THROW(monitoring);
}
