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
#include "mockHTTTPRequest.hpp"
#include "trampolineHTTPRequest.hpp"

auto mockHTTPRequestLambda =
    [](const std::string& greenResponse, const std::string& redResponse, const std::string& yellowResponse)
{
    return [greenResponse, redResponse, yellowResponse](RequestParameters requestParameters,
                                                        PostRequestParameters postRequestParameters,
                                                        ConfigurationParameters /*configurationParameters*/)
    {
        const auto& url = requestParameters.url.url();
        if (url == GREEN_SERVER + "/_cat/health?v")
        {
            postRequestParameters.onSuccess(greenResponse);
        }
        else if (url == RED_SERVER + "/_cat/health?v" || url == YELLOW_SERVER + "/_cat/health?v")
        {
            postRequestParameters.onError(redResponse, 200);
        }
        else
        {
            postRequestParameters.onError("Unknown server", 404);
        }
    };
};

/**
 * @brief Test that checks availability of an unregistered server.
 *
 * This test sets up mock responses for registered servers (green and red).
 * It also verifies the behavior when an unregistered server is queried.
 */
TEST_F(MonitoringTest, TestCheckIfAnUnregisteredServerIsAvailable)
{
    const std::string greenResponse =
        "epoch\ttimestamp\tcluster\tstatus\tnode.total\tnode.data\tdiscovered_cluster_"
        "manager\tshards\tpri\trelo\tinit\tunassign\tpending_tasks\tmax_task_wait_time\tactive_"
        "shards_percent\n1725296432\t17:00:32\twazuh-"
        "cluster\tgreen\t1\t1\ttrue\t47\t47\t0\t0\t0\t0\t-\t100.0%\n";

    const std::string redResponse =
        "epoch\ttimestamp\tcluster\tstatus\tnode.total\tnode.data\tdiscovered_cluster_"
        "manager\tshards\tpri\trelo\tinit\tunassign\tpending_tasks\tmax_task_wait_time\tactive_"
        "shards_percent\n1725296432\t17:00:32\twazuh-"
        "cluster\tred\t1\t1\ttrue\t47\t47\t0\t0\t0\t0\t-\t100.0%\n";

    const std::string yellowResponse =
        "epoch\ttimestamp\tcluster\tstatus\tnode.total\tnode.data\tdiscovered_cluster_"
        "manager\tshards\tpri\trelo\tinit\tunassign\tpending_tasks\tmax_task_wait_time\tactive_"
        "shards_percent\n1725296432\t17:00:32\twazuh-"
        "cluster\tyellow\t1\t1\ttrue\t47\t47\t0\t0\t0\t0\t-\t100.0%\n";

    // Set up the expectations for the MockHTTPRequest with the generalized lambda
    EXPECT_CALL(*spHTTPRequest, get(::testing::_, ::testing::_, ::testing::_))
        .WillRepeatedly(mockHTTPRequestLambda(greenResponse, redResponse, yellowResponse));

    const std::string unregisteredServer {"http://localhost:9500"};

    // Instantiate Monitoring object
    auto m_monitoring =
        std::make_shared<TMonitoring<TrampolineHTTPRequest>>(m_servers, MONITORING_HEALTH_CHECK_INTERVAL);

    // Ensure no exceptions during instantiation
    EXPECT_NO_THROW(m_monitoring);

    // Verify availability of registered servers
    EXPECT_TRUE(m_monitoring->isAvailable(GREEN_SERVER));
    EXPECT_TRUE(m_monitoring->isAvailable(RED_SERVER));

    // Check server health status after interval
    std::this_thread::sleep_for(std::chrono::milliseconds(MONITORING_HEALTH_CHECK_INTERVAL * 2));

    EXPECT_TRUE(m_monitoring->isAvailable(GREEN_SERVER));
    EXPECT_FALSE(m_monitoring->isAvailable(RED_SERVER));

    // Unregistered server should throw an exception
    EXPECT_THROW(m_monitoring->isAvailable(unregisteredServer), std::out_of_range);
}

/**
 * @brief Test instantiation with both valid servers (green and red).
 *
 * Verifies that Monitoring correctly tracks availability based on the responses.
 */
TEST_F(MonitoringTest, TestInstantiationWithGreenRedServers)
{
    const std::string greenResponse =
        "epoch\ttimestamp\tcluster\tstatus\tnode.total\tnode.data\tdiscovered_cluster_"
        "manager\tshards\tpri\trelo\tinit\tunassign\tpending_tasks\tmax_task_wait_time\tactive_"
        "shards_percent\n1725296432\t17:00:32\twazuh-"
        "cluster\tgreen\t1\t1\ttrue\t47\t47\t0\t0\t0\t0\t-\t100.0%\n";

    const std::string redResponse =
        "epoch\ttimestamp\tcluster\tstatus\tnode.total\tnode.data\tdiscovered_cluster_"
        "manager\tshards\tpri\trelo\tinit\tunassign\tpending_tasks\tmax_task_wait_time\tactive_"
        "shards_percent\n1725296432\t17:00:32\twazuh-"
        "cluster\tred\t1\t1\ttrue\t47\t47\t0\t0\t0\t0\t-\t100.0%\n";

    const std::string yellowResponse =
        "epoch\ttimestamp\tcluster\tstatus\tnode.total\tnode.data\tdiscovered_cluster_"
        "manager\tshards\tpri\trelo\tinit\tunassign\tpending_tasks\tmax_task_wait_time\tactive_"
        "shards_percent\n1725296432\t17:00:32\twazuh-"
        "cluster\tyellow\t1\t1\ttrue\t47\t47\t0\t0\t0\t0\t-\t100.0%\n";

    // Set up the expectations for the MockHTTPRequest with the generalized lambda
    EXPECT_CALL(*spHTTPRequest, get(::testing::_, ::testing::_, ::testing::_))
        .WillRepeatedly(mockHTTPRequestLambda(greenResponse, redResponse, yellowResponse));

    // Instantiate Monitoring object
    auto m_monitoring =
        std::make_shared<TMonitoring<TrampolineHTTPRequest>>(m_servers, MONITORING_HEALTH_CHECK_INTERVAL);

    // Ensure no exceptions during instantiation
    EXPECT_NO_THROW(m_monitoring);

    // Verify availability of green and red servers
    EXPECT_TRUE(m_monitoring->isAvailable(GREEN_SERVER));
    EXPECT_TRUE(m_monitoring->isAvailable(RED_SERVER));

    // Check server health status after interval
    std::this_thread::sleep_for(std::chrono::milliseconds(MONITORING_HEALTH_CHECK_INTERVAL * 2));

    EXPECT_TRUE(m_monitoring->isAvailable(GREEN_SERVER));
    EXPECT_FALSE(m_monitoring->isAvailable(RED_SERVER));
}

/**
 * @brief Test instantiation without any servers.
 *
 * Verifies that Monitoring can be instantiated without any servers in the input vector.
 */
TEST_F(MonitoringTest, TestInstantiationWithoutServers)
{
    m_servers.clear(); // Clear all servers

    // Instantiate Monitoring object without servers
    auto m_monitoring =
        std::make_shared<TMonitoring<TrampolineHTTPRequest>>(m_servers, MONITORING_HEALTH_CHECK_INTERVAL);

    // Ensure no exceptions during instantiation even with no servers
    EXPECT_NO_THROW(m_monitoring);
}
