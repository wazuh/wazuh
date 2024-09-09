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

// Generalized lambda for simulating HTTP responses based on server health status
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
        else if (url == RED_SERVER + "/_cat/health?v")
        {
            postRequestParameters.onError(redResponse, 200);
        }
        else if (url == YELLOW_SERVER + "/_cat/health?v")
        {
            postRequestParameters.onError(yellowResponse, 200);
        }
        else
        {
            postRequestParameters.onError("Unknown server", 404);
        }
    };
};

// Responses for each server health state
const std::string greenResponse =
    "epoch\ttimestamp\tcluster\tstatus\tnode.total\tnode.data\tdiscovered_cluster_"
    "manager\tshards\tpri\trelo\tinit\tunassign\tpending_tasks\tmax_task_wait_time\tactive_"
    "shards_percent\n1725296432\t17:00:32\twazuh-"
    "cluster\tgreen\t1\t1\ttrue\t47\t47\t0\t0\t0\t0\t-\t100.0%\n";

const std::string redResponse = "epoch\ttimestamp\tcluster\tstatus\tnode.total\tnode.data\tdiscovered_cluster_"
                                "manager\tshards\tpri\trelo\tinit\tunassign\tpending_tasks\tmax_task_wait_time\tactive_"
                                "shards_percent\n1725296432\t17:00:32\twazuh-"
                                "cluster\tred\t1\t1\ttrue\t47\t47\t0\t0\t0\t0\t-\t100.0%\n";

const std::string yellowResponse =
    "epoch\ttimestamp\tcluster\tstatus\tnode.total\tnode.data\tdiscovered_cluster_"
    "manager\tshards\tpri\trelo\tinit\tunassign\tpending_tasks\tmax_task_wait_time\tactive_"
    "shards_percent\n1725296432\t17:00:32\twazuh-"
    "cluster\tyellow\t1\t1\ttrue\t47\t47\t0\t0\t0\t0\t-\t100.0%\n";

/**
 * @brief Test to check the availability of an unregistered server.
 *
 * This test sets up mock responses for registered servers (green and red),
 * and verifies the behavior when an unregistered server is queried.
 */
TEST_F(MonitoringTest, TestCheckIfAnUnregisteredServerIsAvailable)
{
    // Set up expectations for the MockHTTPRequest with the generalized lambda
    EXPECT_CALL(*spHTTPRequest, get(::testing::_, ::testing::_, ::testing::_))
        .WillRepeatedly(mockHTTPRequestLambda(greenResponse, redResponse, yellowResponse));

    const std::string unregisteredServer {"http://localhost:9500"};

    // Instantiate the Monitoring object
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
 * @brief Test to verify the instantiation and availability of valid servers (green and red).
 *
 * This test checks that Monitoring correctly tracks server availability based on responses.
 */
TEST_F(MonitoringTest, TestInstantiationWithGreenRedServers)
{
    // Set up expectations for the MockHTTPRequest with the generalized lambda
    EXPECT_CALL(*spHTTPRequest, get(::testing::_, ::testing::_, ::testing::_))
        .WillRepeatedly(mockHTTPRequestLambda(greenResponse, redResponse, yellowResponse));

    // Instantiate the Monitoring object
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
 * @brief Test to verify instantiation without any servers.
 *
 * This test checks that Monitoring can be instantiated with an empty server list.
 */
TEST_F(MonitoringTest, TestInstantiationWithoutServers)
{
    m_servers.clear(); // Clear all servers

    // Instantiate Monitoring object without servers
    auto m_monitoring =
        std::make_shared<TMonitoring<TrampolineHTTPRequest>>(m_servers, MONITORING_HEALTH_CHECK_INTERVAL);

    // Ensure no exceptions during instantiation with an empty server list
    EXPECT_NO_THROW(m_monitoring);
}
