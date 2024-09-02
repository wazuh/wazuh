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

/**
 * @brief Test instantiation and check the availability of an unregistered server.
 *
 */
TEST_F(MonitoringTest, TestCheckIfAnUnregisteredServerIsAvailable)
{
    // Set up the expectations for the MockHTTPRequest
    EXPECT_CALL(*spHTTPRequest, get(::testing::_, ::testing::_, ::testing::_))
        .WillRepeatedly(::testing::Invoke(
            [](RequestParameters requestParameters,
               PostRequestParameters postRequestParameters,
               ConfigurationParameters /*configurationParameters*/)
            {
                const auto& url = requestParameters.url.url(); // Convert URL to string if needed
                std::string response;

                if (url == GREEN_SERVER + "/_cat/health?v")
                {
                    // Simulate a successful response for the green server
                    response = "epoch\ttimestamp\tcluster\tstatus\tnode.total\tnode.data\tdiscovered_cluster_"
                               "manager\tshards\tpri\trelo\tinit\tunassign\tpending_tasks\tmax_task_wait_time\tactive_"
                               "shards_percent\n1725296432\t17:00:32\twazuh-"
                               "cluster\tgreen\t1\t1\ttrue\t47\t47\t0\t0\t0\t0\t-\t100.0%\n";
                    postRequestParameters.onSuccess(response);
                }
                else if (url == RED_SERVER + "/_cat/health?v")
                {
                    // Simulate a failed response for the red server
                    response = "epoch\ttimestamp\tcluster\tstatus\tnode.total\tnode.data\tdiscovered_cluster_"
                               "manager\tshards\tpri\trelo\tinit\tunassign\tpending_tasks\tmax_task_wait_time\tactive_"
                               "shards_percent\n1725296432\t17:00:32\twazuh-"
                               "cluster\tred\t1\t1\ttrue\t47\t47\t0\t0\t0\t0\t-\t100.0%\n";
                    postRequestParameters.onError(response, 200);
                }
                else
                {
                    // Unknown server, simulate an error
                    postRequestParameters.onError("Unknown server", 404);
                    return;
                }
            }));

    const auto unregisteredServer {"http://localhost:9400"};

    // Instantiate the Monitoring object
    auto m_monitoring =
        std::make_shared<TMonitoring<TrampolineHTTPRequest>>(m_servers, MONITORING_HEALTH_CHECK_INTERVAL);

    // It doesn't throw an exception because the class Monitoring accepts vector without servers
    EXPECT_NO_THROW(m_monitoring);

    // Verify that the green server is marked as available
    EXPECT_TRUE(m_monitoring->isAvailable(GREEN_SERVER));

    // Verify that the red server is marked as available
    EXPECT_TRUE(m_monitoring->isAvailable(RED_SERVER));

    // Verify that the unregistered server is marked as not available

    // Interval to check the health of the servers
    std::this_thread::sleep_for(std::chrono::milliseconds(MONITORING_HEALTH_CHECK_INTERVAL * 2));

    EXPECT_TRUE(m_monitoring->isAvailable(GREEN_SERVER));
    EXPECT_FALSE(m_monitoring->isAvailable(RED_SERVER));
    EXPECT_THROW(m_monitoring->isAvailable(unregisteredServer), std::out_of_range);
}

/**
 * @brief Test instantiation and check the availability of valid servers.
 *
 */
TEST_F(MonitoringTest, TestInstantiationWithGreenRedServers)
{
    // Set up the expectations for the MockHTTPRequest
    EXPECT_CALL(*spHTTPRequest, get(::testing::_, ::testing::_, ::testing::_))
        .WillRepeatedly(::testing::Invoke(
            [](RequestParameters requestParameters,
               PostRequestParameters postRequestParameters,
               ConfigurationParameters /*configurationParameters*/)
            {
                const auto& url = requestParameters.url.url(); // Convert URL to string if needed
                std::string response;

                if (url == GREEN_SERVER + "/_cat/health?v")
                {
                    // Simulate a successful response for the green server
                    response = "epoch\ttimestamp\tcluster\tstatus\tnode.total\tnode.data\tdiscovered_cluster_"
                               "manager\tshards\tpri\trelo\tinit\tunassign\tpending_tasks\tmax_task_wait_time\tactive_"
                               "shards_percent\n1725296432\t17:00:32\twazuh-"
                               "cluster\tgreen\t1\t1\ttrue\t47\t47\t0\t0\t0\t0\t-\t100.0%\n";
                    postRequestParameters.onSuccess(response.c_str());
                }
                else if (url == RED_SERVER + "/_cat/health?v")
                {
                    // Simulate a failed response for the red server
                    response = "epoch\ttimestamp\tcluster\tstatus\tnode.total\tnode.data\tdiscovered_cluster_"
                               "manager\tshards\tpri\trelo\tinit\tunassign\tpending_tasks\tmax_task_wait_time\tactive_"
                               "shards_percent\n1725296432\t17:00:32\twazuh-"
                               "cluster\tred\t1\t1\ttrue\t47\t47\t0\t0\t0\t0\t-\t100.0%\n";
                    postRequestParameters.onError(response.c_str(), 200);
                }
                else
                {
                    // Unknown server, simulate an error
                    postRequestParameters.onError("Unknown server", 404);
                    return;
                }
            }));

    // Instantiate the Monitoring object
    auto m_monitoring =
        std::make_shared<TMonitoring<TrampolineHTTPRequest>>(m_servers, MONITORING_HEALTH_CHECK_INTERVAL);

    // Ensure the object is created without throwing an exception
    EXPECT_NO_THROW(m_monitoring);

    // Verify that the green server is marked as available
    EXPECT_TRUE(m_monitoring->isAvailable(GREEN_SERVER));

    // Verify that the red server is marked as available
    EXPECT_TRUE(m_monitoring->isAvailable(RED_SERVER));

    // Interval to check the health of the servers
    std::this_thread::sleep_for(std::chrono::milliseconds(MONITORING_HEALTH_CHECK_INTERVAL * 2));

    // Verify that the green server is marked as available
    EXPECT_TRUE(m_monitoring->isAvailable(GREEN_SERVER));

    // Verify that the red server is marked as not available
    EXPECT_FALSE(m_monitoring->isAvailable(RED_SERVER));
}

/**
 * @brief Test instantiation without servers.
 *
 */
TEST_F(MonitoringTest, TestInstantiationWithoutServers)
{
    m_servers.clear();

    // Instantiate the Monitoring object
    auto m_monitoring =
        std::make_shared<TMonitoring<TrampolineHTTPRequest>>(m_servers, MONITORING_HEALTH_CHECK_INTERVAL);

    // It doesn't throw an exception because the class Monitoring accepts vector without servers
    EXPECT_NO_THROW(m_monitoring);
}
