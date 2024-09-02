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

    std::string nextServer;

    // Instantiate the Server Selector object
    auto m_selector = std::make_shared<TServerSelector<TMonitoring<TrampolineHTTPRequest>>>(
        m_servers, MONITORING_HEALTH_CHECK_INTERVAL);
    EXPECT_NO_THROW(m_selector);

    // It doesn't throw an exception because all servers are available before health check
    EXPECT_NO_THROW(nextServer = m_selector->getNext());
    EXPECT_EQ(nextServer, GREEN_SERVER);

    // It doesn't throw an exception because all servers are available before health check
    EXPECT_NO_THROW(nextServer = m_selector->getNext());
    EXPECT_EQ(nextServer, RED_SERVER);

    // Reset the mock
    spHTTPRequest.reset();
}

/**
 * @brief Test instantiation and getNext server before and after health check.
 *
 */
TEST_F(ServerSelectorTest, TestGetNextBeforeAndAfterHealthCheck)
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

    std::string nextServer;

    // Instantiate the Server Selector object
    auto m_selector = std::make_shared<TServerSelector<TMonitoring<TrampolineHTTPRequest>>>(
        m_servers, MONITORING_HEALTH_CHECK_INTERVAL);
    EXPECT_NO_THROW(m_selector);

    // It doesn't throw an exception because all servers are available before health check
    EXPECT_NO_THROW(nextServer = m_selector->getNext());
    EXPECT_EQ(nextServer, GREEN_SERVER);

    // It doesn't throw an exception because all servers are available before health check
    EXPECT_NO_THROW(nextServer = m_selector->getNext());
    EXPECT_EQ(nextServer, RED_SERVER);

    // Interval to check the health of the servers
    std::this_thread::sleep_for(std::chrono::milliseconds(MONITORING_HEALTH_CHECK_INTERVAL * 2));

    // next server will be the green because it's available
    EXPECT_NO_THROW(nextServer = m_selector->getNext());
    EXPECT_EQ(nextServer, GREEN_SERVER);

    // next server will be the green because the red server isn't available
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

    std::string nextServer;

    // Instantiate the Server Selector object
    auto m_selector = std::make_shared<TServerSelector<TMonitoring<TrampolineHTTPRequest>>>(
        m_servers, MONITORING_HEALTH_CHECK_INTERVAL);
    EXPECT_NO_THROW(m_selector);

    // It doesn't throw an exception because all servers are available before health check
    EXPECT_NO_THROW(nextServer = m_selector->getNext());
    EXPECT_EQ(nextServer, RED_SERVER);

    // Interval to check the health of the servers
    std::this_thread::sleep_for(std::chrono::milliseconds(MONITORING_HEALTH_CHECK_INTERVAL * 2));

    // It throws an exception because there are no available servers
    EXPECT_THROW(nextServer = m_selector->getNext(), std::runtime_error);
}
