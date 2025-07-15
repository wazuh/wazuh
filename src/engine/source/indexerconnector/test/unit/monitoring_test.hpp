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

#include "monitoring.hpp"
#include <gtest/gtest.h>
#include <httpRequest/mockHttpRequest.hpp>
#include <memory>

#ifndef _MONITORING_TEST_HPP
#define _MONITORING_TEST_HPP

auto constexpr MONITORING_HEALTH_CHECK_INTERVAL {2u};
const std::string GREEN_SERVER {"http://localhost:9200"};
const std::string RED_SERVER {"http://localhost:9300"};
const std::string YELLOW_SERVER {"http://localhost:9400"};

/**
 * @brief Runs unit tests for Monitoring class
 */
class MonitoringTest : public ::testing::Test
{
protected:
    std::vector<std::string> m_servers; ///< Servers

    /**
     * @brief Sets initial conditions for each test case.
     */
    // cppcheck-suppress unusedFunction
    void SetUp() override
    {
        // Register the host and port of the green server
        m_servers.emplace_back(GREEN_SERVER);
        // Register the host and port of the red server
        m_servers.emplace_back(RED_SERVER);
        // Register the host and port of the yellow server
        m_servers.emplace_back(YELLOW_SERVER);
    }

    /**
     * @brief Cleans up after each test case.
     */
    // cppcheck-suppress unusedFunction
    void TearDown() override
    {
        // Clear the servers
        m_servers.clear();
    }
};

#endif // _MONITORING_TEST_HPP
