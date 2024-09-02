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

#ifndef _SERVER_SELECTOR_TEST_HPP
#define _SERVER_SELECTOR_TEST_HPP

#include "mockHTTTPRequest.hpp"
#include "serverSelector.hpp"
#include <gtest/gtest.h>
#include <string>
#include <vector>

// Define the global spHTTPRequest
std::shared_ptr<MockHTTPRequest> spHTTPRequest = std::make_shared<MockHTTPRequest>();

auto constexpr MONITORING_HEALTH_CHECK_INTERVAL {2u};
const std::string GREEN_SERVER {"http://localhost:9200"};
const std::string RED_SERVER {"http://localhost:9300"};

/**
 * @brief Runs unit tests for ServerSelector class
 */
class ServerSelectorTest : public ::testing::Test
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
    }

    /**
     * @brief Resets variables after each test case.
     */
    // cppcheck-suppress unusedFunction
    void TearDown()
    {

        // Clear the servers
        m_servers.clear();
    }
};

#endif // _SERVER_SELECTOR_TEST_HPP
