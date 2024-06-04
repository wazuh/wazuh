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

#include "fakeOpenSearchServer.hpp"
#include "serverSelector.hpp"
#include <gtest/gtest.h>
#include <string>
#include <vector>

/**
 * @brief Runs unit tests for ServerSelector class
 */
class ServerSelectorTest : public ::testing::Test
{
protected:
    inline static std::unique_ptr<FakeOpenSearchServer>
        m_fakeOpenSearchGreenServer; ///< pointer to FakeOpenSearchServer class

    inline static std::unique_ptr<FakeOpenSearchServer>
        m_fakeOpenSearchRedServer; ///< pointer to FakeOpenSearchServer class

    std::shared_ptr<ServerSelector> m_selector; ///< pointer to Selector class

    std::vector<std::string> m_servers; ///< Servers

    /**
     * @brief Sets initial conditions for each test case.
     */
    // cppcheck-suppress unusedFunction
    void SetUp() override
    {
        // Register the host and port of the green server
        m_servers.emplace_back("http://localhost:9209");
        // Register the host and port of the red server
        m_servers.emplace_back("http://localhost:9210");
    }

    /**
     * @brief Creates the fakeOpenSearchServers for the runtime of the test suite
     */
    // cppcheck-suppress unusedFunction
    static void SetUpTestSuite()
    {
        const std::string host {"localhost"};

        if (!m_fakeOpenSearchGreenServer)
        {
            m_fakeOpenSearchGreenServer = std::make_unique<FakeOpenSearchServer>(host, 9209, "green");
        }

        if (!m_fakeOpenSearchRedServer)
        {
            m_fakeOpenSearchRedServer = std::make_unique<FakeOpenSearchServer>(host, 9210, "red");
        }
    }

    /**
     * @brief Resets fakeOpenSearchServers causing the shutdown of the test server.
     */
    // cppcheck-suppress unusedFunction
    static void TearDownTestSuite()
    {
        m_fakeOpenSearchGreenServer.reset();
        m_fakeOpenSearchRedServer.reset();
    }
};

#endif // _SERVER_SELECTOR_TEST_HPP
