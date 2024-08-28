/*
 * Wazuh Indexer Connector - Monitoring tests
 * Copyright (C) 2015, Wazuh Inc.
 * September 08, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _MONITORING_TEST_HPP
#define _MONITORING_TEST_HPP

#include "fakeOpenSearchServer.hpp"
#include "monitoring.hpp"
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

/**
 * @brief Runs unit tests for Monitoring class
 */
class MonitoringTest : public ::testing::Test
{
protected:
    inline static std::unique_ptr<FakeOpenSearchServer>
        m_fakeOpenSearchGreenServer; ///< pointer to FakeOpenSearchServer class

    inline static std::unique_ptr<FakeOpenSearchServer>
        m_fakeOpenSearchRedServer; ///< pointer to FakeOpenSearchServer class

    inline static std::unique_ptr<FakeOpenSearchServer>
        m_fakeOpenSearchYellowServer; ///< pointer to FakeOpenSearchServer class

    inline static std::unique_ptr<FakeOpenSearchServer>
        m_fakeOpenSearchGreenServerWithDelay; ///< pointer to FakeOpenSearchServer class

    std::shared_ptr<Monitoring> m_monitoring; ///< pointer to Monitoring class

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
        // Register the host and port of the yellow server
        m_servers.emplace_back("http://localhost:9211");
        // Register the host and port of the server with delay
        m_servers.emplace_back("http://localhost:9212");
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

        if (!m_fakeOpenSearchYellowServer)
        {
            m_fakeOpenSearchYellowServer = std::make_unique<FakeOpenSearchServer>(host, 9211, "yellow");
        }

        if (!m_fakeOpenSearchGreenServerWithDelay)
        {
            // Create a server with a delay of 100 milliseconds
            m_fakeOpenSearchGreenServerWithDelay = std::make_unique<FakeOpenSearchServer>(host, 9212, "green", 100);
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
        m_fakeOpenSearchYellowServer.reset();
        m_fakeOpenSearchGreenServerWithDelay.reset();
    }
};

#endif // _MONITORING_TEST_HPP
