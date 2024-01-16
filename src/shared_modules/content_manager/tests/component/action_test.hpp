/*
 * Wazuh content manager - Component Tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 26, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _ACTION_TEST_HPP
#define _ACTION_TEST_HPP

#include "fakes/fakeServer.hpp"
#include "routerProvider.hpp"
#include "gtest/gtest.h"
#include <external/nlohmann/json.hpp>
#include <filesystem>
#include <memory>
#include <string>

/**
 * @brief Runs component tests for Action
 */
class ActionTest : public ::testing::Test
{
protected:
    ActionTest() = default;
    ~ActionTest() override = default;

    nlohmann::json m_parameters; ///< Parameters used to create the Action

    inline static std::unique_ptr<FakeServer> m_spFakeServer; ///< Pointer to FakeServer class

    std::shared_ptr<RouterProvider> m_spRouterProvider; ///< Router provider used on tests.
    const unsigned int INITIAL_OFFSET {1};              ///< Initial offset to be inserted on the database.

    /**
     * @brief Sets initial conditions for each test case.
     */
    // cppcheck-suppress unusedFunction
    void SetUp() override
    {
        m_parameters = R"(
            {
                "topicName": "action-tests",
                "interval": 1,
                "ondemand": false,
                "configData": {
                    "contentSource": "cti-offset",
                    "compressionType": "raw",
                    "versionedContent": "false",
                    "deleteDownloadedContent": false,
                    "url": "http://localhost:4444/raw/consumers",
                    "outputFolder": "/tmp/action-tests",
                    "contentFileName": "sample.json",
                    "databasePath": "/tmp/action-tests/rocksdb"
                }
            }
        )"_json;

        // Init router provider.
        const auto& topicName {m_parameters.at("topicName").get_ref<const std::string&>()};
        m_spRouterProvider = std::make_shared<RouterProvider>(topicName);
        m_spRouterProvider->start();

        // An initial offset different from zero is inserted in order to avoid the snapshot download.
        m_parameters.at("configData")["offset"] = INITIAL_OFFSET;
    }

    /**
     * @brief Tear down routine for tests
     *
     */
    // cppcheck-suppress unusedFunction
    void TearDown() override
    {
        // Removes the directory if it exists
        const auto outputFolder = m_parameters.at("configData").at("outputFolder").get_ref<const std::string&>();
        if (std::filesystem::exists(outputFolder))
        {
            // Delete the output folder.
            std::filesystem::remove_all(outputFolder);
        }

        // Stop router provider.
        m_spRouterProvider->stop();
    }

    /**
     * @brief Creates the fakeServer for the runtime of the test suite
     */
    // cppcheck-suppress unusedFunction
    static void SetUpTestSuite()
    {
        if (!m_spFakeServer)
        {
            m_spFakeServer = std::make_unique<FakeServer>("localhost", 4444);
        }
    }

    /**
     * @brief Resets fakeServer causing the shutdown of the test server.
     */
    // cppcheck-suppress unusedFunction
    static void TearDownTestSuite()
    {
        m_spFakeServer.reset();
    }
};

#endif //_ACTION_TEST_HPP
