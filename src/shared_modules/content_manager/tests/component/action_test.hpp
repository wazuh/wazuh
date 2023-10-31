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
#include "timeHelper.h"
#include "utils/rocksDBWrapper.hpp"
#include "gtest/gtest.h"
#include <chrono>
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

    inline static const auto m_databasePath {std::filesystem::temp_directory_path() /
                                             "action_test_database"}; ///< Path used for storing the RocksDB database.

    inline static std::unique_ptr<FakeServer> m_spFakeServer; ///< Pointer to FakeServer class

    std::shared_ptr<RouterProvider> m_spRouterProvider; ///< Router provider used on tests.

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
                    "contentSource": "cti-api",
                    "compressionType": "raw",
                    "versionedContent": "false",
                    "deleteDownloadedContent": false,
                    "url": "http://localhost:4444/raw/consumers",
                    "outputFolder": "/tmp/action-tests",
                    "dataFormat": "json",
                    "contentFileName": "sample.json"
                }
            }
        )"_json;
        m_parameters["databasePath"] = m_databasePath.string();

        // Init router provider.
        const auto& topicName {m_parameters.at("topicName").get_ref<const std::string&>()};
        m_spRouterProvider = std::make_shared<RouterProvider>(topicName);
        m_spRouterProvider->start();
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
     * @brief Creates the fakeServer and the RocksDB database for the runtime of the test suite.
     */
    // cppcheck-suppress unusedFunction
    static void SetUpTestSuite()
    {
        if (!m_spFakeServer)
        {
            m_spFakeServer = std::make_unique<FakeServer>("localhost", 4444);
        }

        // Initialize RocksDB database with an initial offset.
        auto databaseDriver {Utils::RocksDBWrapper(m_databasePath.string())};
        databaseDriver.put(Utils::getCompactTimestamp(std::time(nullptr)), "0");
    }

    /**
     * @brief Resets fakeServer causing the shutdown of the test server. It also removes the database folder.
     */
    // cppcheck-suppress unusedFunction
    static void TearDownTestSuite()
    {
        m_spFakeServer.reset();
        std::filesystem::remove_all(m_databasePath);
    }
};

#endif //_ACTION_TEST_HPP
