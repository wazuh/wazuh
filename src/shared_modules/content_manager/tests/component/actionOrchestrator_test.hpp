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

#ifndef _ACTION_ORCHESTRATOR_TEST_HPP
#define _ACTION_ORCHESTRATOR_TEST_HPP

#include "conditionSync.hpp"
#include "fakes/fakeServer.hpp"
#include "mocks/mockRouterProvider.hpp"
#include "gtest/gtest.h"
#include <external/nlohmann/json.hpp>
#include <filesystem>
#include <memory>
#include <string>

/**
 * @brief Runs component tests for ActionOrchestrator
 */
class ActionOrchestratorTest : public ::testing::Test
{
protected:
    ActionOrchestratorTest() = default;
    ~ActionOrchestratorTest() override = default;

    nlohmann::json m_parameters; ///< Parameters used to create the ActionOrchestrator

    inline static std::unique_ptr<FakeServer> m_spFakeServer; ///< Pointer to FakeServer class
    std::shared_ptr<ConditionSync> m_spStopActionCondition {
        std::make_shared<ConditionSync>(false)}; ///< Stop condition wrapper

    const std::filesystem::path DATABASE_PATH {std::filesystem::temp_directory_path() /
                                               "ActionOrchestratorTest"}; ///< Path used to store the RocksDB database.
    const unsigned int INITIAL_OFFSET {1}; ///< Initial offset to be inserted on the database.
    const std::filesystem::path m_inputFilesDir {std::filesystem::current_path() /
                                                 "input_files"}; ///< Input files folder.
    std::shared_ptr<MockRouterProvider> m_spMockRouterProvider;  ///< Router provider used on tests.

    /**
     * @brief Sets initial conditions for each test case.
     */
    // cppcheck-suppress unusedFunction
    void SetUp() override
    {
        m_parameters = R"(
            {
                "topicName": "action-orchestrator-tests",
                "interval": 1,
                "ondemand": true,
                "configData": {
                    "consumerName": "ActionOrchestratorTest",
                    "contentSource": "cti-offset",
                    "compressionType": "raw",
                    "versionedContent": "false",
                    "deleteDownloadedContent": false,
                    "url": "http://localhost:4444/raw/consumers",
                    "outputFolder": "/tmp/action-orchestrator-tests",
                    "contentFileName": "sample.json"
                }
            }
        )"_json;

        // An initial offset different from zero is inserted in order to avoid the snapshot download.
        m_parameters.at("configData")["databasePath"] = DATABASE_PATH;
        m_parameters.at("configData")["offset"] = INITIAL_OFFSET;

        m_spMockRouterProvider = std::make_shared<MockRouterProvider>();
    }
    /**
     * @brief Tear down routine for tests
     *
     */
    // cppcheck-suppress unusedFunction
    void TearDown() override
    {
        // Removes the directory if it exists
        const auto outputFolder = m_parameters.at("configData").at("outputFolder").get<const std::string>();
        if (std::filesystem::exists(outputFolder))
        {
            // Delete the output folder.
            std::filesystem::remove_all(outputFolder);
        }

        // Remove database files.
        std::filesystem::remove_all(DATABASE_PATH);
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

#endif //_ACTION_ORCHESTRATOR_TEST_HPP
