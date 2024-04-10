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

#ifndef _CONTENT_PROVIDER_TEST_HPP
#define _CONTENT_PROVIDER_TEST_HPP

#include "fakes/fakeServer.hpp"
#include "gtest/gtest.h"
#include <external/nlohmann/json.hpp>
#include <filesystem>
#include <memory>
#include <string>

/**
 * @brief Runs component tests for ContentProvider
 */
class ContentProviderTest : public ::testing::Test
{
protected:
    ContentProviderTest() = default;
    ~ContentProviderTest() override = default;

    nlohmann::json m_parameters; ///< Parameters used to create the ContentProvider

    inline static std::unique_ptr<FakeServer> m_spFakeServer; ///< Pointer to FakeServer class

    /**
     * @brief Sets initial conditions for each test case.
     */
    // cppcheck-suppress unusedFunction
    void SetUp() override
    {
        m_parameters = R"(
            {
                "topicName": "content-provider-tests",
                "interval": 1,
                "ondemand": false,
                "configData": {
                    "consumerName": "ContentProviderTest",
                    "contentSource": "cti-offset",
                    "compressionType": "raw",
                    "versionedContent": "false",
                    "deleteDownloadedContent": false,
                    "url": "http://localhost:4444/raw/consumers",
                    "outputFolder": "/tmp/content-provider-tests",
                    "contentFileName": "sample.json"
                }
            }
        )"_json;
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

#endif //_CONTENT_PROVIDER_TEST_HPP
