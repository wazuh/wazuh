/*
 * Wazuh content manager - Unit Tests
 * Copyright (C) 2015, Wazuh Inc.
 * Jun 08, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _API_DOWNLOADER_TEST_HPP
#define _API_DOWNLOADER_TEST_HPP

#include "APIDownloader.hpp"
#include "HTTPRequest.hpp"
#include "conditionSync.hpp"
#include "fakes/fakeServer.hpp"
#include "updaterContext.hpp"
#include "gtest/gtest.h"
#include <memory>

/**
 * @brief Runs unit tests for APIDownloader
 */
class APIDownloaderTest : public ::testing::Test
{
protected:
    APIDownloaderTest() = default;
    ~APIDownloaderTest() override = default;

    std::shared_ptr<UpdaterContext> m_spUpdaterContext; ///< UpdaterContext used on the merge pipeline.

    std::shared_ptr<UpdaterBaseContext> m_spUpdaterBaseContext; ///< UpdaterBaseContext used on the merge pipeline.

    std::shared_ptr<APIDownloader> m_spAPIDownloader; ///< APIDownloader used to download the content.

    inline static std::unique_ptr<FakeServer> m_spFakeServer; ///< pointer to FakeServer class

    std::shared_ptr<ConditionSync> m_spStopActionCondition {
        std::make_shared<ConditionSync>(false)}; ///< Stop condition wrapper

    /**
     * @brief Sets initial conditions for each test case.
     *
     */
    // cppcheck-suppress unusedFunction
    void SetUp() override
    {
        m_spAPIDownloader = std::make_shared<APIDownloader>(HTTPRequest::instance());
        // Create a updater base context
        m_spUpdaterBaseContext = std::make_shared<UpdaterBaseContext>(m_spStopActionCondition);
        m_spUpdaterBaseContext->outputFolder = "/tmp/api-downloader-tests";
        m_spUpdaterBaseContext->downloadsFolder = m_spUpdaterBaseContext->outputFolder / DOWNLOAD_FOLDER;
        m_spUpdaterBaseContext->contentsFolder = m_spUpdaterBaseContext->outputFolder / CONTENTS_FOLDER;
        m_spUpdaterBaseContext->configData = R"(
            {
                "contentSource": "api",
                "compressionType": "raw",
                "versionedContent": "false",
                "deleteDownloadedContent": false,
                "url": "http://localhost:4444/raw",
                "outputFolder": "/tmp/api-downloader-tests",
                "contentFileName": "sample.json"
            }
        )"_json;
        // Create a updater context
        m_spUpdaterContext = std::make_shared<UpdaterContext>();
        // Create folders
        std::filesystem::create_directory(m_spUpdaterBaseContext->outputFolder);
        std::filesystem::create_directory(m_spUpdaterBaseContext->downloadsFolder);
        std::filesystem::create_directory(m_spUpdaterBaseContext->contentsFolder);
    }

    /**
     * @brief Tear down routine for tests
     *
     */
    // cppcheck-suppress unusedFunction
    void TearDown() override
    {
        // Remove outputFolder
        std::filesystem::remove_all(m_spUpdaterBaseContext->outputFolder);
        // Reset APIDownloader
        m_spAPIDownloader.reset();
        // Reset UpdaterContext
        m_spUpdaterContext.reset();
        // Reset UpdaterBaseContext
        m_spUpdaterBaseContext.reset();
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

#endif //_API_DOWNLOADER_TEST_HPP
