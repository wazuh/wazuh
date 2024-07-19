/*
 * Wazuh content manager - Unit Tests
 * Copyright (C) 2015, Wazuh Inc.
 * October 24, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _OFFLINE_DOWNLOADER_TEST
#define _OFFLINE_DOWNLOADER_TEST

#include "conditionSync.hpp"
#include "fakes/fakeServer.hpp"
#include "offlineDownloader.hpp"
#include "updaterContext.hpp"
#include "gtest/gtest.h"
#include <filesystem>
#include <fstream>
#include <memory>

/**
 * @brief Runs unit tests for OfflineDownloader
 *
 */
class OfflineDownloaderTest : public ::testing::Test
{
protected:
    OfflineDownloaderTest() = default;
    ~OfflineDownloaderTest() override = default;

    const std::filesystem::path m_tempPath {std::filesystem::temp_directory_path()};   ///< Temporary path.
    const std::filesystem::path m_inputFilePathRaw {m_tempPath / "testFile.txt"};      ///< Raw input test path.
    const std::string m_inputFileHashRaw {"da21ecfc2146bfeb7c2d4020eda94afc6878266d"}; ///< Raw file hash.
    const std::filesystem::path m_inputFilePathCompressed {m_tempPath /
                                                           "testFile.txt.gz"}; ///< Compressed input test path.
    const std::string m_inputFileHashCompressed {"b2e0c197e5bc308fb868b31292c5e75145d8735b"}; ///< Compressed file hash.
    const std::filesystem::path m_outputFolder {m_tempPath / "offline-downloader-tests"};     ///< Output test folder.
    std::shared_ptr<UpdaterContext> m_spUpdaterContext;         ///< UpdaterContext used on tests.
    std::shared_ptr<UpdaterBaseContext> m_spUpdaterBaseContext; ///< UpdaterBaseContext used on tests.

    inline static std::unique_ptr<FakeServer> m_spFakeServer; ///< Fake HTTP server used in tests.
    std::shared_ptr<ConditionSync> m_spStopActionCondition {
        std::make_shared<ConditionSync>(false)}; ///< Stop condition wrapper

    /**
     * @brief Set up routine for each test fixture.
     *
     */
    void SetUp() override
    {
        // Create raw input file.
        std::ofstream testFileStream {m_inputFilePathRaw};
        testFileStream << "I'm a test file with a .txt extension." << std::endl;
        testFileStream.close();

        // Create "compressed" input file with a greater size.
        testFileStream.open(m_inputFilePathCompressed);
        testFileStream.fill(' ');
        testFileStream.width(10000);
        testFileStream << "I'm a larger test file with a .gz extension." << std::endl;
        testFileStream.close();

        // Updater base context.
        m_spUpdaterBaseContext = std::make_shared<UpdaterBaseContext>(m_spStopActionCondition);
        m_spUpdaterBaseContext->outputFolder = m_outputFolder;
        m_spUpdaterBaseContext->downloadsFolder = m_outputFolder / DOWNLOAD_FOLDER;
        m_spUpdaterBaseContext->contentsFolder = m_outputFolder / CONTENTS_FOLDER;

        m_spUpdaterContext = std::make_shared<UpdaterContext>();
        m_spUpdaterContext->spUpdaterBaseContext = m_spUpdaterBaseContext;

        std::filesystem::create_directory(m_spUpdaterBaseContext->outputFolder);
        std::filesystem::create_directory(m_spUpdaterBaseContext->downloadsFolder);
        std::filesystem::create_directory(m_spUpdaterBaseContext->contentsFolder);
    }

    /**
     * @brief Tear down routine for each test fixture.
     *
     */
    void TearDown() override
    {
        std::filesystem::remove(m_inputFilePathRaw);
        std::filesystem::remove(m_inputFilePathCompressed);
        std::filesystem::remove_all(m_outputFolder);
    }

    /**
     * @brief Set up routine for the test suite.
     *
     */
    static void SetUpTestSuite()
    {
        if (!m_spFakeServer)
        {
            m_spFakeServer = std::make_unique<FakeServer>("localhost", 4444);
        }
    }

    /**
     * @brief Tear down routine for the test suite.
     *
     */
    static void TearDownTestSuite()
    {
        m_spFakeServer.reset();
    }
};

#endif //_OFFLINE_DOWNLOADER_TEST
