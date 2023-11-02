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

    const std::filesystem::path m_tempPath {std::filesystem::temp_directory_path()};          ///< Temporary path.
    const std::filesystem::path m_inputFilePathRaw {"file://" / m_tempPath / "testFile.txt"}; ///< Raw input test path.
    const std::filesystem::path m_inputFilePathCompressed {"file://" / m_tempPath /
                                                           "testFile.txt.gz"}; ///< Compressed input test path.
    const std::filesystem::path m_outputFolder {m_tempPath / "offline-downloader-tests"}; ///< Output test folder.
    std::shared_ptr<UpdaterContext> m_spUpdaterContext;         ///< UpdaterContext used on tests.
    std::shared_ptr<UpdaterBaseContext> m_spUpdaterBaseContext; ///< UpdaterBaseContext used on tests.

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
        m_spUpdaterBaseContext = std::make_shared<UpdaterBaseContext>();
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
};

#endif //_OFFLINE_DOWNLOADER_TEST
