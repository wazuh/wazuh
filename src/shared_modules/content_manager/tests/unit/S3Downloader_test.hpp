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

#ifndef _S3_DOWNLOADER_TEST_HPP
#define _S3_DOWNLOADER_TEST_HPP

#include "fakes/fakeServer.hpp"
#include "updaterContext.hpp"
#include "gtest/gtest.h"
#include <filesystem>
#include <memory>

/**
 * @brief Runs unit tests for S3Downloader
 *
 */
class S3DownloaderTest : public ::testing::Test
{
protected:
    S3DownloaderTest() = default;
    ~S3DownloaderTest() override = default;

    std::shared_ptr<UpdaterContext> m_spUpdaterContext; ///< Context used in tests.
    const std::filesystem::path m_outputFolder {std::filesystem::temp_directory_path() /
                                                "s3DownloaderTest"}; ///< Output folder for tests.
    inline static std::unique_ptr<FakeServer> m_spFakeServer;        ///< Fake HTTP server used in tests.

    /**
     * @brief Setup routine for the test suite.
     *
     */
    static void SetUpTestSuite();

    /**
     * @brief Teardown routine for the test suite.
     *
     */
    static void TearDownTestSuite();

    /**
     * @brief Setup routine for each test fixture.
     *
     */
    void SetUp() override;

    /**
     * @brief Teardown routine for each test fixture.
     *
     */
    void TearDown() override;
};

#endif //_S3_DOWNLOADER_TEST_HPP
