/*
 * Wazuh Content Manager - Unit Tests
 * Copyright (C) 2015, Wazuh Inc.
 * Dec 01, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CTI_SNAPSHOT_DOWNLOADER_TEST_HPP
#define _CTI_SNAPSHOT_DOWNLOADER_TEST_HPP

#include "fakes/fakeServer.hpp"
#include "updaterContext.hpp"
#include "gtest/gtest.h"
#include <memory>

/**
 * @brief Runs unit tests for CtiSnapshotDownloader
 *
 */
class CtiSnapshotDownloaderTest : public ::testing::Test
{
protected:
    CtiSnapshotDownloaderTest() = default;
    ~CtiSnapshotDownloaderTest() override = default;

    std::shared_ptr<UpdaterContext> m_spUpdaterContext;       ///< UpdaterContext used on the merge pipeline.
    inline static std::unique_ptr<FakeServer> m_spFakeServer; ///< FakeServer used for tests.

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
};

#endif //_CTI_SNAPSHOT_DOWNLOADER_TEST_HPP
