/*
 * Wazuh content manager - Unit Tests
 * Copyright (C) 2015, Wazuh Inc.
 * Apr 20, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CLEAN_UP_CONTENT_TEST_HPP
#define _CLEAN_UP_CONTENT_TEST_HPP

#include "cleanUpContent.hpp"
#include "conditionSync.hpp"
#include "updaterContext.hpp"
#include <gtest/gtest.h>

const std::string TEST_DIR {"/tmp/test"};
const std::string DOWNLOAD_DIR {TEST_DIR + "/download"};
const std::string CONTENTS_DIR {TEST_DIR + "/contents"};

/**
 * @brief Runs unit tests for CleanUpContent
 */
class CleanUpContentTest : public ::testing::Test
{
protected:
    CleanUpContentTest() = default;
    ~CleanUpContentTest() override = default;

    /**
     * @brief Context used on the content manager orchestration.
     */
    std::shared_ptr<UpdaterContext> m_spUpdaterContext;

    /**
     * @brief Context used on the content manager orchestration.
     */
    std::shared_ptr<UpdaterBaseContext> m_spUpdaterBaseContext;

    /**
     * @brief Instance of the class to test.
     */
    std::shared_ptr<CleanUpContent> m_spCleanUpContent;

    std::shared_ptr<ConditionSync> m_spStopActionCondition {
        std::make_shared<ConditionSync>(false)}; ///< Stop condition wrapper
    /**
     * @brief Sets up the test fixture.
     */
    void SetUp() override
    {
        // Initialize contexts
        m_spUpdaterBaseContext = std::make_shared<UpdaterBaseContext>(m_spStopActionCondition);

        m_spUpdaterContext = std::make_shared<UpdaterContext>();
        m_spUpdaterContext->spUpdaterBaseContext = m_spUpdaterBaseContext;
        m_spUpdaterContext->spUpdaterBaseContext->downloadsFolder = DOWNLOAD_DIR;
        m_spUpdaterContext->spUpdaterBaseContext->contentsFolder = CONTENTS_DIR;

        // Instance of the class to test
        m_spCleanUpContent = std::make_shared<CleanUpContent>();

        // Create the test directory
        std::filesystem::create_directory(TEST_DIR);
        std::filesystem::create_directory(DOWNLOAD_DIR);
        std::filesystem::create_directory(CONTENTS_DIR);
    }

    /**
     * @brief Tears down the test fixture.
     */
    void TearDown() override
    {
        // Remove the test directory
        std::filesystem::remove_all(TEST_DIR);
    }
};

#endif //_CLEAN_UP_CONTENT_TEST_HPP
