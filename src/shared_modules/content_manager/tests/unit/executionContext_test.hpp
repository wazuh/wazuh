/*
 * Wazuh content manager - Unit Tests
 * Copyright (C) 2015, Wazuh Inc.
 * Jun 07, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _EXECUTION_CONTEXT_TEST_HPP
#define _EXECUTION_CONTEXT_TEST_HPP

#include "conditionSync.hpp"
#include "executionContext.hpp"
#include "updaterContext.hpp"
#include "gtest/gtest.h"
#include <filesystem>
#include <memory>

/**
 * @brief Runs unit tests for ExecutionContext
 */
class ExecutionContextTest : public ::testing::Test
{
protected:
    ExecutionContextTest() = default;
    ~ExecutionContextTest() override = default;

    std::shared_ptr<UpdaterContext> m_spUpdaterContext; ///< UpdaterContext used on the merge pipeline.

    std::shared_ptr<UpdaterBaseContext> m_spUpdaterBaseContext; ///< UpdaterBaseContext used on the merge pipeline.

    std::shared_ptr<ExecutionContext> m_spExecutionContext; ///< ExecutionContext.

    const std::filesystem::path m_databasePath {"/tmp/database"};        ///< Path used to store the database files.
    const std::filesystem::path m_outputFolder {"/tmp/content_manager"}; ///< Path used to store the output files.
    std::shared_ptr<ConditionSync> m_spStopActionCondition {
        std::make_shared<ConditionSync>(false)};               ///< Stop condition wrapper
    const std::string m_consumerName {"ExecutionContextTest"}; ///< Test agent name.

    /**
     * @brief Sets initial conditions for each test case.
     *
     */
    // cppcheck-suppress unusedFunction
    void SetUp() override
    {
        m_spExecutionContext = std::make_shared<ExecutionContext>();
        // Create a updater context
        m_spUpdaterContext = std::make_shared<UpdaterContext>();
        m_spUpdaterBaseContext =
            std::make_shared<UpdaterBaseContext>(m_spStopActionCondition,
                                                 [](const std::string& msg) -> FileProcessingResult {
                                                     return {0, "", false};
                                                 });
        m_spUpdaterBaseContext->configData["outputFolder"] = m_outputFolder.string();
        m_spUpdaterBaseContext->configData["consumerName"] = m_consumerName;
    }

    /**
     * @brief Tear down routine for each test fixture.
     *
     */
    void TearDown() override
    {
        // Destruct RocksDB wrapper.
        if (m_spUpdaterBaseContext->spRocksDB)
        {
            m_spUpdaterBaseContext->spRocksDB.reset();
        }

        std::filesystem::remove_all(m_outputFolder);
        std::filesystem::remove_all(m_databasePath);
    }
};

#endif //_EXECUTION_CONTEXT_TEST_HPP
