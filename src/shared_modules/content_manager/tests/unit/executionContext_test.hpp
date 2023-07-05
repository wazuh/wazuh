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

#include "executionContext.hpp"
#include "updaterContext.hpp"
#include "gtest/gtest.h"
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
        m_spUpdaterBaseContext = std::make_shared<UpdaterBaseContext>();
        m_spUpdaterBaseContext->configData = R"(
            {
                "outputFolder": "/tmp/content_manager"
            }
        )"_json;
    }
};

#endif //_EXECUTION_CONTEXT_TEST_HPP
