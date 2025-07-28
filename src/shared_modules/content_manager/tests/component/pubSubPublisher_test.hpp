/*
 * Wazuh content manager - Component Tests
 * Copyright (C) 2015, Wazuh Inc.
 * Jun 20, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PUB_SUB_PUBLISHER_TEST_HPP
#define _PUB_SUB_PUBLISHER_TEST_HPP

#include "conditionSync.hpp"
#include "pubSubPublisher.hpp"
#include "updaterContext.hpp"
#include "gtest/gtest.h"
#include <memory>

/**
 * @brief Runs component tests for PubSubPublisher
 */
class PubSubPublisherTest : public ::testing::Test
{
protected:
    PubSubPublisherTest() = default;
    ~PubSubPublisherTest() override = default;

    std::shared_ptr<UpdaterContext> m_spUpdaterContext; ///< UpdaterContext used on the merge pipeline.

    std::shared_ptr<UpdaterBaseContext> m_spUpdaterBaseContext; ///< UpdaterBaseContext used on the merge pipeline.

    std::shared_ptr<PubSubPublisher> m_spPubSubPublisher; ///< PubSubPublisher used to publish the content data.
    std::shared_ptr<ConditionSync> m_spStopActionCondition {
        std::make_shared<ConditionSync>(false)}; ///< Stop condition wrapper

    /**
     * @brief Sets initial conditions for each test case.
     *
     */
    // cppcheck-suppress unusedFunction
    void SetUp() override
    {
        m_spPubSubPublisher = std::make_shared<PubSubPublisher>();
        // Create a updater context
        m_spUpdaterContext = std::make_shared<UpdaterContext>();
        m_spUpdaterBaseContext =
            std::make_shared<UpdaterBaseContext>(m_spStopActionCondition,
                                                 [](const std::string& msg) -> FileProcessingResult {
                                                     return {0, "", true};
                                                 });
    }
};

#endif //_PUB_SUB_PUBLISHER_TEST_HPP
