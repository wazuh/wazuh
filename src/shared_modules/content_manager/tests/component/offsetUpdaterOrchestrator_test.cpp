/*
 * Wazuh Content Manager - Component Tests
 * Copyright (C) 2015, Wazuh Inc.
 * December 22, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "offsetUpdaterOrchestrator_test.hpp"
#include "components/componentsHelper.hpp"
#include "offsetUpdaterOrchestrator.hpp"
#include "utils/rocksDBWrapper.hpp"
#include "gtest/gtest.h"
#include <filesystem>
#include <memory>
#include <string>

void OffsetUpdaterOrchestratorTest::SetUp()
{
    m_parameters = R"(
        {
            "interval": 1,
            "ondemand": true,
            "configData": {
                "offset": 0
            }
        }
    )"_json;

    m_parameters["topicName"] = m_topicName;
    m_parameters.at("configData")["databasePath"] = m_databaseFolder;
    m_parameters.at("configData")["outputFolder"] = m_outputFolder;

    m_spRocksDBWrapper = std::make_shared<Utils::RocksDBWrapper>(m_databaseFolder);
}

void OffsetUpdaterOrchestratorTest::TearDown()
{
    m_spRocksDBWrapper.reset();
    std::filesystem::remove_all(m_databaseFolder);
    std::filesystem::remove_all(m_outputFolder);
}

/**
 * @brief Tests the correct instantiation of the class.
 *
 */
TEST_F(OffsetUpdaterOrchestratorTest, Instantiation)
{
    EXPECT_NO_THROW(OffsetUpdaterOrchestrator(m_parameters, m_shouldRun, m_spRocksDBWrapper));
    EXPECT_NO_THROW(std::make_shared<OffsetUpdaterOrchestrator>(m_parameters, m_shouldRun, m_spRocksDBWrapper));
}

/**
 * @brief Tests the correct offset update.
 *
 */
TEST_F(OffsetUpdaterOrchestratorTest, RunOrchestration)
{
    constexpr auto OFFSET {100};
    constexpr auto ITERATIONS {5};

    // Run the orchestration ITERATIONS times over the same database.
    for (auto i {0}; i < ITERATIONS; i++)
    {
        auto offsetUpdater {std::make_unique<OffsetUpdaterOrchestrator>(m_parameters, m_shouldRun, m_spRocksDBWrapper)};
        ASSERT_NO_THROW(offsetUpdater->run(OFFSET + i));
        offsetUpdater.reset();

        const auto databaseOffset {
            m_spRocksDBWrapper->getLastKeyValue(Components::Columns::CURRENT_OFFSET).second.ToString()};
        EXPECT_EQ(std::to_string(OFFSET + i), databaseOffset);
    }
}
