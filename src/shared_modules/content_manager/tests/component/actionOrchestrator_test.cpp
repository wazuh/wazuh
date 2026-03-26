/*
 * Wazuh content manager - Component Tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 26, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "actionOrchestrator_test.hpp"

#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include "actionOrchestrator.hpp"
#include "stringHelper.h"

namespace Log
{
    std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>
        GLOBAL_LOG_FUNCTION;
}; // namespace Log

/*
 * @brief Tests the instantiation of the ActionOrchestratorTest class
 */
TEST_F(ActionOrchestratorTest, TestInstantiation)
{
    const auto& topicName {m_parameters.at("topicName").get_ref<const std::string&>()};
    const auto& outputFolder {m_parameters.at("configData").at("outputFolder").get_ref<const std::string&>()};

    EXPECT_NO_THROW(std::make_shared<ActionOrchestrator>(m_parameters,
                                                         m_spStopActionCondition,
                                                         [](nlohmann::json msg) -> FileProcessingResult {
                                                             return {0, "", false};
                                                         }));

    EXPECT_TRUE(std::filesystem::exists(outputFolder));
}

/*
 * @brief Tests the instantiation of the ActionOrchestratorTest class without configData
 */
TEST_F(ActionOrchestratorTest, TestInstantiationWhitoutConfigData)
{
    // creates a copy of `m_parameters` because it's used in `TearDown` method
    auto parameters = m_parameters;

    const auto& topicName {parameters.at("topicName").get_ref<const std::string&>()};

    parameters.erase("configData");

    EXPECT_THROW(std::make_shared<ActionOrchestrator>(parameters,
                                                      m_spStopActionCondition,
                                                      [](nlohmann::json msg) -> FileProcessingResult {
                                                          return {0, "", false};
                                                      }),
                 std::invalid_argument);
}
