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

#include "contentProvider_test.hpp"
#include "contentProvider.hpp"
#include <filesystem>
#include <memory>
#include <stdexcept>

/*
 * @brief Tests the instantiation of the ContentProvider class
 */
TEST_F(ContentProviderTest, TestInstantiation)
{
    const auto& topicName {m_parameters.at("topicName").get_ref<const std::string&>()};
    const auto& outputFolder {m_parameters.at("configData").at("outputFolder").get_ref<const std::string&>()};

    EXPECT_NO_THROW(std::make_shared<ContentProvider>(topicName,
                                                      m_parameters,
                                                      [](const std::string& msg) -> FileProcessingResult {
                                                          return {0, "", false};
                                                      }));

    EXPECT_TRUE(std::filesystem::exists(outputFolder));
}

/*
 * @brief Tests the instantiation of the ContentProvider class without configData
 */
TEST_F(ContentProviderTest, TestInstantiationWithoutConfigData)
{
    // creates a copy of `m_parameters` because it's used in `TearDown` method
    auto parameters = m_parameters;

    const auto& topicName {parameters.at("topicName").get_ref<const std::string&>()};

    parameters.erase("configData");

    EXPECT_THROW(std::make_shared<ContentProvider>(topicName,
                                                   parameters,
                                                   [](const std::string& msg) -> FileProcessingResult {
                                                       return {0, "", false};
                                                   }),
                 std::invalid_argument);
}

/*
 * @brief Tests the instantiation of the ContentProvider class and start action scheduler
 */
TEST_F(ContentProviderTest, TestInstantiationAndStartActionScheduler)
{
    const auto& topicName {m_parameters.at("topicName").get_ref<const std::string&>()};
    const auto& outputFolder {m_parameters.at("configData").at("outputFolder").get_ref<const std::string&>()};
    const auto& interval {m_parameters.at("interval").get_ref<const size_t&>()};

    auto contentProvider {std::make_shared<ContentProvider>(topicName,
                                                            m_parameters,
                                                            [](const std::string& msg) -> FileProcessingResult {
                                                                return {0, "", false};
                                                            })};

    EXPECT_NO_THROW(contentProvider->startActionScheduler(interval));

    EXPECT_TRUE(std::filesystem::exists(outputFolder));
}

/*
 * @brief Tests the instantiation of the ContentProvider class and change scheduler interval
 */
TEST_F(ContentProviderTest, TestInstantiationAndChangeSchedulerInterval)
{
    const auto& topicName {m_parameters.at("topicName").get_ref<const std::string&>()};
    const auto& outputFolder {m_parameters.at("configData").at("outputFolder").get_ref<const std::string&>()};
    const auto& interval {m_parameters.at("interval").get_ref<const size_t&>()};

    auto contentProvider {std::make_shared<ContentProvider>(topicName,
                                                            m_parameters,
                                                            [](const std::string& msg) -> FileProcessingResult {
                                                                return {0, "", false};
                                                            })};

    EXPECT_NO_THROW(contentProvider->startActionScheduler(interval));

    EXPECT_NO_THROW(contentProvider->changeSchedulerInterval(interval + 1));

    EXPECT_TRUE(std::filesystem::exists(outputFolder));
}
