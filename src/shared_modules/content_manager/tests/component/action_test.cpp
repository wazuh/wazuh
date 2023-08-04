/*
 * Wazuh content manager - Unit Tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 26, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "action_test.hpp"
#include "action.hpp"
#include "routerProvider.hpp"
#include <chrono>
#include <filesystem>
#include <memory>
#include <string>
#include <thread>

/*
 * @brief Tests the instantiation of the Action class
 */
TEST_F(ActionTest, TestInstantiation)
{
    const auto& topicName {m_parameters.at("topicName").get_ref<const std::string&>()};
    const auto& outputFolder {m_parameters.at("configData").at("outputFolder").get_ref<const std::string&>()};

    auto routerProvider {std::make_shared<RouterProvider>(topicName)};

    EXPECT_NO_THROW(routerProvider->start());

    EXPECT_NO_THROW(std::make_shared<Action>(routerProvider, topicName, m_parameters));

    EXPECT_TRUE(std::filesystem::exists(outputFolder));

    EXPECT_NO_THROW(routerProvider->stop());
}

/*
 * @brief Tests the instantiation of the Action class without configData
 */
TEST_F(ActionTest, TestInstantiationWhitoutConfigData)
{
    // creates a copy of `m_parameters` because it's used in `TearDown` method
    auto parameters = m_parameters;

    const auto& topicName {parameters.at("topicName").get_ref<const std::string&>()};

    auto routerProvider {std::make_shared<RouterProvider>(topicName)};

    EXPECT_NO_THROW(routerProvider->start());

    parameters.erase("configData");

    EXPECT_THROW(std::make_shared<Action>(routerProvider, topicName, parameters), std::invalid_argument);

    EXPECT_NO_THROW(routerProvider->stop());
}

/*
 * @brief Tests the instantiation of the Action class and execution of startActionScheduler for raw data
 */
TEST_F(ActionTest, TestInstantiationAndStartActionSchedulerForRawData)
{
    const auto& topicName {m_parameters.at("topicName").get_ref<const std::string&>()};
    const auto& outputFolder {m_parameters.at("configData").at("outputFolder").get_ref<const std::string&>()};
    const auto& fileName {m_parameters.at("configData").at("fileName").get_ref<const std::string&>()};
    const auto& interval {m_parameters.at("interval").get_ref<const size_t&>()};
    const auto filePath {outputFolder + "/" + fileName};

    auto routerProvider {std::make_shared<RouterProvider>(topicName)};

    EXPECT_NO_THROW(routerProvider->start());

    auto action {std::make_shared<Action>(routerProvider, topicName, m_parameters)};

    EXPECT_TRUE(std::filesystem::exists(outputFolder));

    EXPECT_NO_THROW(action->startActionScheduler(interval));

    std::this_thread::sleep_for(std::chrono::seconds(interval + 1));

    EXPECT_NO_THROW(action->stopActionScheduler());

    // This file shouldn't exist because it's a test for raw data
    EXPECT_FALSE(std::filesystem::exists(filePath));

    EXPECT_TRUE(std::filesystem::exists(outputFolder));

    EXPECT_NO_THROW(routerProvider->stop());
}

/*
 * @brief Tests the instantiation of the Action class and execution of startActionScheduler for compressed data with
 * deleteDownloadedContent enabled
 */
TEST_F(ActionTest, TestInstantiationAndStartActionSchedulerForRawDataWithDeleteDownloadedContentEnabled)
{
    const auto& topicName {m_parameters.at("topicName").get_ref<const std::string&>()};
    const auto& outputFolder {m_parameters.at("configData").at("outputFolder").get_ref<const std::string&>()};
    const auto& fileName {m_parameters.at("configData").at("fileName").get_ref<const std::string&>()};
    const auto& interval {m_parameters.at("interval").get_ref<const size_t&>()};
    const auto filePath {outputFolder + "/" + fileName};

    auto routerProvider {std::make_shared<RouterProvider>(topicName)};

    EXPECT_NO_THROW(routerProvider->start());

    m_parameters["configData"]["compressionType"] = "xz";
    m_parameters["configData"]["deleteDownloadedContent"] = true;

    auto action {std::make_shared<Action>(routerProvider, topicName, m_parameters)};

    EXPECT_TRUE(std::filesystem::exists(outputFolder));

    EXPECT_NO_THROW(action->startActionScheduler(interval));

    std::this_thread::sleep_for(std::chrono::seconds(interval + 1));

    EXPECT_NO_THROW(action->stopActionScheduler());

    // This file shouldn't exist because deleteDownloadedContent is enabled
    EXPECT_FALSE(std::filesystem::exists(filePath));

    EXPECT_TRUE(std::filesystem::exists(outputFolder));

    EXPECT_NO_THROW(routerProvider->stop());
}

/*
 * @brief Tests the instantiation of the Action class and execution of startActionScheduler for
 * compressed data
 */
TEST_F(ActionTest, TestInstantiationAndStartActionSchedulerForCompressedData)
{
    const auto& topicName {m_parameters.at("topicName").get_ref<const std::string&>()};
    const auto& outputFolder {m_parameters.at("configData").at("outputFolder").get_ref<const std::string&>()};
    const auto& fileName {m_parameters.at("configData").at("fileName").get_ref<const std::string&>()};
    const auto& interval {m_parameters.at("interval").get_ref<const size_t&>()};
    const auto filePath {outputFolder + "/" + fileName};

    auto routerProvider {std::make_shared<RouterProvider>(topicName)};

    EXPECT_NO_THROW(routerProvider->start());

    m_parameters["configData"]["compressionType"] = "xz";

    auto action {std::make_shared<Action>(routerProvider, topicName, m_parameters)};

    EXPECT_TRUE(std::filesystem::exists(outputFolder));

    EXPECT_NO_THROW(action->startActionScheduler(interval));

    std::this_thread::sleep_for(std::chrono::seconds(interval + 1));

    EXPECT_NO_THROW(action->stopActionScheduler());

    // This file should exist because deleteDownloadedContent is not enabled
    EXPECT_TRUE(std::filesystem::exists(filePath));

    EXPECT_TRUE(std::filesystem::exists(outputFolder));

    EXPECT_NO_THROW(routerProvider->stop());
}

/*
 * @brief Tests the instantiation of the Action class and execution of registerActionOnDemand for raw data
 */
TEST_F(ActionTest, TestInstantiationAndRegisterActionOnDemandForRawData)
{
    GTEST_SKIP();
    auto routerProvider {std::make_shared<RouterProvider>(m_parameters.at("topicName"))};

    EXPECT_NO_THROW(routerProvider->start());

    m_parameters["ondemand"] = true;

    auto action {std::make_shared<Action>(routerProvider, m_parameters.at("topicName"), m_parameters)};

    EXPECT_TRUE(std::filesystem::exists(m_parameters.at("configData").at("outputFolder")));

    EXPECT_NO_THROW(action->registerActionOnDemand());

    EXPECT_NO_THROW(action->unregisterActionOnDemand());

    std::string filePath = m_parameters.at("configData").at("outputFolder").get<std::string>() + "/" +
                           m_parameters.at("configData").at("fileName").get<std::string>();

    EXPECT_TRUE(std::filesystem::exists(filePath));

    EXPECT_NO_THROW(routerProvider->stop());
}
