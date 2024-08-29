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

#include "contentModuleFacade_test.hpp"
#include "contentModuleFacade.hpp"
#include "stringHelper.h"
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>

/*
 * @brief Tests singleton of the ContentModuleFacade class
 */
TEST_F(ContentModuleFacadeTest, TestSingleton)
{
    auto& contentModuleFacade = ContentModuleFacade::instance();

    EXPECT_EQ(&contentModuleFacade, &ContentModuleFacade::instance());
}

/*
 * @brief Tests singleton of the ContentModuleFacade class and start
 */
TEST_F(ContentModuleFacadeTest, TestSingletonAndStart)
{
    auto& contentModuleFacade = ContentModuleFacade::instance();

    EXPECT_EQ(&contentModuleFacade, &ContentModuleFacade::instance());

    EXPECT_NO_THROW(contentModuleFacade.start({}));

    EXPECT_NO_THROW(contentModuleFacade.stop());
}

/*
 * @brief Tests singleton of the ContentModuleFacade class and add provider
 */
TEST_F(ContentModuleFacadeTest, TestSingletonAndAddProvider)
{
    const auto& topicName {m_parameters.at("topicName").get_ref<const std::string&>()};

    auto& contentModuleFacade = ContentModuleFacade::instance();

    EXPECT_EQ(&contentModuleFacade, &ContentModuleFacade::instance());

    EXPECT_NO_THROW(contentModuleFacade.start({}));

    EXPECT_NO_THROW(contentModuleFacade.addProvider(topicName, m_parameters));

    EXPECT_NO_THROW(contentModuleFacade.stop());
}

/*
 * @brief Tests singleton of the ContentModuleFacade class and add two provider with the same name
 */
TEST_F(ContentModuleFacadeTest, TestSingletonAndAddTwoProviders)
{
    const auto& topicName {m_parameters.at("topicName").get_ref<const std::string&>()};

    auto& contentModuleFacade = ContentModuleFacade::instance();

    EXPECT_EQ(&contentModuleFacade, &ContentModuleFacade::instance());

    EXPECT_NO_THROW(contentModuleFacade.start({}));

    EXPECT_NO_THROW(contentModuleFacade.addProvider(topicName, m_parameters));

    EXPECT_THROW(contentModuleFacade.addProvider(topicName, m_parameters), std::runtime_error);

    EXPECT_NO_THROW(contentModuleFacade.stop());
}

/*
 * @brief Tests singleton of the ContentModuleFacade class and start scheduling for raw data
 */
TEST_F(ContentModuleFacadeTest, TestSingletonAndStartSchedulingForRawData)
{
    const auto& topicName {m_parameters.at("topicName").get_ref<const std::string&>()};
    const auto& interval {m_parameters.at("interval").get_ref<const size_t&>()};
    const auto& outputFolder {m_parameters.at("configData").at("outputFolder").get_ref<const std::string&>()};
    const auto& fileName {m_parameters.at("configData").at("contentFileName").get_ref<const std::string&>()};
    const auto contentPath {outputFolder + "/" + CONTENTS_FOLDER + "/3-" + fileName};
    const auto downloadPath {outputFolder + "/" + DOWNLOAD_FOLDER + "/3-" + fileName};

    auto& contentModuleFacade = ContentModuleFacade::instance();

    EXPECT_EQ(&contentModuleFacade, &ContentModuleFacade::instance());

    EXPECT_NO_THROW(contentModuleFacade.start({}));

    EXPECT_NO_THROW(contentModuleFacade.addProvider(topicName, m_parameters));

    EXPECT_NO_THROW(contentModuleFacade.startScheduling(topicName, interval));

    std::this_thread::sleep_for(std::chrono::seconds(interval + 1));

    EXPECT_NO_THROW(contentModuleFacade.stop());

    // This file shouldn't exist because it's a test for raw data
    EXPECT_FALSE(std::filesystem::exists(downloadPath));

    EXPECT_TRUE(std::filesystem::exists(contentPath));

    EXPECT_TRUE(std::filesystem::exists(outputFolder));
}

/*
 * @brief Tests singleton of the ContentModuleFacade class and change scheduler interval for raw data
 */
TEST_F(ContentModuleFacadeTest, TestSingletonAndChangeSchedulerIntervalForRawData)
{
    const auto& topicName {m_parameters.at("topicName").get_ref<const std::string&>()};
    const auto& interval {m_parameters.at("interval").get_ref<const size_t&>()};
    const auto& outputFolder {m_parameters.at("configData").at("outputFolder").get_ref<const std::string&>()};
    const auto& fileName {m_parameters.at("configData").at("contentFileName").get_ref<const std::string&>()};
    const auto contentPath {outputFolder + "/" + CONTENTS_FOLDER + "/3-" + fileName};
    const auto downloadPath {outputFolder + "/" + DOWNLOAD_FOLDER + "/3-" + fileName};

    auto& contentModuleFacade = ContentModuleFacade::instance();

    EXPECT_EQ(&contentModuleFacade, &ContentModuleFacade::instance());

    EXPECT_NO_THROW(contentModuleFacade.start({}));

    EXPECT_NO_THROW(contentModuleFacade.addProvider(topicName, m_parameters));

    EXPECT_NO_THROW(contentModuleFacade.changeSchedulerInterval(topicName, interval + 1));

    std::this_thread::sleep_for(std::chrono::seconds(interval + 1));

    EXPECT_NO_THROW(contentModuleFacade.stop());

    // This file shouldn't exist because it's a test for raw data
    EXPECT_FALSE(std::filesystem::exists(downloadPath));

    EXPECT_FALSE(std::filesystem::exists(contentPath));

    EXPECT_TRUE(std::filesystem::exists(outputFolder));
}

/*
 * @brief Tests singleton of the ContentModuleFacade class and change scheduler interval without provider
 */
TEST_F(ContentModuleFacadeTest, TestSingletonAndChangeSchedulerIntervalWithoutProvider)
{
    const auto& topicName {m_parameters.at("topicName").get_ref<const std::string&>()};
    const auto& interval {m_parameters.at("interval").get_ref<const size_t&>()};
    const auto& outputFolder {m_parameters.at("configData").at("outputFolder").get_ref<const std::string&>()};
    const auto& fileName {m_parameters.at("configData").at("contentFileName").get_ref<const std::string&>()};
    const auto contentPath {outputFolder + "/" + CONTENTS_FOLDER + "/3-" + fileName};
    const auto downloadPath {outputFolder + "/" + DOWNLOAD_FOLDER + "/3-" + fileName};

    auto& contentModuleFacade = ContentModuleFacade::instance();

    EXPECT_EQ(&contentModuleFacade, &ContentModuleFacade::instance());

    EXPECT_NO_THROW(contentModuleFacade.start({}));

    EXPECT_NO_THROW(contentModuleFacade.changeSchedulerInterval(topicName, interval + 1));

    std::this_thread::sleep_for(std::chrono::seconds(interval + 1));

    EXPECT_NO_THROW(contentModuleFacade.stop());

    // This file shouldn't exist because it's a test for raw data
    EXPECT_FALSE(std::filesystem::exists(downloadPath));

    EXPECT_FALSE(std::filesystem::exists(contentPath));
}

/*
 * @brief Tests singleton of the ContentModuleFacade class and start on demand for raw data
 */
TEST_F(ContentModuleFacadeTest, TestSingletonAndStartOnDemandForRawData)
{
    const auto& topicName {m_parameters.at("topicName").get_ref<const std::string&>()};
    const auto& outputFolder {m_parameters.at("configData").at("outputFolder").get_ref<const std::string&>()};
    const auto& fileName {m_parameters.at("configData").at("contentFileName").get_ref<const std::string&>()};
    const auto contentPath {outputFolder + "/" + CONTENTS_FOLDER + "/3-" + fileName};
    const auto downloadPath {outputFolder + "/" + DOWNLOAD_FOLDER + "/3-" + fileName};

    m_parameters["ondemand"] = true;

    auto& contentModuleFacade = ContentModuleFacade::instance();

    EXPECT_EQ(&contentModuleFacade, &ContentModuleFacade::instance());

    EXPECT_NO_THROW(contentModuleFacade.start({}));

    EXPECT_NO_THROW(contentModuleFacade.addProvider(topicName, m_parameters));

    EXPECT_NO_THROW(contentModuleFacade.startOndemand(topicName));

    std::this_thread::sleep_for(std::chrono::seconds(1));

    EXPECT_NO_THROW(contentModuleFacade.stop());

    // This file shouldn't exist because it's a test for raw data
    EXPECT_FALSE(std::filesystem::exists(downloadPath));

    EXPECT_FALSE(std::filesystem::exists(contentPath));

    EXPECT_TRUE(std::filesystem::exists(outputFolder));
}

/*
 * @brief Tests singleton of the ContentModuleFacade class and start on demand without provider
 */
TEST_F(ContentModuleFacadeTest, TestSingletonAndStartOnDemandWithoutProvider)
{
    const auto& topicName {m_parameters.at("topicName").get_ref<const std::string&>()};
    const auto& outputFolder {m_parameters.at("configData").at("outputFolder").get_ref<const std::string&>()};
    const auto& fileName {m_parameters.at("configData").at("contentFileName").get_ref<const std::string&>()};
    const auto contentPath {outputFolder + "/" + CONTENTS_FOLDER + "/3-" + fileName};
    const auto downloadPath {outputFolder + "/" + DOWNLOAD_FOLDER + "/3-" + fileName};

    m_parameters["ondemand"] = true;

    auto& contentModuleFacade = ContentModuleFacade::instance();

    EXPECT_EQ(&contentModuleFacade, &ContentModuleFacade::instance());

    EXPECT_NO_THROW(contentModuleFacade.start({}));

    EXPECT_NO_THROW(contentModuleFacade.startOndemand(topicName));

    std::this_thread::sleep_for(std::chrono::seconds(1));

    EXPECT_NO_THROW(contentModuleFacade.stop());

    // This file shouldn't exist because it's a test for raw data
    EXPECT_FALSE(std::filesystem::exists(downloadPath));

    EXPECT_FALSE(std::filesystem::exists(contentPath));
}

/*
 * @brief Tests singleton of the ContentModuleFacade class and start scheduling for compressed data
 */
TEST_F(ContentModuleFacadeTest, TestSingletonAndStartSchedulingForCompressedData)
{
    m_parameters["configData"]["url"] = "http://localhost:4444/xz/consumers";
    m_parameters["configData"]["compressionType"] = "xz";

    // Append XZ extension.
    auto& fileName {m_parameters.at("configData").at("contentFileName").get_ref<std::string&>()};
    fileName += ".xz";

    const auto& topicName {m_parameters.at("topicName").get_ref<const std::string&>()};
    const auto& interval {m_parameters.at("interval").get_ref<const size_t&>()};
    const auto& outputFolder {m_parameters.at("configData").at("outputFolder").get_ref<const std::string&>()};
    const auto downloadPath {outputFolder + "/" + DOWNLOAD_FOLDER + "/3-" + fileName};

    auto& contentModuleFacade = ContentModuleFacade::instance();

    EXPECT_EQ(&contentModuleFacade, &ContentModuleFacade::instance());

    EXPECT_NO_THROW(contentModuleFacade.start({}));

    EXPECT_NO_THROW(contentModuleFacade.addProvider(topicName, m_parameters));

    EXPECT_NO_THROW(contentModuleFacade.startScheduling(topicName, interval));

    std::this_thread::sleep_for(std::chrono::seconds(interval + 1));

    EXPECT_NO_THROW(contentModuleFacade.stop());

    // This file should exist because deleteDownloadedContent is not enabled
    EXPECT_TRUE(std::filesystem::exists(downloadPath));

    const auto contentPath {outputFolder + "/" + CONTENTS_FOLDER + "/3-" + Utils::rightTrim(fileName, ".xz")};
    EXPECT_TRUE(std::filesystem::exists(contentPath));

    EXPECT_TRUE(std::filesystem::exists(outputFolder));
}

/*
 * @brief Tests singleton of the ContentModuleFacade class and startScheduling without provider
 */
TEST_F(ContentModuleFacadeTest, TestSingletonAndStartSchedulingWithoutProvider)
{
    const auto& topicName {m_parameters.at("topicName").get_ref<const std::string&>()};
    const auto& interval {m_parameters.at("interval").get_ref<const size_t&>()};

    m_parameters["configData"]["compressionType"] = "xz";

    auto& contentModuleFacade = ContentModuleFacade::instance();

    EXPECT_EQ(&contentModuleFacade, &ContentModuleFacade::instance());

    EXPECT_NO_THROW(contentModuleFacade.start({}));

    EXPECT_NO_THROW(contentModuleFacade.startScheduling(topicName, interval));

    std::this_thread::sleep_for(std::chrono::seconds(interval + 1));

    EXPECT_NO_THROW(contentModuleFacade.stop());
}

/*
 * @brief Tests singleton of the ContentModuleFacade class and start scheduling for compressed data
 *  with deleteDownloadedContent enabled
 */
TEST_F(ContentModuleFacadeTest,
       TestSingletonAndStartSchedulingMethodForCompressedDataWithDeleteDownloadedContentEnabled)
{
    m_parameters["configData"]["url"] = "http://localhost:4444/xz/consumers";
    m_parameters["configData"]["compressionType"] = "xz";
    m_parameters["configData"]["deleteDownloadedContent"] = true;

    // Append XZ extension.
    auto& fileName {m_parameters.at("configData").at("contentFileName").get_ref<std::string&>()};
    fileName += ".xz";

    const auto& topicName {m_parameters.at("topicName").get_ref<const std::string&>()};
    const auto& interval {m_parameters.at("interval").get_ref<const size_t&>()};
    const auto& outputFolder {m_parameters.at("configData").at("outputFolder").get_ref<const std::string&>()};
    const auto downloadPath {outputFolder + "/" + DOWNLOAD_FOLDER + "/3-" + fileName};

    auto& contentModuleFacade = ContentModuleFacade::instance();

    EXPECT_EQ(&contentModuleFacade, &ContentModuleFacade::instance());

    EXPECT_NO_THROW(contentModuleFacade.start({}));

    EXPECT_NO_THROW(contentModuleFacade.addProvider(topicName, m_parameters));

    EXPECT_NO_THROW(contentModuleFacade.startScheduling(topicName, interval));

    std::this_thread::sleep_for(std::chrono::seconds(interval + 1));

    EXPECT_NO_THROW(contentModuleFacade.stop());

    // This file shouldn't exist because deleteDownloadedContent is enabled
    EXPECT_FALSE(std::filesystem::exists(downloadPath));

    const auto contentPath {outputFolder + "/" + CONTENTS_FOLDER + "/3-" + Utils::rightTrim(fileName, ".xz")};
    EXPECT_TRUE(std::filesystem::exists(contentPath));

    EXPECT_TRUE(std::filesystem::exists(outputFolder));
}
