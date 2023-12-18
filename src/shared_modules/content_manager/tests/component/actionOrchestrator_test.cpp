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
#include "actionOrchestrator.hpp"
#include "mocks/mockRouterProvider.hpp"
#include "routerProvider.hpp"
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace Log
{
    std::function<void(
        const int, const std::string&, const std::string&, const int, const std::string&, const std::string&)>
        GLOBAL_LOG_FUNCTION;
};

/*
 * @brief Tests the instantiation of the ActionOrchestratorTest class
 */
TEST_F(ActionOrchestratorTest, TestInstantiation)
{
    const auto& topicName {m_parameters.at("topicName").get_ref<const std::string&>()};
    const auto& outputFolder {m_parameters.at("configData").at("outputFolder").get_ref<const std::string&>()};

    auto routerProvider {std::make_shared<RouterProvider>(topicName)};

    EXPECT_NO_THROW(routerProvider->start());

    EXPECT_NO_THROW(std::make_shared<ActionOrchestrator>(routerProvider, m_parameters, m_shouldRun));

    EXPECT_TRUE(std::filesystem::exists(outputFolder));

    EXPECT_NO_THROW(routerProvider->stop());
}

/*
 * @brief Tests the instantiation of the ActionOrchestratorTest class without configData
 */
TEST_F(ActionOrchestratorTest, TestInstantiationWhitoutConfigData)
{
    // creates a copy of `m_parameters` because it's used in `TearDown` method
    auto parameters = m_parameters;

    const auto& topicName {parameters.at("topicName").get_ref<const std::string&>()};

    auto routerProvider {std::make_shared<RouterProvider>(topicName)};

    EXPECT_NO_THROW(routerProvider->start());

    parameters.erase("configData");

    EXPECT_THROW(std::make_shared<ActionOrchestrator>(routerProvider, parameters, m_shouldRun), std::invalid_argument);

    EXPECT_NO_THROW(routerProvider->stop());
}

/*
 * @brief Tests the instantiation of the ActionOrchestratorTest class without contentSource in configData
 */
TEST_F(ActionOrchestratorTest, TestInstantiationWhitoutContentSourceInConfigData)
{
    const auto& topicName {m_parameters.at("topicName").get_ref<const std::string&>()};
    const auto& outputFolder {m_parameters.at("configData").at("outputFolder").get_ref<const std::string&>()};

    auto routerProvider {std::make_shared<RouterProvider>(topicName)};

    EXPECT_NO_THROW(routerProvider->start());

    m_parameters.at("configData").erase("contentSource");

    EXPECT_THROW(std::make_shared<ActionOrchestrator>(routerProvider, m_parameters, m_shouldRun),
                 std::invalid_argument);

    EXPECT_TRUE(std::filesystem::exists(outputFolder));

    EXPECT_NO_THROW(routerProvider->stop());
}

/*
 * @brief Tests the instantiation of the ActionOrchestratorTest class without compressionType in configData
 */
TEST_F(ActionOrchestratorTest, TestInstantiationWhitoutCompressionTypeInConfigData)
{
    const auto& topicName {m_parameters.at("topicName").get_ref<const std::string&>()};
    const auto& outputFolder {m_parameters.at("configData").at("outputFolder").get_ref<const std::string&>()};

    auto routerProvider {std::make_shared<RouterProvider>(topicName)};

    EXPECT_NO_THROW(routerProvider->start());

    m_parameters.at("configData").erase("compressionType");

    EXPECT_THROW(std::make_shared<ActionOrchestrator>(routerProvider, m_parameters, m_shouldRun),
                 std::invalid_argument);

    EXPECT_TRUE(std::filesystem::exists(outputFolder));

    EXPECT_NO_THROW(routerProvider->stop());
}

/*
 * @brief Tests the instantiation of the ActionOrchestratorTest class with xz compressionType
 */
TEST_F(ActionOrchestratorTest, TestInstantiationWhitXZCompressionType)
{
    const auto& topicName {m_parameters.at("topicName").get_ref<const std::string&>()};
    const auto& outputFolder {m_parameters.at("configData").at("outputFolder").get_ref<const std::string&>()};

    auto routerProvider {std::make_shared<RouterProvider>(topicName)};

    EXPECT_NO_THROW(routerProvider->start());

    m_parameters["configData"]["compressionType"] = "xz";

    EXPECT_NO_THROW(std::make_shared<ActionOrchestrator>(routerProvider, m_parameters, m_shouldRun));

    EXPECT_TRUE(std::filesystem::exists(outputFolder));

    EXPECT_NO_THROW(routerProvider->stop());
}

/*
 * @brief Tests the instantiation of the ActionOrchestratorTest class without versionedContent in configData
 */
TEST_F(ActionOrchestratorTest, TestInstantiationWhitoutVersionedContentInConfigData)
{
    const auto& topicName {m_parameters.at("topicName").get_ref<const std::string&>()};
    const auto& outputFolder {m_parameters.at("configData").at("outputFolder").get_ref<const std::string&>()};

    auto routerProvider {std::make_shared<RouterProvider>(topicName)};

    EXPECT_NO_THROW(routerProvider->start());

    m_parameters.at("configData").erase("versionedContent");

    EXPECT_THROW(std::make_shared<ActionOrchestrator>(routerProvider, m_parameters, m_shouldRun),
                 std::invalid_argument);

    EXPECT_TRUE(std::filesystem::exists(outputFolder));

    EXPECT_NO_THROW(routerProvider->stop());
}

/*
 * @brief Tests the instantiation of the ActionOrchestratorTest class without deleteDownloadedContent in configData
 */
TEST_F(ActionOrchestratorTest, TestInstantiationWhitoutDeleteDownloadedContentInConfigData)
{
    const auto& topicName {m_parameters.at("topicName").get_ref<const std::string&>()};
    const auto& outputFolder {m_parameters.at("configData").at("outputFolder").get_ref<const std::string&>()};

    auto routerProvider {std::make_shared<RouterProvider>(topicName)};

    EXPECT_NO_THROW(routerProvider->start());

    m_parameters.at("configData").erase("deleteDownloadedContent");

    EXPECT_THROW(std::make_shared<ActionOrchestrator>(routerProvider, m_parameters, m_shouldRun),
                 std::invalid_argument);

    EXPECT_TRUE(std::filesystem::exists(outputFolder));

    EXPECT_NO_THROW(routerProvider->stop());
}

/*
 * @brief Tests the instantiation of the ActionOrchestratorTest class and execution of the run method for raw data
 */
TEST_F(ActionOrchestratorTest, TestInstantiationAndExecutionWhitRawCompressionType)
{
    const auto& topicName {m_parameters.at("topicName").get_ref<const std::string&>()};
    const auto& outputFolder {m_parameters.at("configData").at("outputFolder").get_ref<const std::string&>()};
    const auto& fileName {m_parameters.at("configData").at("contentFileName").get_ref<const std::string&>()};
    const auto contentPath {outputFolder + "/" + CONTENTS_FOLDER + "/3-" + fileName};
    const auto downloadPath {outputFolder + "/" + DOWNLOAD_FOLDER + "/3-" + fileName};

    auto routerProvider {std::make_shared<RouterProvider>(topicName)};

    EXPECT_NO_THROW(routerProvider->start());

    auto actionOrchestrator {std::make_shared<ActionOrchestrator>(routerProvider, m_parameters, m_shouldRun)};

    EXPECT_TRUE(std::filesystem::exists(outputFolder));

    EXPECT_NO_THROW(actionOrchestrator->run());

    // This file shouldn't exist because it's a test for raw data
    EXPECT_FALSE(std::filesystem::exists(downloadPath));

    EXPECT_TRUE(std::filesystem::exists(contentPath));

    EXPECT_TRUE(std::filesystem::exists(outputFolder));

    EXPECT_NO_THROW(routerProvider->stop());
}

/*
 * @brief Tests the instantiation of the ActionOrchestratorTest class and execution of the run method for compressed
 * data
 */
TEST_F(ActionOrchestratorTest, TestInstantiationAndExecutionWhitXZCompressionType)
{
    m_parameters["configData"]["url"] = "http://localhost:4444/xz/consumers";
    m_parameters["configData"]["compressionType"] = "xz";

    const auto& topicName {m_parameters.at("topicName").get_ref<const std::string&>()};
    const auto& outputFolder {m_parameters.at("configData").at("outputFolder").get_ref<const std::string&>()};
    const auto& fileName {m_parameters.at("configData").at("contentFileName").get_ref<const std::string&>()};
    const auto contentPath {outputFolder + "/" + CONTENTS_FOLDER + "/3-" + fileName};
    const auto downloadPath {outputFolder + "/" + DOWNLOAD_FOLDER + "/3-" + fileName};

    auto routerProvider {std::make_shared<RouterProvider>(topicName)};

    EXPECT_NO_THROW(routerProvider->start());

    auto actionOrchestrator {std::make_shared<ActionOrchestrator>(routerProvider, m_parameters, m_shouldRun)};

    EXPECT_TRUE(std::filesystem::exists(outputFolder));

    EXPECT_NO_THROW(actionOrchestrator->run());

    // This file should exist because deleteDownloadedContent is not enabled
    EXPECT_TRUE(std::filesystem::exists(downloadPath));

    EXPECT_TRUE(std::filesystem::exists(contentPath));

    EXPECT_TRUE(std::filesystem::exists(outputFolder));

    EXPECT_NO_THROW(routerProvider->stop());
}

/*
 * @brief Tests the instantiation of the ActionOrchestratorTest class and execution of the run method for compressed
 * data with deleteDownloadedContent enabled
 */
TEST_F(ActionOrchestratorTest, TestInstantiationAndExecutionWhitXZCompressionTypeAndDeleteDownloadedContentEnabled)
{
    m_parameters["configData"]["url"] = "http://localhost:4444/xz/consumers";
    m_parameters["configData"]["compressionType"] = "xz";
    m_parameters["configData"]["deleteDownloadedContent"] = true;

    const auto& topicName {m_parameters.at("topicName").get_ref<const std::string&>()};
    const auto& outputFolder {m_parameters.at("configData").at("outputFolder").get_ref<const std::string&>()};
    const auto& fileName {m_parameters.at("configData").at("contentFileName").get_ref<const std::string&>()};
    const auto contentPath {outputFolder + "/" + CONTENTS_FOLDER + "/3-" + fileName};
    const auto downloadPath {outputFolder + "/" + DOWNLOAD_FOLDER + "/3-" + fileName};

    auto routerProvider {std::make_shared<RouterProvider>(topicName)};

    EXPECT_NO_THROW(routerProvider->start());

    auto actionOrchestrator {std::make_shared<ActionOrchestrator>(routerProvider, m_parameters, m_shouldRun)};

    EXPECT_TRUE(std::filesystem::exists(outputFolder));

    EXPECT_NO_THROW(actionOrchestrator->run());

    // This file shouldn't exist because deleteDownloadedContent is enabled
    EXPECT_FALSE(std::filesystem::exists(downloadPath));

    EXPECT_TRUE(std::filesystem::exists(contentPath));

    EXPECT_TRUE(std::filesystem::exists(outputFolder));

    EXPECT_NO_THROW(routerProvider->stop());
}

/**
 * @brief Tests the execution of the orchestration forcing the download of the snapshot before downloading the offsets.
 *
 */
TEST_F(ActionOrchestratorTest, RunWithFullContentDownload)
{
    const auto& topicName {m_parameters.at("topicName").get_ref<const std::string&>()};
    auto routerProvider {std::make_shared<RouterProvider>(topicName)};
    routerProvider->start();

    m_parameters["configData"]["url"] = "http://localhost:4444/snapshot/consumers";
    auto actionOrchestrator {std::make_shared<ActionOrchestrator>(routerProvider, m_parameters, m_shouldRun)};

    // Trigger orchestration with an offset of zero.
    ASSERT_NO_THROW(actionOrchestrator->run(0));

    const auto& outputFolder {m_parameters.at("configData").at("outputFolder").get_ref<const std::string&>()};

    // Check for snapshot existence.
    const auto snapshotPath {outputFolder + "/" + DOWNLOAD_FOLDER + "/" + SNAPSHOT_FILE_NAME};
    EXPECT_TRUE(std::filesystem::exists(snapshotPath));

    // Check for snapshot content existence.
    const auto contentPath {outputFolder + "/" + CONTENTS_FOLDER + "/" + SNAPSHOT_CONTENT_FILE_NAME};
    EXPECT_TRUE(std::filesystem::exists(contentPath));

    routerProvider->stop();
}

/**
 * @brief Tests the execution of the orchestration and correct store of the downloaded file hash.
 *
 */
TEST_F(ActionOrchestratorTest, OfflineDownloadDownloadedFileHashStore)
{
    const auto& topicName {m_parameters.at("topicName").get_ref<const std::string&>()};
    auto routerProvider {std::make_shared<RouterProvider>(topicName)};
    routerProvider->start();

    // Configure the action to download a snapshot in offline mode.
    const auto inputFile {m_inputFilesDir / SNAPSHOT_FILE_NAME};
    m_parameters["configData"]["contentSource"] = "offline";
    m_parameters["configData"]["compressionType"] = "zip";
    m_parameters["configData"]["url"] = "file://" + inputFile.string();

    {
        // Trigger orchestration in a reduced scope so that the database is closed.
        auto actionOrchestrator {std::make_shared<ActionOrchestrator>(routerProvider, m_parameters, m_shouldRun)};
        ASSERT_NO_THROW(actionOrchestrator->run());
    }

    routerProvider->stop();

    const auto EXPECTED_DB_PATH {DATABASE_PATH / ("updater_" + topicName + "_metadata")};
    constexpr auto EXPECTED_HASH {"83f5b8992df285cdd0235bb0304e236047614d60"};
    auto wrapper {Utils::RocksDBWrapper(EXPECTED_DB_PATH)};
    EXPECT_EQ(wrapper.getLastKeyValue(Components::Columns::DOWNLOADED_FILE_HASH).second.ToString(), EXPECTED_HASH);
}

/**
 * @brief Tests the execution of the orchestration three times on different instances: The first two with the same input
 * file and the third one with the same file but modified.
 *
 */
TEST_F(ActionOrchestratorTest, OfflineDownloadSameAndModifiedFileDifferentInstances)
{
    // Create temp test file with dummy data.
    const auto testName {::testing::UnitTest::GetInstance()->current_test_info()->name()};
    const auto inputFilePath {std::filesystem::current_path() / testName};
    std::ofstream testFileStream {inputFilePath};
    if (testFileStream.good())
    {
        testFileStream << testName << std::endl;
    }
    testFileStream.close();

    // Set config.
    m_parameters["configData"]["contentSource"] = "offline";
    m_parameters["configData"]["compressionType"] = "raw";
    m_parameters["configData"]["url"] = "file://" + inputFilePath.string();

    {
        // Run first orchestration. File should be published.
        auto mockRouterProvider {std::make_shared<MockRouterProvider>()};
        EXPECT_CALL(*mockRouterProvider, send(::testing::_)).Times(1);
        ASSERT_NO_THROW(std::make_shared<ActionOrchestrator>(mockRouterProvider, m_parameters, m_shouldRun)->run());
    }

    {
        // Run second orchestration. File should not be published since it didn't change.
        auto mockRouterProvider {std::make_shared<MockRouterProvider>()};
        EXPECT_CALL(*mockRouterProvider, send(::testing::_)).Times(0);
        ASSERT_NO_THROW(std::make_shared<ActionOrchestrator>(mockRouterProvider, m_parameters, m_shouldRun)->run());
    }

    // Modify input file.
    testFileStream.open(inputFilePath, std::ios_base::app);
    testFileStream << testName << std::endl;
    testFileStream.close();

    {
        // Run third orchestration. File should be published since it has changed.
        auto mockRouterProvider {std::make_shared<MockRouterProvider>()};
        EXPECT_CALL(*mockRouterProvider, send(::testing::_)).Times(1);
        ASSERT_NO_THROW(std::make_shared<ActionOrchestrator>(mockRouterProvider, m_parameters, m_shouldRun)->run());
    }

    // Remove input test file.
    std::filesystem::remove(inputFilePath);
}
