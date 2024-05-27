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

#include "executionContext_test.hpp"
#include "componentsHelper.hpp"
#include "defs.h"
#include "executionContext.hpp"
#include "updaterContext.hpp"
#include <filesystem>
#include <memory>
#include <string>

/**
 * @brief Removes the directory if it exists.
 *
 * @param outputFolder Folder to be removed.
 */
void removeOutputFolderIfExists(const std::string& outputFolder)
{
    if (std::filesystem::exists(outputFolder))
    {
        // Delete the output folder.
        std::filesystem::remove_all(outputFolder);
    }
}

/*
 * @brief Tests the instantiation of the ExecutionContext class
 */
TEST_F(ExecutionContextTest, instantiation)
{
    // Check that the ExecutionContext class can be instantiated
    EXPECT_NO_THROW(std::make_shared<ExecutionContext>());
}

/*
 * @brief Test default folder when there is no configuration for the output folder.
 */
TEST_F(ExecutionContextTest, TestDefaultFolderWhenThereIsNoConfigurationForTheOutputFolder)
{
    // Remove the output folder if exists
    removeOutputFolderIfExists(GENERIC_OUTPUT_FOLDER_PATH);

    m_spUpdaterBaseContext->configData.erase("outputFolder");

    m_spExecutionContext->handleRequest(m_spUpdaterBaseContext);

    EXPECT_EQ(m_spUpdaterBaseContext->outputFolder, GENERIC_OUTPUT_FOLDER_PATH);

    EXPECT_TRUE(std::filesystem::exists(m_spUpdaterBaseContext->outputFolder));
}

/*
 * @brief Test default folder when the output folder path is empty.
 */
TEST_F(ExecutionContextTest, TestDefaultFolderWhenTheOutputFolderPathIsEmpty)
{
    // Remove the output folder if exists
    removeOutputFolderIfExists(GENERIC_OUTPUT_FOLDER_PATH);

    m_spUpdaterBaseContext->configData["outputFolder"] = "";

    m_spExecutionContext->handleRequest(m_spUpdaterBaseContext);

    EXPECT_EQ(m_spUpdaterBaseContext->outputFolder, GENERIC_OUTPUT_FOLDER_PATH);

    EXPECT_TRUE(std::filesystem::exists(m_spUpdaterBaseContext->outputFolder));
}

/*
 * @brief Test valid case when the output folder path is not empty.
 */
TEST_F(ExecutionContextTest, TestValidCaseWhenTheOutputFolderPathIsNotEmpty)
{
    const auto expectedOutputFolder {m_spUpdaterBaseContext->configData.at("outputFolder").get<const std::string>()};

    // Remove the output folder if exists
    removeOutputFolderIfExists(expectedOutputFolder);

    m_spExecutionContext->handleRequest(m_spUpdaterBaseContext);

    EXPECT_EQ(m_spUpdaterBaseContext->outputFolder, expectedOutputFolder);

    EXPECT_TRUE(std::filesystem::exists(m_spUpdaterBaseContext->outputFolder));
}

/*
 * @brief Test valid case when the output folder path is not empty and already exists.
 */
TEST_F(ExecutionContextTest, TestValidCaseWhenTheOutputFolderPathIsNotEmptyAndExists)
{
    m_spUpdaterBaseContext->configData["outputFolder"] = "/tmp/output-folder";
    const auto expectedOutputFolder {m_spUpdaterBaseContext->configData.at("outputFolder").get<const std::string>()};

    // Remove the output folder if exists
    removeOutputFolderIfExists(expectedOutputFolder);

    // Create the output folder.
    std::filesystem::create_directory(expectedOutputFolder);

    m_spExecutionContext->handleRequest(m_spUpdaterBaseContext);

    EXPECT_EQ(m_spUpdaterBaseContext->outputFolder, expectedOutputFolder);

    EXPECT_TRUE(std::filesystem::exists(m_spUpdaterBaseContext->outputFolder));
}

/**
 * @brief Test the correct instantiation of the RocksDB database.
 *
 */
TEST_F(ExecutionContextTest, DatabaseGeneration)
{
    constexpr auto OFFSET {0};

    m_spUpdaterBaseContext->configData["databasePath"] = m_databasePath.string();
    m_spUpdaterBaseContext->configData["offset"] = OFFSET;

    EXPECT_NO_THROW(m_spExecutionContext->handleRequest(m_spUpdaterBaseContext));
    EXPECT_TRUE(std::filesystem::exists(m_databasePath));
    EXPECT_EQ(m_spUpdaterBaseContext->spRocksDB->getLastKeyValue(Components::Columns::CURRENT_OFFSET).second.ToString(),
              std::to_string(OFFSET));
}

/**
 * @brief Test the correct instantiation of the RocksDB database. A negative offset is set in the config.
 *
 */
TEST_F(ExecutionContextTest, DatabaseGenerationNegativeOffset)
{
    constexpr auto OFFSET {-1};

    m_spUpdaterBaseContext->configData["databasePath"] = m_databasePath.string();
    m_spUpdaterBaseContext->configData["offset"] = OFFSET;

    EXPECT_THROW(m_spExecutionContext->handleRequest(m_spUpdaterBaseContext), std::runtime_error);
    EXPECT_TRUE(std::filesystem::exists(m_databasePath));
}

/**
 * @brief Test the correct instantiation of the RocksDB database. A positive offset is set in the config.
 *
 */
TEST_F(ExecutionContextTest, DatabaseGenerationPositiveOffset)
{
    constexpr auto OFFSET {100};

    m_spUpdaterBaseContext->configData["databasePath"] = m_databasePath.string();
    m_spUpdaterBaseContext->configData["offset"] = OFFSET;

    EXPECT_NO_THROW(m_spExecutionContext->handleRequest(m_spUpdaterBaseContext));
    EXPECT_TRUE(std::filesystem::exists(m_databasePath));
    EXPECT_EQ(m_spUpdaterBaseContext->spRocksDB->getLastKeyValue(Components::Columns::CURRENT_OFFSET).second.ToString(),
              std::to_string(OFFSET));
}

/**
 * @brief Test the correct instantiation of the RocksDB database in two sequential executions. The second execution has
 * a config offset that is less than the config offset from first execution. The first offset should remain after both
 * executions.
 *
 */
TEST_F(ExecutionContextTest, DatabaseGenerationConfigOffsetLessThanDatabaseOffset)
{
    constexpr auto FIRST_OFFSET {100};
    constexpr auto SECOND_OFFSET {50};

    // First execution.
    m_spUpdaterBaseContext->configData["databasePath"] = m_databasePath.string();
    m_spUpdaterBaseContext->configData["offset"] = FIRST_OFFSET;
    EXPECT_NO_THROW(m_spExecutionContext->handleRequest(m_spUpdaterBaseContext));
    EXPECT_TRUE(std::filesystem::exists(m_databasePath));
    EXPECT_EQ(m_spUpdaterBaseContext->spRocksDB->getLastKeyValue(Components::Columns::CURRENT_OFFSET).second.ToString(),
              std::to_string(FIRST_OFFSET));

    // Call RocksDBWrapper destructor.
    m_spUpdaterBaseContext->spRocksDB.reset();

    // Second execution.
    m_spUpdaterBaseContext->configData["offset"] = SECOND_OFFSET;
    EXPECT_NO_THROW(m_spExecutionContext->handleRequest(m_spUpdaterBaseContext));
    EXPECT_TRUE(std::filesystem::exists(m_databasePath));
    EXPECT_EQ(m_spUpdaterBaseContext->spRocksDB->getLastKeyValue(Components::Columns::CURRENT_OFFSET).second.ToString(),
              std::to_string(FIRST_OFFSET));
}

/**
 * @brief Test the correct instantiation of the RocksDB database in two sequential executions. The second execution has
 * a config offset that is greater than the config offset from first execution. The second offset should remain after
 * both executions.
 *
 */
TEST_F(ExecutionContextTest, DatabaseGenerationConfigOffsetGreaterThanDatabaseOffset)
{
    constexpr auto FIRST_OFFSET {100};
    constexpr auto SECOND_OFFSET {500};

    // First execution.
    m_spUpdaterBaseContext->configData["databasePath"] = m_databasePath.string();
    m_spUpdaterBaseContext->configData["offset"] = FIRST_OFFSET;
    EXPECT_NO_THROW(m_spExecutionContext->handleRequest(m_spUpdaterBaseContext));
    EXPECT_TRUE(std::filesystem::exists(m_databasePath));
    EXPECT_EQ(m_spUpdaterBaseContext->spRocksDB->getLastKeyValue(Components::Columns::CURRENT_OFFSET).second.ToString(),
              std::to_string(FIRST_OFFSET));

    // Call RocksDBWrapper destructor.
    m_spUpdaterBaseContext->spRocksDB.reset();

    // Second execution.
    m_spUpdaterBaseContext->configData["offset"] = SECOND_OFFSET;
    EXPECT_NO_THROW(m_spExecutionContext->handleRequest(m_spUpdaterBaseContext));
    EXPECT_TRUE(std::filesystem::exists(m_databasePath));
    EXPECT_EQ(m_spUpdaterBaseContext->spRocksDB->getLastKeyValue(Components::Columns::CURRENT_OFFSET).second.ToString(),
              std::to_string(SECOND_OFFSET));
}

/**
 * @brief Test the correct instantiation of the RocksDB database in two sequential executions. Both executions have
 * the same config offset.
 *
 */
TEST_F(ExecutionContextTest, DatabaseGenerationConfigOffsetEqualToDatabaseOffset)
{
    constexpr auto OFFSET {100};

    // First execution.
    m_spUpdaterBaseContext->configData["databasePath"] = m_databasePath.string();
    m_spUpdaterBaseContext->configData["offset"] = OFFSET;
    EXPECT_NO_THROW(m_spExecutionContext->handleRequest(m_spUpdaterBaseContext));
    EXPECT_TRUE(std::filesystem::exists(m_databasePath));
    EXPECT_EQ(m_spUpdaterBaseContext->spRocksDB->getLastKeyValue(Components::Columns::CURRENT_OFFSET).second.ToString(),
              std::to_string(OFFSET));

    // Call RocksDBWrapper destructor.
    m_spUpdaterBaseContext->spRocksDB.reset();

    // Second execution.
    EXPECT_NO_THROW(m_spExecutionContext->handleRequest(m_spUpdaterBaseContext));
    EXPECT_TRUE(std::filesystem::exists(m_databasePath));
    EXPECT_EQ(m_spUpdaterBaseContext->spRocksDB->getLastKeyValue(Components::Columns::CURRENT_OFFSET).second.ToString(),
              std::to_string(OFFSET));
}

/**
 * @brief Test the correct set of the downloaded file hash when there is no data on the DB.
 *
 */
TEST_F(ExecutionContextTest, ReadLastDownloadedFileHashInexistant)
{
    m_spUpdaterBaseContext->configData["databasePath"] = m_databasePath;
    m_spUpdaterBaseContext->configData["offset"] = 0;
    m_spExecutionContext->handleRequest(m_spUpdaterBaseContext);

    EXPECT_TRUE(m_spUpdaterBaseContext->downloadedFileHash.empty());
}

/**
 * @brief Test the correct set of the downloaded file hash from the DB.
 *
 */
TEST_F(ExecutionContextTest, ReadLastDownloadedFileHash)
{
    constexpr auto TOPIC_NAME {"topic"};

    m_spUpdaterBaseContext->configData["databasePath"] = m_databasePath;
    m_spUpdaterBaseContext->configData["offset"] = 0;
    m_spUpdaterBaseContext->topicName = TOPIC_NAME;

    // Insert file hash on DB.
    constexpr auto FILE_HASH {"hash"};
    {
        const auto EXPECTED_DB_PATH {m_databasePath / (std::string("updater_") + TOPIC_NAME + "_metadata")};
        auto wrapper {Utils::RocksDBWrapper(EXPECTED_DB_PATH)};
        wrapper.createColumn(Components::Columns::DOWNLOADED_FILE_HASH);
        wrapper.put("test_key", FILE_HASH, Components::Columns::DOWNLOADED_FILE_HASH);
    }

    m_spExecutionContext->handleRequest(m_spUpdaterBaseContext);

    EXPECT_EQ(m_spUpdaterBaseContext->downloadedFileHash, FILE_HASH);
}

/**
 * @brief Tests the correct set of the HTTP user agent context member.
 *
 */
TEST_F(ExecutionContextTest, HttpUserAgentSet)
{
    m_spExecutionContext->handleRequest(m_spUpdaterBaseContext);
    EXPECT_EQ(m_spUpdaterBaseContext->httpUserAgent, m_consumerName + "/" + __ossec_version);
}

/**
 * @brief Test the correct exception generation when the consumerName config is empty.
 *
 */
TEST_F(ExecutionContextTest, HttpUserAgentSetEmptyInputThrow)
{
    m_spUpdaterBaseContext->configData["consumerName"] = "";
    EXPECT_THROW(m_spExecutionContext->handleRequest(m_spUpdaterBaseContext), std::invalid_argument);
}

/**
 * @brief Test the correct exception generation when the consumerName config is not present.
 *
 */
TEST_F(ExecutionContextTest, DefaultHttpUserAgentSet)
{
    m_spUpdaterBaseContext->configData.erase("consumerName");
    EXPECT_THROW(m_spExecutionContext->handleRequest(m_spUpdaterBaseContext), std::invalid_argument);
}
