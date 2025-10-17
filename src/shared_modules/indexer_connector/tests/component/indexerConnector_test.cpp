/*
 * Wazuh Indexer Connector - Component tests
 * Copyright (C) 2015, Wazuh Inc.
 * January 09, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "indexerConnector_test.hpp"
#include "fakeIndexer.hpp"
#include "indexerConnector.hpp"
#include "json.hpp"
#include "stringHelper.h"
#include "gtest/gtest.h"
#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <thread>
#include <utility>

#define LOG_BUFFER_SIZE 4096

namespace Log
{
    std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>
        GLOBAL_LOG_FUNCTION;
}; // namespace Log

// Template.
static const auto TEMPLATE_FILE_PATH {std::filesystem::temp_directory_path() / "template.json"};
static const auto TEMPLATE_DATA = R"(
    {
        "index_patterns": [
            "logs-2020-01-*"
        ],
        "template": {
            "aliases": {
                "my_logs": {}
            },
            "settings": {
                "number_of_shards": 2,
                "number_of_replicas": 1
            },
            "mappings": {
                "properties": {
                    "timestamp": {
                        "type": "date",
                        "format": "yyyy-MM-dd HH:mm:ss||yyyy-MM-dd||epoch_millis"
                    },
                    "value": {
                        "type": "double"
                    }
                }
            }
        }
    }
)"_json; // Real template example.

// Indexers.
static const auto INDEXER_TIMEOUT {0u};
static const std::string INDEXER_HOSTNAME {"localhost"};
static const auto INDEXER_NAME {"indexer_connector_test"}; // Should be in lowercase for a real indexer.
static const auto MAX_INDEXER_INIT_TIME_MS {2000};
static const auto MAX_INDEXER_PUBLISH_TIME_MS {7500};
static const auto INDEX_ID_A {"A"};
static const auto INDEX_ID_B {"B"};

// Indexer A.
static const auto A_IDX {0};
static const auto A_PORT {9999};
static const auto A_ADDRESS {INDEXER_HOSTNAME + ":" + std::to_string(A_PORT)};

// Indexer B.
static const auto B_IDX {1};
static const auto B_PORT {8888};
static const auto B_ADDRESS {INDEXER_HOSTNAME + ":" + std::to_string(B_PORT)};

// Indexer C.
static const auto C_IDX {2};
static const auto C_PORT {7777};
static const auto C_ADDRESS {INDEXER_HOSTNAME + ":" + std::to_string(C_PORT)};

/**
 * @brief Keeps track of the log messages received during the tests.
 *
 * This structure stores information about various error types and log counts
 * encountered during indexer connector component tests.
 */
struct LogTestState
{
    std::atomic<int> errorLogsCount {0};                 ///< Number of error logs received.
    std::atomic<bool> foundMapperError {false};          ///< Found mapper parsing exception.
    std::atomic<bool> foundVersionConflictError {false}; ///< Found version conflict exception.
    std::atomic<bool> foundParseError {false};           ///< Found parse error.
    std::atomic<bool> foundUnknownReason {false};        ///< Found unknown reason.
    std::atomic<bool> foundUnknownType {false};          ///< Found unknown type.
    std::atomic<bool> dbRepaired {true};                 ///< Database was repaired.

    /**
     * @brief Reset the log test state to default values.
     */
    void reset()
    {
        errorLogsCount = 0;
        foundMapperError = false;
        foundVersionConflictError = false;
        foundParseError = false;
        foundUnknownReason = false;
        foundUnknownType = false;
        dbRepaired = true;
    }
};

// Global instance, we need this to be able to check the log messages received in the log function and avoid local
// instance due threads are asynchronous.
static LogTestState g_logTestState;

// Helper function to create the standard log function. As global is copied by value, it is safe to use it in multiple
// tests.
static auto createStandardLogFunction()
{
    return [](const int logLevel,
              const std::string& tag,
              const std::string& file,
              const int line,
              const std::string& func,
              const std::string& logMessage,
              va_list args)
    {
        std::ignore = tag;
        std::ignore = file;
        std::ignore = line;
        std::ignore = func;

        char buffer[LOG_BUFFER_SIZE];
        va_list args_copy;
        va_copy(args_copy, args);
        vsnprintf(buffer, sizeof(buffer), logMessage.c_str(), args_copy);
        va_end(args_copy);

        std::string formatted(buffer);

        if (logLevel == 2) // Warning messages
        {
            // Check for error formats: "Indexer request failed"
            if (formatted.find("Indexer request failed") != std::string::npos)
            {
                g_logTestState.errorLogsCount++;

                // Check for specific error types
                if (formatted.find("mapper_parsing_exception") != std::string::npos)
                {
                    g_logTestState.foundMapperError = true;
                }
                if (formatted.find("version_conflict_engine_exception") != std::string::npos)
                {
                    g_logTestState.foundVersionConflictError = true;
                }
                if (formatted.find("Unknown reason") != std::string::npos)
                {
                    g_logTestState.foundUnknownReason = true;
                }
                if (formatted.find("Unknown type") != std::string::npos)
                {
                    g_logTestState.foundUnknownType = true;
                }
            }

            // Check for parse errors
            if (formatted.find("Failed to parse") != std::string::npos || formatted.find("parse") != std::string::npos)
            {
                g_logTestState.foundParseError = true;
            }

            // Check for database repaired message
            if (logMessage.compare("Database '%s' was repaired because it was corrupt.") == 0)
            {
                g_logTestState.dbRepaired = true;
            }
        }

        // Special case of response with no error formatting
        if (logLevel == 5)
        {
            if (formatted.find("invalid json") != std::string::npos)
            {
                g_logTestState.foundParseError = true;
            }
        }
    };
}

void IndexerConnectorTest::SetUp()
{
    // Create dummy template file.
    std::ofstream outputFile(TEMPLATE_FILE_PATH);
    outputFile << TEMPLATE_DATA.dump();
    outputFile.close();

    // Initialize fake indexers.
    m_indexerServers.push_back(std::make_unique<FakeIndexer>(INDEXER_HOSTNAME, A_PORT, "green", INDEXER_NAME));
    m_indexerServers.push_back(std::make_unique<FakeIndexer>(INDEXER_HOSTNAME, B_PORT, "red", INDEXER_NAME));
    m_indexerServers.push_back(std::make_unique<FakeIndexer>(INDEXER_HOSTNAME, C_PORT, "red", INDEXER_NAME));

    // Start fake indexers.
    for (auto& server : m_indexerServers)
    {
        server->start();
    }
}

void IndexerConnectorTest::TearDown()
{
    const auto QUEUE_FOLDER {std::filesystem::current_path() / "queue"};

    // Remove generated data.
    std::filesystem::remove(TEMPLATE_FILE_PATH);
    std::filesystem::remove_all(QUEUE_FOLDER);

    // Delete fake indexers.
    for (auto& server : m_indexerServers)
    {
        server.reset();
    }
    m_indexerServers.clear();
}

void IndexerConnectorTest::waitUntil(const std::function<bool()>& stopCondition,
                                     const unsigned int& maxSleepTimeMs) const
{
    const unsigned int sleepTimeMilli {100};
    unsigned int totalSleepTime {0};

    do
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(sleepTimeMilli));
        totalSleepTime += sleepTimeMilli;

        if (totalSleepTime > maxSleepTimeMs)
        {
            throw std::runtime_error {"Waiting took too long"};
        }

    } while (!stopCondition());
}

/**
 * @brief Test the connection to an available server. The initialization is checked by reading the index and template
 * data.
 *
 */
TEST_F(IndexerConnectorTest, Connection)
{
    // Callback used to check if the indexer connector is correctly initialized.
    // This callback should be called twice: The first time to initialize the template and the second one to initialize
    // the index.
    nlohmann::json indexData;
    nlohmann::json templateData;
    unsigned int callbackCalled {0};
    const auto checkInitDataCallback {[&callbackCalled, &indexData, &templateData](const std::string& data)
                                      {
                                          auto responseData = nlohmann::json::parse(data);
                                          ++callbackCalled;

                                          if (1 == callbackCalled)
                                          {
                                              templateData = std::move(responseData);
                                              return;
                                          }

                                          indexData = std::move(responseData);
                                      }};
    m_indexerServers[A_IDX]->setInitTemplateCallback(checkInitDataCallback);
    m_indexerServers[A_IDX]->setInitIndexCallback(checkInitDataCallback);

    // Create connector and wait until the connection is established.
    nlohmann::json indexerConfig;
    indexerConfig["name"] = INDEXER_NAME;
    indexerConfig["hosts"] = nlohmann::json::array({A_ADDRESS});
    auto indexerConnector {IndexerConnector(indexerConfig, TEMPLATE_FILE_PATH, "", true, nullptr, INDEXER_TIMEOUT)};
    ASSERT_NO_THROW(waitUntil([this]() { return m_indexerServers[A_IDX]->initialized(); }, MAX_INDEXER_INIT_TIME_MS));

    // Check init data.
    constexpr auto EXPECTED_CALLBACK_CALLED_TIMES {2};
    ASSERT_EQ(callbackCalled, EXPECTED_CALLBACK_CALLED_TIMES);
    ASSERT_EQ(templateData, TEMPLATE_DATA);
    ASSERT_EQ(indexData, TEMPLATE_DATA.at("template"));
}

/**
 * @brief Test the connection to an available server with user and password data.
 *
 * @note The credentials are dummy ones and there are no functionality checks here. The target of this test is to
 * increase the test coverage.
 *
 */
TEST_F(IndexerConnectorTest, ConnectionWithUserAndPassword)
{
    nlohmann::json indexerConfig;
    indexerConfig["name"] = INDEXER_NAME;
    indexerConfig["hosts"] = nlohmann::json::array({A_ADDRESS});
    indexerConfig["username"] = "user";
    indexerConfig["password"] = "password";

    // Create connector and wait until the connection is established.
    auto indexerConnector {IndexerConnector(indexerConfig, TEMPLATE_FILE_PATH, "", true, nullptr, INDEXER_TIMEOUT)};
    EXPECT_NO_THROW(waitUntil([this]() { return m_indexerServers[A_IDX]->initialized(); }, MAX_INDEXER_INIT_TIME_MS));
}

/**
 * @brief Test the connection to an available server with SSL credentials.
 *
 * @note The SSL data is a dummy one and there are no functionality checks here. The target of this test is to increase
 * the test coverage.
 *
 */
TEST_F(IndexerConnectorTest, ConnectionWithSslCredentials)
{
    nlohmann::json indexerConfig;
    indexerConfig["name"] = INDEXER_NAME;
    indexerConfig["hosts"] = nlohmann::json::array({A_ADDRESS});
    indexerConfig["ssl"]["certificate_authorities"] = nlohmann::json::array({"/etc/filebeat/certs/root-ca.pem"});
    indexerConfig["ssl"]["certificate"] = "/etc/filebeat/certs/filebeat.pem";
    indexerConfig["ssl"]["key"] = "/etc/filebeat/certs/filebeat-key.pem";

    // Create connector and wait until the connection is established.
    auto indexerConnector {IndexerConnector(indexerConfig, TEMPLATE_FILE_PATH, "", true, nullptr, INDEXER_TIMEOUT)};
    EXPECT_NO_THROW(waitUntil([this]() { return m_indexerServers[A_IDX]->initialized(); }, MAX_INDEXER_INIT_TIME_MS));
}

/**
 * @brief Test the connection to an unavailable server.
 *
 */
TEST_F(IndexerConnectorTest, ConnectionUnavailableServer)
{
    nlohmann::json indexerConfig;
    indexerConfig["name"] = INDEXER_NAME;
    indexerConfig["hosts"] = nlohmann::json::array({B_ADDRESS});

    // Create connector and wait until the max time is reached.
    auto indexerConnector {IndexerConnector(indexerConfig, TEMPLATE_FILE_PATH, "", true, nullptr, INDEXER_TIMEOUT)};
    EXPECT_THROW(waitUntil([this]() { return m_indexerServers[B_IDX]->initialized(); }, MAX_INDEXER_INIT_TIME_MS),
                 std::runtime_error);
}

/**
 * @brief Test the connection to a list of servers. The connection is expected to be made to the only available server.
 *
 */
TEST_F(IndexerConnectorTest, ConnectionMultipleServers)
{
    // Set the servers health.
    m_indexerServers[A_IDX]->setHealth("red");
    m_indexerServers[B_IDX]->setHealth("red");
    m_indexerServers[C_IDX]->setHealth("green");

    // Create connector and wait until the connection is made with the available server.
    nlohmann::json indexerConfig;
    indexerConfig["name"] = INDEXER_NAME;
    indexerConfig["hosts"] = nlohmann::json::array({A_ADDRESS, B_ADDRESS, C_ADDRESS});
    auto indexerConnector {IndexerConnector(indexerConfig, TEMPLATE_FILE_PATH, "", true, nullptr, INDEXER_TIMEOUT)};
    ASSERT_NO_THROW(waitUntil([this]() { return m_indexerServers[C_IDX]->initialized(); }, MAX_INDEXER_INIT_TIME_MS));
}

/**
 * @brief Test the connection to an inexistant server.
 *
 */
TEST_F(IndexerConnectorTest, ConnectionInvalidServer)
{
    // Trigger connection and expect that it is not made.
    constexpr auto INEXISTANT_SERVER {"localhost:6789"};
    nlohmann::json indexerConfig;
    indexerConfig["name"] = INDEXER_NAME;
    indexerConfig["hosts"] = nlohmann::json::array({INEXISTANT_SERVER});
    auto indexerConnector {IndexerConnector(indexerConfig, TEMPLATE_FILE_PATH, "", true, nullptr, INDEXER_TIMEOUT)};
    ASSERT_THROW(waitUntil([this]() { return m_indexerServers[A_IDX]->initialized(); }, MAX_INDEXER_INIT_TIME_MS),
                 std::runtime_error);
}

/**
 * @brief Test the connection to a server that responds the template initialization with an error.
 *
 */
TEST_F(IndexerConnectorTest, ConnectionInitTemplateErrorFromServer)
{
    std::atomic<bool> callbackCalled {false};
    std::atomic<bool> exceptionThrown {false};

    const auto forceErrorCallback = [&callbackCalled, &exceptionThrown](const std::string& data)
    {
        std::ignore = data;
        callbackCalled = true;
        exceptionThrown = true;
        throw std::runtime_error {"Forced server error"};
    };
    m_indexerServers[A_IDX]->setInitTemplateCallback(forceErrorCallback);

    nlohmann::json indexerConfig;
    indexerConfig["name"] = INDEXER_NAME;
    indexerConfig["hosts"] = nlohmann::json::array({A_ADDRESS});

    // Constructor doesn't throw - initialization is async
    ASSERT_NO_THROW(auto indexerConnector =
                        IndexerConnector(indexerConfig, TEMPLATE_FILE_PATH, "", true, nullptr, INDEXER_TIMEOUT));

    // Wait for the callback to be called
    ASSERT_NO_THROW(waitUntil([&callbackCalled]() { return callbackCalled.load(); }, MAX_INDEXER_INIT_TIME_MS));

    // Verify the callback was called and threw an exception
    EXPECT_TRUE(callbackCalled) << "Init template callback should have been called";
    EXPECT_TRUE(exceptionThrown) << "Exception should have been thrown in callback";

    // Give time for async operations to complete
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
}

/**
 * @brief Test the connection to a server that responds the index initialization with an error.
 *
 */
TEST_F(IndexerConnectorTest, ConnectionInitIndexErrorFromServer)
{
    // Callback function that checks if the callback was executed or not.
    std::atomic<bool> callbackCalled {false};
    const auto forceErrorCallback {[&callbackCalled](const std::string& data)
                                   {
                                       std::ignore = data;
                                       callbackCalled = true;
                                       throw std::runtime_error {"Forced server error"};
                                   }};
    m_indexerServers[A_IDX]->setInitIndexCallback(forceErrorCallback);

    // Create connector and wait until the connection is established.
    nlohmann::json indexerConfig;
    indexerConfig["name"] = INDEXER_NAME;
    indexerConfig["hosts"] = nlohmann::json::array({A_ADDRESS});
    auto indexerConnector {IndexerConnector(indexerConfig, TEMPLATE_FILE_PATH, "", true, nullptr, INDEXER_TIMEOUT)};
    ASSERT_THROW(waitUntil([this]() { return m_indexerServers[A_IDX]->initialized(); }, MAX_INDEXER_INIT_TIME_MS),
                 std::runtime_error);
}

/**
 * @brief Test the connection and posterior data publication into a server. The published data is checked against the
 * expected one.
 *
 */
TEST_F(IndexerConnectorTest, Publish)
{
    nlohmann::json expectedMetadata;
    expectedMetadata["index"]["_index"] = INDEXER_NAME;
    expectedMetadata["index"]["_id"] = INDEX_ID_A;

    // Callback that checks the expected data to be published.
    // The format of the data published is divided in two lines:
    // First line: JSON data with the metadata (indexer name, index ID)
    // Second line: Index data.
    constexpr auto INDEX_DATA {"content"};
    std::atomic<bool> callbackCalled {false};
    const auto checkPublishedData {
        [&expectedMetadata, &callbackCalled, &INDEX_DATA](const std::string& data) -> std::pair<int, std::string>
        {
            const auto splitData {Utils::split(data, '\n')};
            EXPECT_EQ(nlohmann::json::parse(splitData.front()), expectedMetadata);
            EXPECT_EQ(nlohmann::json::parse(splitData.back()), INDEX_DATA);
            callbackCalled = true;
            return {200, R"({"errors":false})"};
        }};
    m_indexerServers[A_IDX]->setPublishCallback(checkPublishedData);

    // Create connector and wait until the connection is established.
    nlohmann::json indexerConfig;
    indexerConfig["name"] = INDEXER_NAME;
    indexerConfig["hosts"] = nlohmann::json::array({A_ADDRESS});
    auto indexerConnector {IndexerConnector(indexerConfig, TEMPLATE_FILE_PATH, "", true, nullptr, INDEXER_TIMEOUT)};
    ASSERT_NO_THROW(waitUntil([this]() { return m_indexerServers[A_IDX]->initialized(); }, MAX_INDEXER_INIT_TIME_MS));

    // Publish content and wait until the publication finishes.
    nlohmann::json publishData;
    publishData["id"] = INDEX_ID_A;
    publishData["operation"] = "INSERT";
    publishData["data"] = INDEX_DATA;
    ASSERT_NO_THROW(indexerConnector.publish(publishData.dump()));
    ASSERT_NO_THROW(waitUntil([&callbackCalled]() { return callbackCalled.load(); }, MAX_INDEXER_PUBLISH_TIME_MS));
}

/**
 * @brief Test the indexer connector when the simplified object is created. We expect that no data is indexed but the
 * local DB is synced.
 *
 */
TEST_F(IndexerConnectorTest, NoPublish)
{
    nlohmann::json expectedMetadata;
    std::string agentId {"001"};
    expectedMetadata["index"]["_index"] = INDEXER_NAME;
    expectedMetadata["index"]["_id"] = agentId + "_" + INDEX_ID_A;

    // Callback that checks the expected data to be published.
    constexpr auto INDEX_DATA {"content"};
    std::atomic<bool> callbackCalled {false};
    const auto checkPublishedData {
        [&expectedMetadata, &callbackCalled, &INDEX_DATA](const std::string& data) -> std::pair<int, std::string>
        {
            const auto splitData {Utils::split(data, '\n')};
            EXPECT_EQ(nlohmann::json::parse(splitData.front()), expectedMetadata);
            EXPECT_EQ(nlohmann::json::parse(splitData.back()), INDEX_DATA);
            callbackCalled = true;
            return {200, R"({"errors":false})"};
        }};
    m_indexerServers[A_IDX]->setPublishCallback(checkPublishedData);

    // Create connector and make sure the connection isn't established.
    nlohmann::json indexerConfig;
    indexerConfig["name"] = INDEXER_NAME;
    indexerConfig["hosts"] = nlohmann::json::array({A_ADDRESS});
    auto indexerConnector {
        std::make_shared<IndexerConnector>(indexerConfig,
                                           true,
                                           static_cast<std::function<void(const int,
                                                                          const std::string&,
                                                                          const std::string&,
                                                                          const int,
                                                                          const std::string&,
                                                                          const std::string&,
                                                                          va_list)>>(nullptr))}; // Simplified object.
    EXPECT_ANY_THROW(waitUntil([this]() { return m_indexerServers[A_IDX]->initialized(); }, MAX_INDEXER_INIT_TIME_MS));

    // Publish content. The local DB should be updated but no data should be indexed.
    nlohmann::json publishData;
    publishData["id"] = agentId + "_" + INDEX_ID_A;
    publishData["operation"] = "INSERT";
    publishData["data"] = INDEX_DATA;
    ASSERT_NO_THROW(indexerConnector->publish(publishData.dump()));
    EXPECT_ANY_THROW(waitUntil([&callbackCalled]() { return callbackCalled.load(); }, MAX_INDEXER_PUBLISH_TIME_MS));
    ASSERT_FALSE(callbackCalled);

    // Now we create the normal object and check the data is synced without pushing it again

    indexerConnector.reset();
    indexerConnector =
        std::make_shared<IndexerConnector>(indexerConfig, TEMPLATE_FILE_PATH, "", true, nullptr, INDEXER_TIMEOUT);
    ASSERT_NO_THROW(waitUntil([this]() { return m_indexerServers[A_IDX]->initialized(); }, MAX_INDEXER_INIT_TIME_MS));

    auto searchCallbackCalled {false};
    m_indexerServers[A_IDX]->setSearchCallback(
        [&](const std::string& data) -> std::string
        {
            EXPECT_NE(data.find(agentId), std::string::npos);
            searchCallbackCalled = true;
            return R"({"_scroll_id":"abcdef","hits": {"total" : {"value": 0}, "hits": []}})";
        });

    auto deleteScrollCallbackCalled {false};
    m_indexerServers[A_IDX]->setDeleteScrollCallback(
        [&](const std::string& data) -> std::string
        {
            EXPECT_EQ(data.compare("abcdef"), 0);
            deleteScrollCallbackCalled = true;
            return R"({"_scroll_id":"abcdef","hits": {"total" : {"value": 0}, "hits": []}})";
        });
    indexerConnector->sync(agentId);
    ASSERT_NO_THROW(waitUntil([&callbackCalled]() { return callbackCalled.load(); }, MAX_INDEXER_PUBLISH_TIME_MS));
    ASSERT_TRUE(callbackCalled);
    ASSERT_TRUE(searchCallbackCalled);
    ASSERT_TRUE(deleteScrollCallbackCalled);
}

/**
 * @brief Test the connection and posterior data publication into a server. The published data is checked against the
 * expected one. The publication contains a DELETED operation.
 *
 */
TEST_F(IndexerConnectorTest, PublishDeleted)
{
    nlohmann::json expectedMetadata;

    // Callback that checks the expected data to be published.
    std::atomic<bool> callbackCalled {false};
    const auto checkPublishedData {
        [&expectedMetadata, &callbackCalled](const std::string& data) -> std::pair<int, std::string>
        {
            const auto splitData {Utils::split(data, '\n')};
            EXPECT_EQ(nlohmann::json::parse(splitData.front()), expectedMetadata);
            callbackCalled = true;
            return {200, R"({"errors":false})"};
        }};
    m_indexerServers[A_IDX]->setPublishCallback(checkPublishedData);

    // Create connector and wait until the connection is established.
    nlohmann::json indexerConfig;
    indexerConfig["name"] = INDEXER_NAME;
    indexerConfig["hosts"] = nlohmann::json::array({A_ADDRESS});
    auto indexerConnector {IndexerConnector(indexerConfig, TEMPLATE_FILE_PATH, "", true, nullptr, INDEXER_TIMEOUT)};
    ASSERT_NO_THROW(waitUntil([this]() { return m_indexerServers[A_IDX]->initialized(); }, MAX_INDEXER_INIT_TIME_MS));

    // Publish content and wait until the publication finishes.
    nlohmann::json publishData;
    expectedMetadata["index"]["_index"] = INDEXER_NAME;
    expectedMetadata["index"]["_id"] = INDEX_ID_A;
    publishData["id"] = INDEX_ID_A;
    publishData["operation"] = "INSERTED";
    publishData["data"] = "content";
    ASSERT_NO_THROW(indexerConnector.publish(publishData.dump()));
    ASSERT_NO_THROW(waitUntil([&callbackCalled]() { return callbackCalled.load(); }, MAX_INDEXER_PUBLISH_TIME_MS));

    callbackCalled = false;
    publishData.erase("data");
    expectedMetadata.clear();
    expectedMetadata["delete"]["_index"] = INDEXER_NAME;
    expectedMetadata["delete"]["_id"] = INDEX_ID_A;
    publishData["id"] = INDEX_ID_A;
    publishData["operation"] = "DELETED";
    ASSERT_NO_THROW(indexerConnector.publish(publishData.dump()));
    ASSERT_NO_THROW(waitUntil([&callbackCalled]() { return callbackCalled.load(); }, MAX_INDEXER_PUBLISH_TIME_MS));
}

/**
 * @brief Test that handleIndexerInternalErrors correctly processes a response with errors and logs them.
 */
TEST_F(IndexerConnectorTest, HandleIndexerInternalErrors_WithErrors)
{
    Log::GLOBAL_LOG_FUNCTION = nullptr;
    g_logTestState.reset();

    auto customLogFunction = createStandardLogFunction();

    nlohmann::json errorResponse;
    errorResponse["errors"] = true;
    errorResponse["items"] = nlohmann::json::array();

    nlohmann::json item1;
    item1["index"]["error"]["type"] = "mapper_parsing_exception";
    item1["index"]["error"]["reason"] = "failed to parse field [timestamp]";
    errorResponse["items"].push_back(item1);

    std::atomic<bool> callbackCalled {false};
    const auto returnErrorResponse = [&errorResponse,
                                      &callbackCalled](const std::string& data) -> std::pair<int, std::string>
    {
        callbackCalled = true;
        return {400, errorResponse.dump()};
    };
    m_indexerServers[A_IDX]->setPublishCallback(returnErrorResponse);

    nlohmann::json indexerConfig;
    indexerConfig["name"] = INDEXER_NAME;
    indexerConfig["hosts"] = nlohmann::json::array({A_ADDRESS});

    auto indexerConnector = std::make_unique<IndexerConnector>(
        indexerConfig, TEMPLATE_FILE_PATH, "", true, customLogFunction, INDEXER_TIMEOUT);

    ASSERT_NO_THROW(waitUntil([this]() { return m_indexerServers[A_IDX]->initialized(); }, MAX_INDEXER_INIT_TIME_MS));

    nlohmann::json publishData;
    publishData["id"] = INDEX_ID_A;
    publishData["operation"] = "INSERT";
    publishData["data"] = "content";

    ASSERT_NO_THROW(indexerConnector->publish(publishData.dump()));
    ASSERT_NO_THROW(waitUntil([&callbackCalled]() { return callbackCalled.load(); }, MAX_INDEXER_PUBLISH_TIME_MS));

    std::this_thread::sleep_for(std::chrono::milliseconds(1000));

    EXPECT_TRUE(callbackCalled) << "Publish callback was not called";
    EXPECT_EQ(g_logTestState.errorLogsCount.load(), 1) << "Expected 1 error log";
    EXPECT_TRUE(g_logTestState.foundMapperError.load()) << "mapper_parsing_exception error log not found";

    indexerConnector.reset();
    Log::GLOBAL_LOG_FUNCTION = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
}

/**
 * @brief Test that handleIndexerInternalErrors correctly processes multiple errors in a batch.
 */
TEST_F(IndexerConnectorTest, HandleIndexerInternalErrors_MultipleErrors)
{
    Log::GLOBAL_LOG_FUNCTION = nullptr;
    g_logTestState.reset();

    auto customLogFunction = createStandardLogFunction();

    nlohmann::json errorResponse;
    errorResponse["errors"] = true;
    errorResponse["items"] = nlohmann::json::array();

    nlohmann::json item1;
    item1["index"]["error"]["type"] = "mapper_parsing_exception";
    item1["index"]["error"]["reason"] = "failed to parse field [timestamp]";
    errorResponse["items"].push_back(item1);

    nlohmann::json item2;
    item2["index"]["_id"] = "B";
    item2["index"]["status"] = 200;
    errorResponse["items"].push_back(item2);

    nlohmann::json item3;
    item3["index"]["error"]["type"] = "version_conflict_engine_exception";
    item3["index"]["error"]["reason"] = "version conflict, document already exists";
    errorResponse["items"].push_back(item3);

    std::atomic<bool> callbackCalled {false};
    const auto returnErrorResponse = [&errorResponse,
                                      &callbackCalled](const std::string& data) -> std::pair<int, std::string>
    {
        callbackCalled = true;
        return {400, errorResponse.dump()};
    };
    m_indexerServers[A_IDX]->setPublishCallback(returnErrorResponse);

    nlohmann::json indexerConfig;
    indexerConfig["name"] = INDEXER_NAME;
    indexerConfig["hosts"] = nlohmann::json::array({A_ADDRESS});

    auto indexerConnector = std::make_unique<IndexerConnector>(
        indexerConfig, TEMPLATE_FILE_PATH, "", true, customLogFunction, INDEXER_TIMEOUT);

    ASSERT_NO_THROW(waitUntil([this]() { return m_indexerServers[A_IDX]->initialized(); }, MAX_INDEXER_INIT_TIME_MS));

    nlohmann::json publishData1;
    publishData1["id"] = INDEX_ID_A;
    publishData1["operation"] = "INSERT";
    publishData1["data"] = "content1";
    ASSERT_NO_THROW(indexerConnector->publish(publishData1.dump()));

    nlohmann::json publishData2;
    publishData2["id"] = INDEX_ID_B;
    publishData2["operation"] = "INSERT";
    publishData2["data"] = "content2";
    ASSERT_NO_THROW(indexerConnector->publish(publishData2.dump()));

    nlohmann::json publishData3;
    publishData3["id"] = "C";
    publishData3["operation"] = "INSERT";
    publishData3["data"] = "content3";
    ASSERT_NO_THROW(indexerConnector->publish(publishData3.dump()));

    ASSERT_NO_THROW(waitUntil([&callbackCalled]() { return callbackCalled.load(); }, MAX_INDEXER_PUBLISH_TIME_MS));

    std::this_thread::sleep_for(std::chrono::milliseconds(1000));

    EXPECT_TRUE(callbackCalled) << "Publish callback was not called";
    EXPECT_EQ(g_logTestState.errorLogsCount.load(), 2) << "Expected 2 error logs (items 1 and 3 have errors)";
    EXPECT_TRUE(g_logTestState.foundMapperError.load()) << "mapper_parsing_exception error log not found";
    EXPECT_TRUE(g_logTestState.foundVersionConflictError.load())
        << "version_conflict_engine_exception error log not found";

    indexerConnector.reset();
    Log::GLOBAL_LOG_FUNCTION = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
}

/**
 * @brief Test that handleIndexerInternalErrors handles response with no errors field gracefully.
 */
TEST_F(IndexerConnectorTest, HandleIndexerInternalErrors_NoErrorsField)
{
    Log::GLOBAL_LOG_FUNCTION = nullptr;
    g_logTestState.reset();

    auto customLogFunction = createStandardLogFunction();

    nlohmann::json successResponse;
    successResponse["items"] = nlohmann::json::array();
    nlohmann::json item;
    item["index"]["_id"] = "A";
    item["index"]["status"] = 200;
    successResponse["items"].push_back(item);

    std::atomic<bool> callbackCalled {false};
    const auto returnSuccessResponse = [&successResponse,
                                        &callbackCalled](const std::string& data) -> std::pair<int, std::string>
    {
        callbackCalled = true;
        return {200, successResponse.dump()};
    };
    m_indexerServers[A_IDX]->setPublishCallback(returnSuccessResponse);

    nlohmann::json indexerConfig;
    indexerConfig["name"] = INDEXER_NAME;
    indexerConfig["hosts"] = nlohmann::json::array({A_ADDRESS});

    auto indexerConnector = std::make_unique<IndexerConnector>(
        indexerConfig, TEMPLATE_FILE_PATH, "", true, customLogFunction, INDEXER_TIMEOUT);

    ASSERT_NO_THROW(waitUntil([this]() { return m_indexerServers[A_IDX]->initialized(); }, MAX_INDEXER_INIT_TIME_MS));

    nlohmann::json publishData;
    publishData["id"] = INDEX_ID_A;
    publishData["operation"] = "INSERT";
    publishData["data"] = "content";
    ASSERT_NO_THROW(indexerConnector->publish(publishData.dump()));

    ASSERT_NO_THROW(waitUntil([&callbackCalled]() { return callbackCalled.load(); }, MAX_INDEXER_PUBLISH_TIME_MS));

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    EXPECT_TRUE(callbackCalled) << "Publish callback was not called";
    EXPECT_EQ(g_logTestState.errorLogsCount.load(), 0) << "No error logs should be generated";

    indexerConnector.reset();
    Log::GLOBAL_LOG_FUNCTION = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
}

/**
 * @brief Test that handleIndexerInternalErrors handles errors=false correctly.
 */
TEST_F(IndexerConnectorTest, HandleIndexerInternalErrors_ErrorsFalse)
{
    Log::GLOBAL_LOG_FUNCTION = nullptr;
    g_logTestState.reset();

    auto customLogFunction = createStandardLogFunction();

    nlohmann::json successResponse;
    successResponse["errors"] = false;
    successResponse["items"] = nlohmann::json::array();
    nlohmann::json item;
    item["index"]["_id"] = "A";
    item["index"]["status"] = 200;
    successResponse["items"].push_back(item);

    std::atomic<bool> callbackCalled {false};
    const auto returnSuccessResponse = [&successResponse,
                                        &callbackCalled](const std::string& data) -> std::pair<int, std::string>
    {
        callbackCalled = true;
        return {200, successResponse.dump()};
    };
    m_indexerServers[A_IDX]->setPublishCallback(returnSuccessResponse);

    nlohmann::json indexerConfig;
    indexerConfig["name"] = INDEXER_NAME;
    indexerConfig["hosts"] = nlohmann::json::array({A_ADDRESS});

    auto indexerConnector = std::make_unique<IndexerConnector>(
        indexerConfig, TEMPLATE_FILE_PATH, "", true, customLogFunction, INDEXER_TIMEOUT);

    ASSERT_NO_THROW(waitUntil([this]() { return m_indexerServers[A_IDX]->initialized(); }, MAX_INDEXER_INIT_TIME_MS));

    nlohmann::json publishData;
    publishData["id"] = INDEX_ID_A;
    publishData["operation"] = "INSERT";
    publishData["data"] = "content";
    ASSERT_NO_THROW(indexerConnector->publish(publishData.dump()));

    ASSERT_NO_THROW(waitUntil([&callbackCalled]() { return callbackCalled.load(); }, MAX_INDEXER_PUBLISH_TIME_MS));

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    EXPECT_TRUE(callbackCalled) << "Publish callback was not called";
    EXPECT_EQ(g_logTestState.errorLogsCount.load(), 0) << "No error logs should be generated when errors=false";

    indexerConnector.reset();
    Log::GLOBAL_LOG_FUNCTION = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
}

/**
 * @brief Test that handleIndexerInternalErrors handles missing error reason field.
 */
TEST_F(IndexerConnectorTest, HandleIndexerInternalErrors_MissingErrorReason)
{
    Log::GLOBAL_LOG_FUNCTION = nullptr;
    g_logTestState.reset();

    auto customLogFunction = createStandardLogFunction();

    nlohmann::json errorResponse;
    errorResponse["errors"] = true;
    errorResponse["items"] = nlohmann::json::array();

    nlohmann::json item;
    item["index"]["error"]["type"] = "some_error_type";
    // Missing "reason" field - should use default "Unknown reason"
    errorResponse["items"].push_back(item);

    std::atomic<bool> callbackCalled {false};
    const auto returnErrorResponse = [&errorResponse,
                                      &callbackCalled](const std::string& data) -> std::pair<int, std::string>
    {
        callbackCalled = true;
        return {400, errorResponse.dump()};
    };
    m_indexerServers[A_IDX]->setPublishCallback(returnErrorResponse);

    nlohmann::json indexerConfig;
    indexerConfig["name"] = INDEXER_NAME;
    indexerConfig["hosts"] = nlohmann::json::array({A_ADDRESS});

    auto indexerConnector = std::make_unique<IndexerConnector>(
        indexerConfig, TEMPLATE_FILE_PATH, "", true, customLogFunction, INDEXER_TIMEOUT);

    ASSERT_NO_THROW(waitUntil([this]() { return m_indexerServers[A_IDX]->initialized(); }, MAX_INDEXER_INIT_TIME_MS));

    nlohmann::json publishData;
    publishData["id"] = INDEX_ID_A;
    publishData["operation"] = "INSERT";
    publishData["data"] = "content";
    ASSERT_NO_THROW(indexerConnector->publish(publishData.dump()));

    ASSERT_NO_THROW(waitUntil([&callbackCalled]() { return callbackCalled.load(); }, MAX_INDEXER_PUBLISH_TIME_MS));

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    EXPECT_TRUE(callbackCalled) << "Publish callback was not called";
    EXPECT_EQ(g_logTestState.errorLogsCount.load(), 1) << "Expected 1 error log";
    EXPECT_TRUE(g_logTestState.foundUnknownReason.load())
        << "'Unknown reason' should be used when reason field is missing";

    indexerConnector.reset();
    Log::GLOBAL_LOG_FUNCTION = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
}

/**
 * @brief Test that handleIndexerInternalErrors handles missing error type field.
 */
TEST_F(IndexerConnectorTest, HandleIndexerInternalErrors_MissingErrorType)
{
    Log::GLOBAL_LOG_FUNCTION = nullptr;
    g_logTestState.reset();

    auto customLogFunction = createStandardLogFunction();

    nlohmann::json errorResponse;
    errorResponse["errors"] = true;
    errorResponse["items"] = nlohmann::json::array();

    nlohmann::json item;
    item["index"]["error"]["reason"] = "some error occurred";
    // Missing "type" field - should use default "Unknown type"
    errorResponse["items"].push_back(item);

    std::atomic<bool> callbackCalled {false};
    const auto returnErrorResponse = [&errorResponse,
                                      &callbackCalled](const std::string& data) -> std::pair<int, std::string>
    {
        callbackCalled = true;
        return {400, errorResponse.dump()};
    };
    m_indexerServers[A_IDX]->setPublishCallback(returnErrorResponse);

    nlohmann::json indexerConfig;
    indexerConfig["name"] = INDEXER_NAME;
    indexerConfig["hosts"] = nlohmann::json::array({A_ADDRESS});

    auto indexerConnector = std::make_unique<IndexerConnector>(
        indexerConfig, TEMPLATE_FILE_PATH, "", true, customLogFunction, INDEXER_TIMEOUT);

    ASSERT_NO_THROW(waitUntil([this]() { return m_indexerServers[A_IDX]->initialized(); }, MAX_INDEXER_INIT_TIME_MS));

    nlohmann::json publishData;
    publishData["id"] = INDEX_ID_A;
    publishData["operation"] = "INSERT";
    publishData["data"] = "content";
    ASSERT_NO_THROW(indexerConnector->publish(publishData.dump()));

    ASSERT_NO_THROW(waitUntil([&callbackCalled]() { return callbackCalled.load(); }, MAX_INDEXER_PUBLISH_TIME_MS));

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    EXPECT_TRUE(callbackCalled) << "Publish callback was not called";
    EXPECT_EQ(g_logTestState.errorLogsCount.load(), 1) << "Expected 1 error log";
    EXPECT_TRUE(g_logTestState.foundUnknownType.load()) << "'Unknown type' should be used when type field is missing";

    indexerConnector.reset();
    Log::GLOBAL_LOG_FUNCTION = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
}

/**
 * @brief Test that handleIndexerInternalErrors handles invalid JSON gracefully.
 */
TEST_F(IndexerConnectorTest, HandleIndexerInternalErrors_InvalidJSON)
{
    Log::GLOBAL_LOG_FUNCTION = nullptr;
    g_logTestState.reset();

    auto customLogFunction = createStandardLogFunction();

    std::atomic<bool> callbackCalled {false};
    const auto returnInvalidJSON = [&callbackCalled](const std::string& data) -> std::pair<int, std::string>
    {
        callbackCalled = true;
        return {400, "{ \"unclosed\": "};
    };
    m_indexerServers[A_IDX]->setPublishCallback(returnInvalidJSON);

    nlohmann::json indexerConfig;
    indexerConfig["name"] = INDEXER_NAME;
    indexerConfig["hosts"] = nlohmann::json::array({A_ADDRESS});

    auto indexerConnector = std::make_unique<IndexerConnector>(
        indexerConfig, TEMPLATE_FILE_PATH, "", true, customLogFunction, INDEXER_TIMEOUT);

    ASSERT_NO_THROW(waitUntil([this]() { return m_indexerServers[A_IDX]->initialized(); }, MAX_INDEXER_INIT_TIME_MS));

    nlohmann::json publishData;
    publishData["id"] = INDEX_ID_A;
    publishData["operation"] = "INSERT";
    publishData["data"] = "content";
    ASSERT_NO_THROW(indexerConnector->publish(publishData.dump()));

    ASSERT_NO_THROW(waitUntil([&callbackCalled]() { return callbackCalled.load(); }, MAX_INDEXER_PUBLISH_TIME_MS));

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    EXPECT_TRUE(callbackCalled) << "Publish callback was not called";
    EXPECT_TRUE(g_logTestState.foundParseError.load()) << "Parse error warning should be logged for invalid JSON";

    indexerConnector.reset();
    Log::GLOBAL_LOG_FUNCTION = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
}

/**
 * @brief Test that handleIndexerInternalErrors handles shard limit exceeded error.
 */
TEST_F(IndexerConnectorTest, HandleIndexerInternalErrors_ShardLimitExceeded)
{
    Log::GLOBAL_LOG_FUNCTION = nullptr;
    g_logTestState.reset();

    auto customLogFunction = createStandardLogFunction();

    // Elasticsearch shard limit error response (request-level, not bulk)
    nlohmann::json errorResponse;
    errorResponse["error"]["type"] = "validation_exception";
    errorResponse["error"]["reason"] = "Validation Failed: 1: this action would add [1] total shards, but this cluster "
                                       "currently has [1000]/[1000] maximum shards open;";
    errorResponse["status"] = 400;

    std::atomic<bool> callbackCalled {false};
    const auto returnErrorResponse = [&errorResponse,
                                      &callbackCalled](const std::string& data) -> std::pair<int, std::string>
    {
        callbackCalled = true;
        return {400, errorResponse.dump()};
    };
    m_indexerServers[A_IDX]->setPublishCallback(returnErrorResponse);

    nlohmann::json indexerConfig;
    indexerConfig["name"] = INDEXER_NAME;
    indexerConfig["hosts"] = nlohmann::json::array({A_ADDRESS});

    auto indexerConnector = std::make_unique<IndexerConnector>(
        indexerConfig, TEMPLATE_FILE_PATH, "", true, customLogFunction, INDEXER_TIMEOUT);

    ASSERT_NO_THROW(waitUntil([this]() { return m_indexerServers[A_IDX]->initialized(); }, MAX_INDEXER_INIT_TIME_MS));

    nlohmann::json publishData;
    publishData["id"] = INDEX_ID_A;
    publishData["operation"] = "INSERT";
    publishData["data"] = "content";
    ASSERT_NO_THROW(indexerConnector->publish(publishData.dump()));

    ASSERT_NO_THROW(waitUntil([&callbackCalled]() { return callbackCalled.load(); }, MAX_INDEXER_PUBLISH_TIME_MS));

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    EXPECT_TRUE(callbackCalled) << "Publish callback was not called";
    EXPECT_EQ(g_logTestState.errorLogsCount.load(), 1) << "Expected 1 request-level error log";
    // Could add a specific flag for validation_exception if needed

    indexerConnector.reset();
    Log::GLOBAL_LOG_FUNCTION = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
}

/**
 * @brief Test that handleIndexerInternalErrors handles 404 index not found error.
 */
TEST_F(IndexerConnectorTest, HandleIndexerInternalErrors_IndexNotFound)
{
    Log::GLOBAL_LOG_FUNCTION = nullptr;
    g_logTestState.reset();

    auto customLogFunction = createStandardLogFunction();

    // Elasticsearch 404 index not found error
    nlohmann::json errorResponse;
    errorResponse["error"]["type"] = "index_not_found_exception";
    errorResponse["error"]["reason"] = "no such index [indexer_connector_test]";
    errorResponse["error"]["resource.type"] = "index_or_alias";
    errorResponse["error"]["resource.id"] = "indexer_connector_test";
    errorResponse["error"]["index"] = "indexer_connector_test";
    errorResponse["status"] = 404;

    std::atomic<bool> callbackCalled {false};
    const auto returnErrorResponse = [&errorResponse,
                                      &callbackCalled](const std::string& data) -> std::pair<int, std::string>
    {
        callbackCalled = true;
        return {404, errorResponse.dump()};
    };
    m_indexerServers[A_IDX]->setPublishCallback(returnErrorResponse);

    nlohmann::json indexerConfig;
    indexerConfig["name"] = INDEXER_NAME;
    indexerConfig["hosts"] = nlohmann::json::array({A_ADDRESS});

    auto indexerConnector = std::make_unique<IndexerConnector>(
        indexerConfig, TEMPLATE_FILE_PATH, "", true, customLogFunction, INDEXER_TIMEOUT);

    ASSERT_NO_THROW(waitUntil([this]() { return m_indexerServers[A_IDX]->initialized(); }, MAX_INDEXER_INIT_TIME_MS));

    nlohmann::json publishData;
    publishData["id"] = INDEX_ID_A;
    publishData["operation"] = "INSERT";
    publishData["data"] = "content";
    ASSERT_NO_THROW(indexerConnector->publish(publishData.dump()));

    ASSERT_NO_THROW(waitUntil([&callbackCalled]() { return callbackCalled.load(); }, MAX_INDEXER_PUBLISH_TIME_MS));

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    EXPECT_TRUE(callbackCalled) << "Publish callback was not called";
    EXPECT_EQ(g_logTestState.errorLogsCount.load(), 1) << "Expected 1 request-level error log";

    indexerConnector.reset();
    Log::GLOBAL_LOG_FUNCTION = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
}

/**
 * @brief Test that handleIndexerInternalErrors handles 403 forbidden/authentication error.
 */
TEST_F(IndexerConnectorTest, HandleIndexerInternalErrors_Forbidden)
{
    Log::GLOBAL_LOG_FUNCTION = nullptr;
    g_logTestState.reset();

    auto customLogFunction = createStandardLogFunction();

    // Elasticsearch 403 forbidden error (authentication/authorization)
    nlohmann::json errorResponse;
    errorResponse["error"]["type"] = "security_exception";
    errorResponse["error"]["reason"] = "action [indices:data/write/bulk] is unauthorized for user [test_user]";
    errorResponse["status"] = 403;

    std::atomic<bool> callbackCalled {false};
    const auto returnErrorResponse = [&errorResponse,
                                      &callbackCalled](const std::string& data) -> std::pair<int, std::string>
    {
        callbackCalled = true;
        return {403, errorResponse.dump()};
    };
    m_indexerServers[A_IDX]->setPublishCallback(returnErrorResponse);

    nlohmann::json indexerConfig;
    indexerConfig["name"] = INDEXER_NAME;
    indexerConfig["hosts"] = nlohmann::json::array({A_ADDRESS});

    auto indexerConnector = std::make_unique<IndexerConnector>(
        indexerConfig, TEMPLATE_FILE_PATH, "", true, customLogFunction, INDEXER_TIMEOUT);

    ASSERT_NO_THROW(waitUntil([this]() { return m_indexerServers[A_IDX]->initialized(); }, MAX_INDEXER_INIT_TIME_MS));

    nlohmann::json publishData;
    publishData["id"] = INDEX_ID_A;
    publishData["operation"] = "INSERT";
    publishData["data"] = "content";
    ASSERT_NO_THROW(indexerConnector->publish(publishData.dump()));

    ASSERT_NO_THROW(waitUntil([&callbackCalled]() { return callbackCalled.load(); }, MAX_INDEXER_PUBLISH_TIME_MS));

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    EXPECT_TRUE(callbackCalled) << "Publish callback was not called";
    EXPECT_EQ(g_logTestState.errorLogsCount.load(), 1) << "Expected 1 request-level error log";

    indexerConnector.reset();
    Log::GLOBAL_LOG_FUNCTION = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
}

/**
 * @brief Test that handleIndexerInternalErrors handles cluster unavailable error.
 */
TEST_F(IndexerConnectorTest, HandleIndexerInternalErrors_ClusterUnavailable)
{
    Log::GLOBAL_LOG_FUNCTION = nullptr;
    g_logTestState.reset();

    auto customLogFunction = createStandardLogFunction();

    // Elasticsearch 503 service unavailable (cluster block, no master, etc.)
    nlohmann::json errorResponse;
    errorResponse["error"]["type"] = "cluster_block_exception";
    errorResponse["error"]["reason"] = "blocked by: [SERVICE_UNAVAILABLE/1/state not recovered / initialized];";
    errorResponse["status"] = 503;

    std::atomic<bool> callbackCalled {false};
    const auto returnErrorResponse = [&errorResponse,
                                      &callbackCalled](const std::string& data) -> std::pair<int, std::string>
    {
        callbackCalled = true;
        return {503, errorResponse.dump()};
    };
    m_indexerServers[A_IDX]->setPublishCallback(returnErrorResponse);

    nlohmann::json indexerConfig;
    indexerConfig["name"] = INDEXER_NAME;
    indexerConfig["hosts"] = nlohmann::json::array({A_ADDRESS});

    auto indexerConnector = std::make_unique<IndexerConnector>(
        indexerConfig, TEMPLATE_FILE_PATH, "", true, customLogFunction, INDEXER_TIMEOUT);

    ASSERT_NO_THROW(waitUntil([this]() { return m_indexerServers[A_IDX]->initialized(); }, MAX_INDEXER_INIT_TIME_MS));

    nlohmann::json publishData;
    publishData["id"] = INDEX_ID_A;
    publishData["operation"] = "INSERT";
    publishData["data"] = "content";
    ASSERT_NO_THROW(indexerConnector->publish(publishData.dump()));

    ASSERT_NO_THROW(waitUntil([&callbackCalled]() { return callbackCalled.load(); }, MAX_INDEXER_PUBLISH_TIME_MS));

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    EXPECT_TRUE(callbackCalled) << "Publish callback was not called";
    EXPECT_EQ(g_logTestState.errorLogsCount.load(), 1) << "Expected 1 request-level error log";

    indexerConnector.reset();
    Log::GLOBAL_LOG_FUNCTION = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
}

/**
 * @brief Test the connection and posterior data publication into a server. The published data is checked against the
 * expected one. The publication contains a DELETED_BY_QUERY operation.
 *
 */
TEST_F(IndexerConnectorTest, PublishDeletedByQuery)
{
    // Define the agent IDs
    std::vector<std::string> agentIds {INDEX_ID_A};
    nlohmann::json expectedMetadata;
    expectedMetadata["query"]["bool"]["filter"]["terms"]["agent.id"] = agentIds;

    // Callback that checks the expected data to be published.
    std::atomic<bool> callbackCalled {false};
    const auto checkPublishedData {
        [&expectedMetadata, &callbackCalled](const std::string& data) -> std::pair<int, std::string>
        {
            EXPECT_EQ(nlohmann::json::parse(data), expectedMetadata);
            callbackCalled = true;
            return {200, R"({"deleted":1})"};
        }};
    m_indexerServers[A_IDX]->setPublishCallback(checkPublishedData);

    // Create connector and wait until the connection is established.
    nlohmann::json indexerConfig;
    indexerConfig["name"] = INDEXER_NAME;
    indexerConfig["hosts"] = nlohmann::json::array({A_ADDRESS});
    auto indexerConnector {IndexerConnector(indexerConfig, TEMPLATE_FILE_PATH, "", true, nullptr, INDEXER_TIMEOUT)};
    ASSERT_NO_THROW(waitUntil([this]() { return m_indexerServers[A_IDX]->initialized(); }, MAX_INDEXER_INIT_TIME_MS));

    // Publish content and wait until the publication finishes.
    nlohmann::json publishData;
    publishData["id"] = INDEX_ID_A;
    publishData["operation"] = "DELETED_BY_QUERY";
    ASSERT_NO_THROW(indexerConnector.publish(publishData.dump()));
    ASSERT_NO_THROW(waitUntil([&callbackCalled]() { return callbackCalled.load(); }, MAX_INDEXER_PUBLISH_TIME_MS));
}

/**
 * @brief Test the publication to an unavailable server.
 *
 */
TEST_F(IndexerConnectorTest, PublishUnavailableServer)
{
    // Callback function that checks if the callback was executed or not.
    std::atomic<bool> callbackCalled {false};
    const auto checkPublishedData {[&callbackCalled](const std::string& data) -> std::pair<int, std::string>
                                   {
                                       std::ignore = data;
                                       callbackCalled = true;
                                       return {200, R"({"errors":false})"};
                                   }};
    m_indexerServers[B_IDX]->setPublishCallback(checkPublishedData);

    // Initialize connector.
    nlohmann::json indexerConfig;
    indexerConfig["name"] = INDEXER_NAME;
    indexerConfig["hosts"] = nlohmann::json::array({B_ADDRESS});
    auto indexerConnector {IndexerConnector(indexerConfig, TEMPLATE_FILE_PATH, "", true, nullptr, INDEXER_TIMEOUT)};

    // Trigger publication and expect that it is not made.
    const auto publishData = R"({"dummy":true})"_json;
    ASSERT_NO_THROW(indexerConnector.publish(publishData.dump()));
    ASSERT_THROW(waitUntil([&callbackCalled]() { return callbackCalled.load(); }, MAX_INDEXER_PUBLISH_TIME_MS),
                 std::runtime_error);
}

/**
 * @brief Test the connection and posterior publication of invalid data to an available server.
 *
 */
TEST_F(IndexerConnectorTest, PublishInvalidNoOperation)
{
    // Callback function that checks if the callback was executed or not.
    std::atomic<bool> callbackCalled {false};
    const auto checkCallbackCalled {[&callbackCalled](const std::string& data) -> std::pair<int, std::string>
                                    {
                                        std::ignore = data;
                                        callbackCalled = true;
                                        return {200, R"({"errors":false})"};
                                    }};
    m_indexerServers[A_IDX]->setPublishCallback(checkCallbackCalled);

    // Create connector and wait until the connection is established.
    nlohmann::json indexerConfig;
    indexerConfig["name"] = INDEXER_NAME;
    indexerConfig["hosts"] = nlohmann::json::array({A_ADDRESS});
    auto indexerConnector {IndexerConnector(indexerConfig, TEMPLATE_FILE_PATH, "", true, nullptr, INDEXER_TIMEOUT)};
    ASSERT_NO_THROW(waitUntil([this]() { return m_indexerServers[A_IDX]->initialized(); }, MAX_INDEXER_INIT_TIME_MS));

    // Trigger publication and expect that it is not made.
    nlohmann::json publishData;
    publishData["id"] = "111";
    ASSERT_NO_THROW(indexerConnector.publish(publishData.dump()));
    ASSERT_THROW(waitUntil([&callbackCalled]() { return callbackCalled.load(); }, MAX_INDEXER_PUBLISH_TIME_MS),
                 std::runtime_error);
    ASSERT_EQ(callbackCalled, false);
}

/**
 * @brief Test the connection and posterior publication of invalid data to an available server.
 *
 */
TEST_F(IndexerConnectorTest, PublishInvalidNoID)
{
    // Callback function that checks if the callback was executed or not.
    std::atomic<bool> callbackCalled {false};
    const auto checkCallbackCalled {[&callbackCalled](const std::string& data) -> std::pair<int, std::string>
                                    {
                                        std::ignore = data;
                                        callbackCalled = true;
                                        return {200, R"({"errors":false})"};
                                    }};
    m_indexerServers[A_IDX]->setPublishCallback(checkCallbackCalled);

    // Create connector and wait until the connection is established.
    nlohmann::json indexerConfig;
    indexerConfig["name"] = INDEXER_NAME;
    indexerConfig["hosts"] = nlohmann::json::array({A_ADDRESS});
    auto indexerConnector {IndexerConnector(indexerConfig, TEMPLATE_FILE_PATH, "", true, nullptr, INDEXER_TIMEOUT)};
    ASSERT_NO_THROW(waitUntil([this]() { return m_indexerServers[A_IDX]->initialized(); }, MAX_INDEXER_INIT_TIME_MS));

    // Trigger publication and expect that it is not made.
    nlohmann::json publishData;
    publishData["operation"] = "DELETED";
    ASSERT_NO_THROW(indexerConnector.publish(publishData.dump()));
    ASSERT_THROW(waitUntil([&callbackCalled]() { return callbackCalled.load(); }, MAX_INDEXER_PUBLISH_TIME_MS),
                 std::runtime_error);
    ASSERT_EQ(callbackCalled, false);
}

/**
 * @brief Test the connection and posterior publication of invalid data to an available server.
 *
 */
TEST_F(IndexerConnectorTest, PublishNoInsertData)
{
    // Callback function that checks if the callback was executed or not.
    std::atomic<bool> callbackCalled {false};
    const auto checkCallbackCalled {[&callbackCalled](const std::string& data) -> std::pair<int, std::string>
                                    {
                                        std::ignore = data;
                                        callbackCalled = true;
                                        return {200, R"({"errors":false})"};
                                    }};
    m_indexerServers[A_IDX]->setPublishCallback(checkCallbackCalled);

    // Create connector and wait until the connection is established.
    nlohmann::json indexerConfig;
    indexerConfig["name"] = INDEXER_NAME;
    indexerConfig["hosts"] = nlohmann::json::array({A_ADDRESS});
    auto indexerConnector {IndexerConnector(indexerConfig, TEMPLATE_FILE_PATH, "", true, nullptr, INDEXER_TIMEOUT)};
    ASSERT_NO_THROW(waitUntil([this]() { return m_indexerServers[A_IDX]->initialized(); }, MAX_INDEXER_INIT_TIME_MS));

    // Trigger publication and expect that it is not made.
    nlohmann::json publishData;
    publishData["id"] = INDEX_ID_A;
    publishData["operation"] = "INSERT";
    ASSERT_NO_THROW(indexerConnector.publish(publishData.dump()));
    ASSERT_THROW(waitUntil([&callbackCalled]() { return callbackCalled.load(); }, MAX_INDEXER_PUBLISH_TIME_MS),
                 std::runtime_error);
    ASSERT_EQ(callbackCalled, false);
}

/**
 * @brief Test the connection and posterior double data publication into a server. The published data is checked against
 * the expected one.
 *
 */
TEST_F(IndexerConnectorTest, PublishTwoIndexes)
{
    auto publishedData = nlohmann::json::array();

    // Callback that stores the published data into a JSON array.
    std::atomic<bool> callbackCalled {false};
    const auto checkPublishedData {
        [&callbackCalled, &publishedData](const std::string& data) -> std::pair<int, std::string>
        {
            const auto splitData {Utils::split(data, '\n')};
            nlohmann::json entry;
            entry["metadata"] = nlohmann::json::parse(splitData.front());
            entry["data"] = nlohmann::json::parse(splitData.back());
            publishedData.push_back(std::move(entry));
            callbackCalled = true;
            return {200, R"({"errors":false})"};
        }};
    m_indexerServers[A_IDX]->setPublishCallback(checkPublishedData);

    // Create connector and wait until the connection is established.
    nlohmann::json indexerConfig;
    indexerConfig["name"] = INDEXER_NAME;
    indexerConfig["hosts"] = nlohmann::json::array({A_ADDRESS});
    auto indexerConnector {IndexerConnector(indexerConfig, TEMPLATE_FILE_PATH, "", true, nullptr, INDEXER_TIMEOUT)};
    ASSERT_NO_THROW(waitUntil([this]() { return m_indexerServers[A_IDX]->initialized(); }, MAX_INDEXER_INIT_TIME_MS));

    // Publish content to INDEX_ID_A and wait until is finished.
    constexpr auto INDEX_DATA_A {"contentA"};
    nlohmann::json publishData;
    publishData["id"] = INDEX_ID_A;
    publishData["operation"] = "INSERT";
    publishData["data"] = INDEX_DATA_A;
    ASSERT_NO_THROW(indexerConnector.publish(publishData.dump()));
    ASSERT_NO_THROW(waitUntil([&callbackCalled]() { return callbackCalled.load(); }, MAX_INDEXER_PUBLISH_TIME_MS));

    // Publish content to INDEX_ID_B and wait until is finished.
    const auto INDEX_DATA_B = R"({"contentB":true})"_json;
    publishData["id"] = INDEX_ID_B;
    publishData["data"] = INDEX_DATA_B;
    ASSERT_NO_THROW(indexerConnector.publish(publishData.dump()));
    callbackCalled = false;
    ASSERT_NO_THROW(waitUntil([&callbackCalled]() { return callbackCalled.load(); }, MAX_INDEXER_PUBLISH_TIME_MS));

    // Check expected data.
    nlohmann::json expectedDataA;
    expectedDataA["metadata"]["index"]["_index"] = INDEXER_NAME;
    expectedDataA["metadata"]["index"]["_id"] = INDEX_ID_A;
    expectedDataA["data"] = INDEX_DATA_A;
    nlohmann::json expectedDataB;
    expectedDataB["metadata"]["index"]["_index"] = INDEXER_NAME;
    expectedDataB["metadata"]["index"]["_id"] = INDEX_ID_B;
    expectedDataB["data"] = INDEX_DATA_B;
    const auto expectedData = nlohmann::json::array({expectedDataA, expectedDataB});
    ASSERT_EQ(expectedData, publishedData);
}

/**
 * @brief Test the connection and posterior publication to a server that responds the publication with an error.
 *
 */
TEST_F(IndexerConnectorTest, PublishErrorFromServer)
{
    // Callback function that checks if the callback was executed or not.
    std::atomic<bool> callbackCalled {false};
    const auto forceErrorCallback {[&callbackCalled](const std::string& data) -> std::pair<int, std::string>
                                   {
                                       std::ignore = data;
                                       callbackCalled = true;
                                       throw std::runtime_error {"Forced server error"};
                                   }};
    m_indexerServers[A_IDX]->setPublishCallback(forceErrorCallback);

    // Create connector and wait until the connection is established.
    nlohmann::json indexerConfig;
    indexerConfig["name"] = INDEXER_NAME;
    indexerConfig["hosts"] = nlohmann::json::array({A_ADDRESS});
    auto indexerConnector {IndexerConnector(indexerConfig, TEMPLATE_FILE_PATH, "", true, nullptr, INDEXER_TIMEOUT)};
    ASSERT_NO_THROW(waitUntil([this]() { return m_indexerServers[A_IDX]->initialized(); }, MAX_INDEXER_INIT_TIME_MS));

    // Trigger publication and expect that it is not made.
    nlohmann::json publishData;
    publishData["id"] = INDEX_ID_A;
    publishData["operation"] = "INSERTED";
    publishData["data"] = "content";
    ASSERT_NO_THROW(indexerConnector.publish(publishData.dump()));
    ASSERT_NO_THROW(waitUntil([&callbackCalled]() { return callbackCalled.load(); }, MAX_INDEXER_PUBLISH_TIME_MS));

    callbackCalled = false;
    publishData.erase("data");
    publishData["id"] = INDEX_ID_A;
    publishData["operation"] = "DELETED";
    ASSERT_NO_THROW(indexerConnector.publish(publishData.dump()));
    ASSERT_NO_THROW(waitUntil([&callbackCalled]() { return callbackCalled.load(); }, MAX_INDEXER_PUBLISH_TIME_MS));
}

/**
 * @brief Test the connection to a server with an invalid template file path.
 *
 */
TEST_F(IndexerConnectorTest, TemplateFileNotFoundThrows)
{
    nlohmann::json indexerConfig;
    indexerConfig["name"] = INDEXER_NAME;
    indexerConfig["hosts"] = nlohmann::json::array({A_ADDRESS});

    constexpr auto INVALID_TEMPLATE_FILE_PATH {"inexistant.json"};
    EXPECT_THROW(IndexerConnector(indexerConfig, INVALID_TEMPLATE_FILE_PATH, "", true, nullptr, INDEXER_TIMEOUT),
                 std::runtime_error);
}

/**
 * @brief Test the initialization with upper case character in the index name.
 *
 */
TEST_F(IndexerConnectorTest, UpperCaseCharactersIndexName)
{

    // Create connector and wait until the connection is established.
    nlohmann::json indexerConfig;
    indexerConfig["name"] = "UPPER_case_INDEX";
    indexerConfig["hosts"] = nlohmann::json::array({A_ADDRESS});
    EXPECT_THROW(IndexerConnector(indexerConfig, TEMPLATE_FILE_PATH, "", true, nullptr, INDEXER_TIMEOUT),
                 std::runtime_error);
}

TEST_F(IndexerConnectorTest, QueueCorruptionTest)
{
    Log::GLOBAL_LOG_FUNCTION = nullptr;
    g_logTestState.reset();

    auto customLogFunction = createStandardLogFunction();
    nlohmann::json indexerConfig;
    indexerConfig["name"] = INDEXER_NAME;
    indexerConfig["hosts"] = nlohmann::json::array({A_ADDRESS});
    indexerConfig["username"] = "user";
    indexerConfig["password"] = "password";

    auto spIndexerConnector =
        std::make_unique<IndexerConnector>(indexerConfig, TEMPLATE_FILE_PATH, "", true, nullptr, INDEXER_TIMEOUT);

    spIndexerConnector.reset();

    bool corrupted {false};
    std::string prefix {"queue/indexer/indexer_connector_test/MANIFEST"};
    for (const auto& entry : std::filesystem::directory_iterator("queue/indexer/indexer_connector_test"))
    {
        if (entry.path().string().substr(0, prefix.size()).compare(prefix) == 0)
        {
            std::filesystem::remove(entry.path());
            corrupted = true;
            break;
        }
    }
    EXPECT_TRUE(corrupted);

    EXPECT_NO_THROW({
        spIndexerConnector = std::make_unique<IndexerConnector>(
            indexerConfig, TEMPLATE_FILE_PATH, "", true, customLogFunction, INDEXER_TIMEOUT);
    });

    EXPECT_TRUE(g_logTestState.dbRepaired) << "The log that indicates the database was repaired wasn't found";
}
