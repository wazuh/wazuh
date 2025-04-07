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

namespace Log
{
    std::function<void(
        const int, const std::string&, const std::string&, const int, const std::string&, const std::string&, va_list)>
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
    auto indexerConnector {IndexerConnector(indexerConfig, TEMPLATE_FILE_PATH, "", nullptr, INDEXER_TIMEOUT)};
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
    auto indexerConnector {IndexerConnector(indexerConfig, TEMPLATE_FILE_PATH, "", nullptr, INDEXER_TIMEOUT)};
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
    auto indexerConnector {IndexerConnector(indexerConfig, TEMPLATE_FILE_PATH, "", nullptr, INDEXER_TIMEOUT)};
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
    auto indexerConnector {IndexerConnector(indexerConfig, TEMPLATE_FILE_PATH, "", nullptr, INDEXER_TIMEOUT)};
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
    auto indexerConnector {IndexerConnector(indexerConfig, TEMPLATE_FILE_PATH, "", nullptr, INDEXER_TIMEOUT)};
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
    auto indexerConnector {IndexerConnector(indexerConfig, TEMPLATE_FILE_PATH, "", nullptr, INDEXER_TIMEOUT)};
    ASSERT_THROW(waitUntil([this]() { return m_indexerServers[A_IDX]->initialized(); }, MAX_INDEXER_INIT_TIME_MS),
                 std::runtime_error);
}

/**
 * @brief Test the connection to a server that responds the template initialization with an error.
 *
 */
TEST_F(IndexerConnectorTest, ConnectionInitTemplateErrorFromServer)
{
    // Callback function that checks if the callback was executed or not.
    std::atomic<bool> callbackCalled {false};
    const auto forceErrorCallback {[&callbackCalled](const std::string& data)
                                   {
                                       std::ignore = data;
                                       callbackCalled = true;
                                       throw std::runtime_error {"Forced server error"};
                                   }};
    m_indexerServers[A_IDX]->setInitTemplateCallback(forceErrorCallback);

    // Create connector and wait until the connection is established.
    nlohmann::json indexerConfig;
    indexerConfig["name"] = INDEXER_NAME;
    indexerConfig["hosts"] = nlohmann::json::array({A_ADDRESS});
    auto indexerConnector {IndexerConnector(indexerConfig, TEMPLATE_FILE_PATH, "", nullptr, INDEXER_TIMEOUT)};
    ASSERT_THROW(waitUntil([this]() { return m_indexerServers[A_IDX]->initialized(); }, MAX_INDEXER_INIT_TIME_MS),
                 std::runtime_error);
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
    auto indexerConnector {IndexerConnector(indexerConfig, TEMPLATE_FILE_PATH, "", nullptr, INDEXER_TIMEOUT)};
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
    const auto checkPublishedData {[&expectedMetadata, &callbackCalled, &INDEX_DATA](const std::string& data)
                                   {
                                       const auto splitData {Utils::split(data, '\n')};
                                       ASSERT_EQ(nlohmann::json::parse(splitData.front()), expectedMetadata);
                                       ASSERT_EQ(nlohmann::json::parse(splitData.back()), INDEX_DATA);
                                       callbackCalled = true;
                                   }};
    m_indexerServers[A_IDX]->setPublishCallback(checkPublishedData);

    // Create connector and wait until the connection is established.
    nlohmann::json indexerConfig;
    indexerConfig["name"] = INDEXER_NAME;
    indexerConfig["hosts"] = nlohmann::json::array({A_ADDRESS});
    auto indexerConnector {IndexerConnector(indexerConfig, TEMPLATE_FILE_PATH, "", nullptr, INDEXER_TIMEOUT)};
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
    // The format of the data published is divided in two lines:
    // First line: JSON data with the metadata (indexer name, index ID)
    // Second line: Index data.
    constexpr auto INDEX_DATA {"content"};
    std::atomic<bool> callbackCalled {false};
    const auto checkPublishedData {[&expectedMetadata, &callbackCalled, &INDEX_DATA](const std::string& data)
                                   {
                                       const auto splitData {Utils::split(data, '\n')};
                                       ASSERT_EQ(nlohmann::json::parse(splitData.front()), expectedMetadata);
                                       ASSERT_EQ(nlohmann::json::parse(splitData.back()), INDEX_DATA);
                                       callbackCalled = true;
                                   }};
    m_indexerServers[A_IDX]->setPublishCallback(checkPublishedData);

    // Create connector and make sure the connection isn't established.
    nlohmann::json indexerConfig;
    indexerConfig["name"] = INDEXER_NAME;
    indexerConfig["hosts"] = nlohmann::json::array({A_ADDRESS});
    auto indexerConnector {
        std::make_shared<IndexerConnector>(indexerConfig,
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
        std::make_shared<IndexerConnector>(indexerConfig, TEMPLATE_FILE_PATH, "", nullptr, INDEXER_TIMEOUT);
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
    expectedMetadata["delete"]["_index"] = INDEXER_NAME;
    expectedMetadata["delete"]["_id"] = INDEX_ID_A;

    // Callback that checks the expected data to be published.
    // The format of the data published is divided in two lines:
    // First line: JSON data with the metadata (indexer name, index ID)
    // Second line: Index data. When the operation is DELETED, no data is present.
    std::atomic<bool> callbackCalled {false};
    const auto checkPublishedData {[&expectedMetadata, &callbackCalled](const std::string& data)
                                   {
                                       const auto splitData {Utils::split(data, '\n')};
                                       ASSERT_EQ(nlohmann::json::parse(splitData.front()), expectedMetadata);
                                       callbackCalled = true;
                                   }};
    m_indexerServers[A_IDX]->setPublishCallback(checkPublishedData);

    // Create connector and wait until the connection is established.
    nlohmann::json indexerConfig;
    indexerConfig["name"] = INDEXER_NAME;
    indexerConfig["hosts"] = nlohmann::json::array({A_ADDRESS});
    auto indexerConnector {IndexerConnector(indexerConfig, TEMPLATE_FILE_PATH, "", nullptr, INDEXER_TIMEOUT)};
    ASSERT_NO_THROW(waitUntil([this]() { return m_indexerServers[A_IDX]->initialized(); }, MAX_INDEXER_INIT_TIME_MS));

    // Publish content and wait until the publication finishes.
    nlohmann::json publishData;
    publishData["id"] = INDEX_ID_A;
    publishData["operation"] = "DELETED";
    ASSERT_NO_THROW(indexerConnector.publish(publishData.dump()));
    ASSERT_NO_THROW(waitUntil([&callbackCalled]() { return callbackCalled.load(); }, MAX_INDEXER_PUBLISH_TIME_MS));
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
    // The format of the data published is divided in two lines:
    // First line: JSON data with the metadata (indexer name, index ID)
    // Second line: Index data. When the operation is DELETED, no data is present.
    std::atomic<bool> callbackCalled {false};
    const auto checkPublishedData {[&expectedMetadata, &callbackCalled](const std::string& data)
                                   {
                                       ASSERT_EQ(nlohmann::json::parse(data), expectedMetadata);
                                       callbackCalled = true;
                                   }};
    m_indexerServers[A_IDX]->setPublishCallback(checkPublishedData);

    // Create connector and wait until the connection is established.
    nlohmann::json indexerConfig;
    indexerConfig["name"] = INDEXER_NAME;
    indexerConfig["hosts"] = nlohmann::json::array({A_ADDRESS});
    auto indexerConnector {IndexerConnector(indexerConfig, TEMPLATE_FILE_PATH, "", nullptr, INDEXER_TIMEOUT)};
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
    const auto checkPublishedData {[&callbackCalled](const std::string& data)
                                   {
                                       std::ignore = data;
                                       callbackCalled = true;
                                   }};
    m_indexerServers[B_IDX]->setPublishCallback(checkPublishedData);

    // Initialize connector.
    nlohmann::json indexerConfig;
    indexerConfig["name"] = INDEXER_NAME;
    indexerConfig["hosts"] = nlohmann::json::array({B_ADDRESS});
    auto indexerConnector {IndexerConnector(indexerConfig, TEMPLATE_FILE_PATH, "", nullptr, INDEXER_TIMEOUT)};

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
    const auto checkCallbackCalled {[&callbackCalled](const std::string& data)
                                    {
                                        std::ignore = data;
                                        callbackCalled = true;
                                    }};
    m_indexerServers[A_IDX]->setPublishCallback(checkCallbackCalled);

    // Create connector and wait until the connection is established.
    nlohmann::json indexerConfig;
    indexerConfig["name"] = INDEXER_NAME;
    indexerConfig["hosts"] = nlohmann::json::array({A_ADDRESS});
    auto indexerConnector {IndexerConnector(indexerConfig, TEMPLATE_FILE_PATH, "", nullptr, INDEXER_TIMEOUT)};
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
    const auto checkCallbackCalled {[&callbackCalled](const std::string& data)
                                    {
                                        std::ignore = data;
                                        callbackCalled = true;
                                    }};
    m_indexerServers[A_IDX]->setPublishCallback(checkCallbackCalled);

    // Create connector and wait until the connection is established.
    nlohmann::json indexerConfig;
    indexerConfig["name"] = INDEXER_NAME;
    indexerConfig["hosts"] = nlohmann::json::array({A_ADDRESS});
    auto indexerConnector {IndexerConnector(indexerConfig, TEMPLATE_FILE_PATH, "", nullptr, INDEXER_TIMEOUT)};
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
    const auto checkCallbackCalled {[&callbackCalled](const std::string& data)
                                    {
                                        std::ignore = data;
                                        callbackCalled = true;
                                    }};
    m_indexerServers[A_IDX]->setPublishCallback(checkCallbackCalled);

    // Create connector and wait until the connection is established.
    nlohmann::json indexerConfig;
    indexerConfig["name"] = INDEXER_NAME;
    indexerConfig["hosts"] = nlohmann::json::array({A_ADDRESS});
    auto indexerConnector {IndexerConnector(indexerConfig, TEMPLATE_FILE_PATH, "", nullptr, INDEXER_TIMEOUT)};
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

    // Callback that stores the published data into a JSON array. It also counts the times the callback was called.
    // The format of the data published is divided in two lines:
    // First line: JSON data with the metadata (indexer name, index ID).
    // Second line: Index data.
    std::atomic<bool> callbackCalled {false};
    const auto checkPublishedData {[&callbackCalled, &publishedData](const std::string& data)
                                   {
                                       const auto splitData {Utils::split(data, '\n')};
                                       nlohmann::json entry;
                                       entry["metadata"] = nlohmann::json::parse(splitData.front());
                                       entry["data"] = nlohmann::json::parse(splitData.back());
                                       publishedData.push_back(std::move(entry));
                                       callbackCalled = true;
                                   }};
    m_indexerServers[A_IDX]->setPublishCallback(checkPublishedData);

    // Create connector and wait until the connection is established.
    nlohmann::json indexerConfig;
    indexerConfig["name"] = INDEXER_NAME;
    indexerConfig["hosts"] = nlohmann::json::array({A_ADDRESS});
    auto indexerConnector {IndexerConnector(indexerConfig, TEMPLATE_FILE_PATH, "", nullptr, INDEXER_TIMEOUT)};
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
    const auto forceErrorCallback {[&callbackCalled](const std::string& data)
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
    auto indexerConnector {IndexerConnector(indexerConfig, TEMPLATE_FILE_PATH, "", nullptr, INDEXER_TIMEOUT)};
    ASSERT_NO_THROW(waitUntil([this]() { return m_indexerServers[A_IDX]->initialized(); }, MAX_INDEXER_INIT_TIME_MS));

    // Trigger publication and expect that it is not made.
    nlohmann::json publishData;
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
    EXPECT_THROW(IndexerConnector(indexerConfig, INVALID_TEMPLATE_FILE_PATH, "", nullptr, INDEXER_TIMEOUT),
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
    EXPECT_THROW(IndexerConnector(indexerConfig, TEMPLATE_FILE_PATH, "", nullptr, INDEXER_TIMEOUT), std::runtime_error);
}

TEST_F(IndexerConnectorTest, QueueCorruptionTest)
{
    nlohmann::json indexerConfig;
    indexerConfig["name"] = INDEXER_NAME;
    indexerConfig["hosts"] = nlohmann::json::array({A_ADDRESS});
    indexerConfig["username"] = "user";
    indexerConfig["password"] = "password";

    auto spIndexerConnector =
        std::make_unique<IndexerConnector>(indexerConfig, TEMPLATE_FILE_PATH, "", nullptr, INDEXER_TIMEOUT);

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

    bool dbRepaired {false};
    auto customLogFunction = [&dbRepaired](const int logLevel,
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
        std::ignore = args;

        if (logLevel == 2) // Warning messages
        {
            if (logMessage.compare("Database '%s' was repaired because it was corrupt.") == 0)
            {
                dbRepaired = true;
            }
        }
    };

    EXPECT_NO_THROW({
        spIndexerConnector = std::make_unique<IndexerConnector>(
            indexerConfig, TEMPLATE_FILE_PATH, "", customLogFunction, INDEXER_TIMEOUT);
    });

    EXPECT_TRUE(dbRepaired) << "The log that indicates the database was repaired wasn't found";
}
