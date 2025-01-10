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

#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <grp.h>
#include <memory>
#include <nlohmann/json.hpp>
#include <pwd.h>
#include <regex>
#include <stdexcept>
#include <thread>
#include <utility>

#include <base/logging.hpp>
#include <base/utils/stringUtils.hpp>
#include <base/utils/timeUtils.hpp>

#include <gtest/gtest.h>
#include <indexerConnector/indexerConnector.hpp>

#include "fakeIndexer.hpp"

#define BUFFER_SIZE 256

class IndexerConnectorTest : public ::testing::Test
{
protected:
    IndexerConnectorTest() = default;
    ~IndexerConnectorTest() override = default;

    std::vector<std::unique_ptr<FakeIndexer>> m_indexerServers; ///< List of indexer servers.

    /**
     * @brief Setup routine for each test fixture.
     *
     */
    void SetUp() override;

    /**
     * @brief Teardown routine for each test fixture.
     *
     */
    void TearDown() override;

    /**
     * @brief Waits until the stop condition is true or the max sleep time is reached. In the latter, an exception is
     * thrown.
     *
     * @param stopCondition Wait stop condition function.
     * @param maxSleepTimeMs Max time to wait.
     */
    void waitUntil(const std::function<bool()>& stopCondition, const unsigned int& maxSleepTimeMs) const;
};

constexpr auto DATABASE_BASE_PATH = "queue/indexer/";

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

static const auto DEFAULT_CONTENT {"Content published"};
constexpr auto LOG_FILE = "indexer_connector_test.log";

void IndexerConnectorTest::SetUp()
{
    // Configure logging file
    auto logginfConfig =
        logging::LoggingConfig {.filePath = LOG_FILE, .level = logging::Level::Debug, .truncate = true};
    logging::start(logginfConfig);

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

    logging::stop();
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

extern "C" struct passwd* __wrap_getpwnam(const char* name)
{
    static struct passwd dummy_passwd;
    static char dummy_name[BUFFER_SIZE];
    static char dummy_dir[BUFFER_SIZE];
    static char dummy_shell[BUFFER_SIZE];

    if (strcmp(name, "wazuh") == 0) // Simulate only "wazuh" user existing
    {
        dummy_passwd.pw_name = strcpy(dummy_name, "wazuh");
        dummy_passwd.pw_uid = 1000;
        dummy_passwd.pw_gid = 1000;
        dummy_passwd.pw_dir = strcpy(dummy_dir, "/home/wazuh");
        dummy_passwd.pw_shell = strcpy(dummy_shell, "/bin/bash");
        return &dummy_passwd;
    }

    return nullptr; // Simulate failure for other users
}

extern "C" struct group* __wrap_getgrnam(const char* name)
{
    static struct group dummy_group;
    static char dummy_name[BUFFER_SIZE];

    if (strcmp(name, "wazuh") == 0) // Simulate only "wazuh" group existing
    {
        dummy_group.gr_name = strcpy(dummy_name, "wazuh");
        dummy_group.gr_gid = 1000;
        dummy_group.gr_mem = nullptr; // No additional group members in this mock
        return &dummy_group;
    }

    return nullptr; // Simulate failure for other groups
}

extern "C" int __wrap_chown(const char* path, uid_t owner, gid_t group)
{
    // Simulate a successful chown operation for the "/tmp/success" file
    if (strcmp(path, "/tmp/wazuh-server/root-ca-merged.pem") == 0)
    {
        return 0; // Return success
    }
    return -1; // Return failure
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
    IndexerConnectorOptions indexerConfig {.name = INDEXER_NAME,
                                           .hosts = {A_ADDRESS},
                                           .username = "user",
                                           .password = "password",
                                           .timeout = INDEXER_TIMEOUT};

    // Create connector and wait until the connection is established.
    auto indexerConnector {IndexerConnector(indexerConfig)};
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
    IndexerConnectorOptions indexerConfig {.name = INDEXER_NAME,
                                           .hosts = {A_ADDRESS},
                                           .sslOptions = {.cacert = {"/etc/filebeat/certs/root-ca.pem"},
                                                          .cert = "/etc/filebeat/certs/filebeat.pem",
                                                          .key = "/etc/filebeat/certs/filebeat-key.pem"},
                                           .timeout = INDEXER_TIMEOUT};

    // Create connector and wait until the connection is established.
    auto indexerConnector {IndexerConnector(indexerConfig)};
}

/**
 * @brief Test the connection to an available server with SSL credentials.
 *
 * @note The SSL data is a dummy one and there are no functionality checks here. The target of this test is to increase
 * the test coverage.
 *
 */
TEST_F(IndexerConnectorTest, ConnectionWithCertsArray)
{
    // Setup for the test
    const std::string certFileOne = "./root-ca-one.pem";
    const std::string certFileTwo = "./root-ca-two.pem";
    const std::string mergedCertFile = "/tmp/wazuh-server/root-ca-merged.pem";

    // Create the first certificate file
    std::ofstream outputFile(certFileOne);
    outputFile << "CERT-ONE\n";
    outputFile.close();

    // Create the second certificate file
    std::ofstream outputFileSecond(certFileTwo);
    outputFileSecond << "CERT-TWO\n";
    outputFileSecond.close();

    // Indexer configuration with SSL options
    IndexerConnectorOptions indexerConfig {.name = INDEXER_NAME,
                                           .hosts = {A_ADDRESS},
                                           .sslOptions = {.cacert = {certFileOne, certFileTwo},
                                                          .cert = "/etc/filebeat/certs/filebeat.pem",
                                                          .key = "/etc/filebeat/certs/filebeat-key.pem"},
                                           .timeout = INDEXER_TIMEOUT};

    // Attempt to create the connector and expect no exceptions for valid certificates
    ASSERT_NO_THROW({ IndexerConnector indexerConnector(indexerConfig); });

    // Check that the content of the merged file is as expected
    std::ifstream file(mergedCertFile);
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    ASSERT_EQ(content, "CERT-ONE\nCERT-TWO\n");

    // Clean up files
    std::filesystem::remove(certFileOne);
    std::filesystem::remove(certFileTwo);
}

/**
 * @brief Test the connection to an available server with SSL credentials.
 *
 * @note The SSL data is a dummy one and there are no functionality checks here. The target of this test is to increase
 * the test coverage.
 *
 */
TEST_F(IndexerConnectorTest, ConnectionWithCertsArrayNoFiles)
{
    IndexerConnectorOptions indexerConfig {
        .name = INDEXER_NAME,
        .hosts = {A_ADDRESS},
        .sslOptions = {.cacert = {"/etc/filebeat/certs/root-ca.pem", "/etc/filebeat/certs/root-ca-two.pem"},
                       .cert = "/etc/filebeat/certs/filebeat.pem",
                       .key = "/etc/filebeat/certs/filebeat-key.pem"},
        .timeout = INDEXER_TIMEOUT};

    // Create connector and wait until the connection is established.
    // Throw is expected if the certs are not found.
    EXPECT_THROW(auto indexerConnector {IndexerConnector(indexerConfig)}, std::runtime_error);
}

/**
 * @brief Test the connection to an unavailable server.
 *
 */
TEST_F(IndexerConnectorTest, ConnectionUnavailableServer)
{
    IndexerConnectorOptions indexerConfig {.name = INDEXER_NAME, .hosts = {B_ADDRESS}, .timeout = INDEXER_TIMEOUT};

    // Create connector and wait until the max time is reached.
    auto indexerConnector {IndexerConnector(indexerConfig)};
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
    IndexerConnectorOptions indexerConfig {
        .name = INDEXER_NAME, .hosts = {A_ADDRESS, B_ADDRESS, C_ADDRESS}, .timeout = INDEXER_TIMEOUT};
    auto indexerConnector {IndexerConnector(indexerConfig)};
}

/**
 * @brief Test the connection to an inexistant server.
 *
 */
TEST_F(IndexerConnectorTest, ConnectionInvalidServer)
{
    // Trigger connection and expect that it is not made.
    constexpr auto INEXISTANT_SERVER {"localhost:6789"};
    IndexerConnectorOptions indexerConfig {
        .name = INDEXER_NAME, .hosts = {INEXISTANT_SERVER}, .timeout = INDEXER_TIMEOUT};

    auto indexerConnector {IndexerConnector(indexerConfig)};
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
        [&expectedMetadata, &callbackCalled, &INDEX_DATA](const std::string& data, std::string& content)
        {
            const auto splitData {base::utils::string::split(data, '\n')};
            ASSERT_EQ(nlohmann::json::parse(splitData.front()), expectedMetadata);
            ASSERT_EQ(nlohmann::json::parse(splitData.back()), INDEX_DATA);
            callbackCalled = true;
            content = DEFAULT_CONTENT;
        }};
    m_indexerServers[A_IDX]->setPublishCallback(checkPublishedData);

    // Create connector and wait until the connection is established.
    IndexerConnectorOptions indexerConfig {
        .name = INDEXER_NAME, .hosts = {A_ADDRESS}, .timeout = INDEXER_TIMEOUT, .databasePath = DATABASE_BASE_PATH};
    auto indexerConnector {IndexerConnector(indexerConfig)};

    // Publish content and wait until the publication finishes.
    nlohmann::json publishData;
    publishData["id"] = INDEX_ID_A;
    publishData["operation"] = "INSERT";
    publishData["data"] = INDEX_DATA;
    ASSERT_NO_THROW(indexerConnector.publish(publishData.dump()));
    ASSERT_NO_THROW(waitUntil([&callbackCalled]() { return callbackCalled.load(); }, MAX_INDEXER_PUBLISH_TIME_MS));
}

/**
 * @brief Test the connection and posterior data publication into a server. The mismatch size case is tested.
 *
 */
TEST_F(IndexerConnectorTest, PublishWithErrorsInBulkMismatch)
{
    nlohmann::json expectedMetadata;
    expectedMetadata["index"]["_index"] = INDEXER_NAME;
    expectedMetadata["index"]["_id"] = INDEX_ID_A;

    // Expected content
    auto constexpr totalElements {2};
    auto expectedContent = R"(
    {
        "took": 5055,
        "errors": true,
        "items": []
    })"_json;

    auto expectedElement = R"(
    {
        "index": {
            "_index": "test-basic-index",
            "_id": "1rQ_kZIBmzjx6FV-K3nH",
            "status": 400,
            "error": {
                "type": "mapper_parsing_exception",
                "reason": "failed to parse field [suricata.flow.bytes_toclient] of type [long] in document with id '1rQ_kZIBmzjx6FV-K3nH'. Preview of field's value: 'non-integer'",
                "caused_by": {
                    "type": "illegal_argument_exception",
                    "reason": "For input string: \"non-integer\""
                }
            }
        }
    })"_json;

    for (int i = 0; i < totalElements; ++i)
    {
        expectedContent.at("items").push_back(expectedElement);
    }

    // Callback that checks the expected data to be published.
    // The format of the data published is divided in two lines:
    // First line: JSON data with the metadata (indexer name, index ID)
    // Second line: Index data.
    std::atomic<bool> callbackCalled {false};
    const auto checkPublishedData {[&](const std::string& data, std::string& content)
                                   {
                                       const auto splitData {base::utils::string::split(data, '\n')};
                                       ASSERT_EQ(nlohmann::json::parse(splitData.front()), expectedMetadata);
                                       callbackCalled = true;
                                       // Properly formatted JSON content as a string
                                       content = expectedContent.dump();
                                   }};
    m_indexerServers[A_IDX]->setPublishCallback(checkPublishedData);

    // Create connector and wait until the connection is established.
    IndexerConnectorOptions indexerConfig {.name = INDEXER_NAME,
                                           .hosts = {A_ADDRESS},
                                           .username = "admin",
                                           .password = "admin",
                                           .timeout = INDEXER_TIMEOUT,
                                           .workingThreads = 1,
                                           .databasePath = DATABASE_BASE_PATH};
    auto indexerConnector {IndexerConnector(indexerConfig)};

    // Publish content and wait until the publication finishes.
    nlohmann::json publishData;
    publishData["id"] = INDEX_ID_A;
    publishData["operation"] = "INSERT";
    publishData["data"] = R"({
        "timestamp" : "2018-10-03T16:16:26.711841+0000",
        "flow_id" : 678269478904081,
        "in_iface" : "enp0s3",
        "event_type" : "alert",
        "src_ip" : "192.168.1.146",
        "src_port" : 32864,
        "dest_ip" : "89.160.20.112",
        "dest_port" : 80,
        "proto" : "TCP",
        "tx_id" : 0,
        "alert" : {
            "action" : "allowed",
            "gid" : 1,
            "signature_id" : 2013028,
            "rev" : 4,
            "signature" : "ET POLICY curl User-Agent Outbound",
            "category" : "Attempted Information Leak",
            "severity" : 2
        },
        "http" : {
            "hostname" : "example.net",
            "url" : "/",
            "http_user_agent" : "curl/7.58.0",
            "http_content_type" : "text/html",
            "http_method" : "GET",
            "protocol" : "HTTP/1.1",
            "status" : 200,
            "length" : 1121
        },
        "app_proto" : "http",
        "flow" : {
            "pkts_toserver" : 4,
            "pkts_toclient" : 3,
            "bytes_toserver" : 347,
            "bytes_toclient" : "non-integer",
            "start" : "2018-10-03T16:16:26.467217+0000"
        }
    })"_json;

    for (int i = 0; i < totalElements - 1; ++i)
    {
        ASSERT_NO_THROW(indexerConnector.publish(publishData.dump()));
    }

    ASSERT_NO_THROW(waitUntil([&callbackCalled]() { return callbackCalled.load(); }, MAX_INDEXER_PUBLISH_TIME_MS));

    // Wait for the log file to be written
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Read the log file and check the error message
    std::ifstream logFile(LOG_FILE);
    std::string logContent((std::istreambuf_iterator<char>(logFile)), {});
    logFile.close();

    // Check the log content
    auto foundError = logContent.find("warning: Mismatch between the number of events (1) and response items (2)");
    ASSERT_TRUE(foundError != std::string::npos);
}

/**
 * @brief Test the connection and posterior data publication into a server. The published data is checked against the
 * expected one.
 *
 */
TEST_F(IndexerConnectorTest, PublishWithErrorsInBulkMultiThread)
{
    nlohmann::json expectedMetadata;
    expectedMetadata["index"]["_index"] = INDEXER_NAME;
    expectedMetadata["index"]["_id"] = INDEX_ID_A;

    // Expected content
    auto constexpr totalElements {100};
    auto expectedContent = R"(
    {
        "took": 5055,
        "errors": true,
        "items": []
    })"_json;

    auto expectedElement = R"(
    {
        "index": {
            "_index": "test-basic-index",
            "_id": "1rQ_kZIBmzjx6FV-K3nH",
            "status": 400,
            "error": {
                "type": "mapper_parsing_exception",
                "reason": "failed to parse field [suricata.flow.bytes_toclient] of type [long] in document with id '1rQ_kZIBmzjx6FV-K3nH'. Preview of field's value: 'non-integer'",
                "caused_by": {
                    "type": "illegal_argument_exception",
                    "reason": "For input string: \"non-integer\""
                }
            }
        }
    })"_json;

    for (int i = 0; i < totalElements; ++i)
    {
        expectedContent.at("items").push_back(expectedElement);
    }

    // Callback that checks the expected data to be published.
    // The format of the data published is divided in two lines:
    // First line: JSON data with the metadata (indexer name, index ID)
    // Second line: Index data.
    std::atomic<bool> callbackCalled {false};
    const auto checkPublishedData {[&](const std::string& data, std::string& content)
                                   {
                                       const auto splitData {base::utils::string::split(data, '\n')};
                                       ASSERT_EQ(nlohmann::json::parse(splitData.front()), expectedMetadata);
                                       callbackCalled = true;
                                       // Properly formatted JSON content as a string
                                       content = expectedContent.dump();
                                   }};
    m_indexerServers[A_IDX]->setPublishCallback(checkPublishedData);

    // Create connector and wait until the connection is established.
    IndexerConnectorOptions indexerConfig {.name = INDEXER_NAME,
                                           .hosts = {A_ADDRESS},
                                           .username = "admin",
                                           .password = "admin",
                                           .timeout = INDEXER_TIMEOUT,
                                           .workingThreads = 2,
                                           .databasePath = DATABASE_BASE_PATH};
    auto indexerConnector {IndexerConnector(indexerConfig)};

    // Publish content and wait until the publication finishes.
    nlohmann::json publishData;
    publishData["id"] = INDEX_ID_A;
    publishData["operation"] = "INSERT";
    publishData["data"] = R"({
        "timestamp" : "2018-10-03T16:16:26.711841+0000",
        "flow_id" : 678269478904081,
        "in_iface" : "enp0s3",
        "event_type" : "alert",
        "src_ip" : "192.168.1.146",
        "src_port" : 32864,
        "dest_ip" : "89.160.20.112",
        "dest_port" : 80,
        "proto" : "TCP",
        "tx_id" : 0,
        "alert" : {
            "action" : "allowed",
            "gid" : 1,
            "signature_id" : 2013028,
            "rev" : 4,
            "signature" : "ET POLICY curl User-Agent Outbound",
            "category" : "Attempted Information Leak",
            "severity" : 2
        },
        "http" : {
            "hostname" : "example.net",
            "url" : "/",
            "http_user_agent" : "curl/7.58.0",
            "http_content_type" : "text/html",
            "http_method" : "GET",
            "protocol" : "HTTP/1.1",
            "status" : 200,
            "length" : 1121
        },
        "app_proto" : "http",
        "flow" : {
            "pkts_toserver" : 4,
            "pkts_toclient" : 3,
            "bytes_toserver" : 347,
            "bytes_toclient" : "non-integer",
            "start" : "2018-10-03T16:16:26.467217+0000"
        }
    })"_json;

    for (int i = 0; i < totalElements; ++i)
    {
        ASSERT_NO_THROW(indexerConnector.publish(publishData.dump()));
    }

    ASSERT_NO_THROW(waitUntil([&callbackCalled]() { return callbackCalled.load(); }, MAX_INDEXER_PUBLISH_TIME_MS));

    // Wait for the log file to be written
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Read the log file
    std::ifstream logFile(LOG_FILE);
    std::string logContent((std::istreambuf_iterator<char>(logFile)), {});
    logFile.close();

    // Check the log content
    auto errorMessage =
        R"(warning: Error indexing document (type mapper_parsing_exception - reason: 'failed to parse field [suricata.flow.bytes_toclient] )"
        R"(of type [long] in document with id '1rQ_kZIBmzjx6FV-K3nH'. Preview of field's value: 'non-integer'') - Associated event: )"
        R"({"alert":{"action":"allowed","category":"Attempted Information Leak","gid":1,"rev":4,"severity":2,"signature":"ET POLICY curl )"
        R"(User-Agent Outbound","signature_id":2013028},"app_proto":"http","dest_ip":"89.160.20.112","dest_port":80,"event_type":"alert",)"
        R"("flow":{"bytes_toclient":"non-integer","bytes_toserver":347,"pkts_toclient":3,"pkts_toserver":4,"start":"2018-10-03T16:16:26.467217+0000"})"
        R"(,"flow_id":678269478904081,"http":{"hostname":"example.net","http_content_type":"text/html","http_method":"GET","http_user_agent")"
        R"(:"curl/7.58.0","length":1121,"protocol":"HTTP/1.1","status":200,"url":"/"},"in_iface":"enp0s3","proto":"TCP","src_ip")"
        R"(:"192.168.1.146","src_port":32864,"timestamp":"2018-10-03T16:16:26.711841+0000","tx_id":0})";

    size_t foundError = 0;
    for (int i = 0; i < totalElements; ++i)
    {
        foundError = logContent.find(errorMessage, foundError + 1);
        ASSERT_TRUE(foundError != std::string::npos);
    }
}

/**
 * @brief Test the connection and posterior data publication into a server. The published data is checked against
 * the expected one. The publication contains a DELETED operation.
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
    const auto checkPublishedData {[&expectedMetadata, &callbackCalled](const std::string& data, std::string& content)
                                   {
                                       const auto splitData {base::utils::string::split(data, '\n')};
                                       ASSERT_EQ(nlohmann::json::parse(splitData.front()), expectedMetadata);
                                       callbackCalled = true;
                                       content = DEFAULT_CONTENT;
                                   }};
    m_indexerServers[A_IDX]->setPublishCallback(checkPublishedData);

    // Create connector and wait until the connection is established.
    IndexerConnectorOptions indexerConfig {
        .name = INDEXER_NAME, .hosts = {A_ADDRESS}, .timeout = INDEXER_TIMEOUT, .databasePath = DATABASE_BASE_PATH};
    auto indexerConnector {IndexerConnector(indexerConfig)};

    // Publish content and wait until the publication finishes.
    nlohmann::json publishData;
    publishData["id"] = INDEX_ID_A;
    publishData["operation"] = "DELETED";
    ASSERT_NO_THROW(indexerConnector.publish(publishData.dump()));
    ASSERT_NO_THROW(waitUntil([&callbackCalled]() { return callbackCalled.load(); }, MAX_INDEXER_PUBLISH_TIME_MS));
}

/**
 * @brief Test the connection and posterior data publication into a server. The published data is checked against
 * the expected one. The payload doesn't contain an ID.
 *
 */
TEST_F(IndexerConnectorTest, PublishWithoutId)
{
    nlohmann::json expectedMetadata;
    expectedMetadata["index"]["_index"] = INDEXER_NAME;

    // Callback that checks the expected data to be published.
    // The format of the data published is divided in two lines:
    // First line: JSON data with the metadata (indexer name, index ID)
    // Second line: Index data.
    constexpr auto INDEX_DATA {"contentNoId"};
    std::atomic<bool> callbackCalled {false};
    const auto checkPublishedData {
        [&expectedMetadata, &callbackCalled, &INDEX_DATA](const std::string& data, std::string& content)
        {
            const auto splitData {base::utils::string::split(data, '\n')};
            ASSERT_EQ(nlohmann::json::parse(splitData.front()), expectedMetadata);
            ASSERT_EQ(nlohmann::json::parse(splitData.back()), INDEX_DATA);
            callbackCalled = true;
            content = DEFAULT_CONTENT;
        }};
    m_indexerServers[A_IDX]->setPublishCallback(checkPublishedData);

    // Create connector and wait until the connection is established.
    IndexerConnectorOptions indexerConfig {
        .name = INDEXER_NAME, .hosts = {A_ADDRESS}, .timeout = INDEXER_TIMEOUT, .databasePath = DATABASE_BASE_PATH};
    auto indexerConnector {IndexerConnector(indexerConfig)};

    // Publish content and wait until the publication finishes.
    nlohmann::json publishData;
    publishData["operation"] = "INSERT";
    publishData["data"] = INDEX_DATA;
    ASSERT_NO_THROW(indexerConnector.publish(publishData.dump()));
    ASSERT_NO_THROW(waitUntil([&callbackCalled]() { return callbackCalled.load(); }, MAX_INDEXER_PUBLISH_TIME_MS));
    ASSERT_TRUE(callbackCalled);
}

/**
 * @brief Test the publication to an unavailable server.
 *
 */
TEST_F(IndexerConnectorTest, PublishUnavailableServer)
{
    // Callback function that checks if the callback was executed or not.
    std::atomic<bool> callbackCalled {false};
    const auto checkPublishedData {[&callbackCalled](const std::string& data, std::string& content)
                                   {
                                       std::ignore = data;
                                       callbackCalled = true;
                                       content = DEFAULT_CONTENT;
                                   }};
    m_indexerServers[B_IDX]->setPublishCallback(checkPublishedData);

    // Initialize connector.
    IndexerConnectorOptions indexerConfig {
        .name = INDEXER_NAME, .hosts = {B_ADDRESS}, .timeout = INDEXER_TIMEOUT, .databasePath = DATABASE_BASE_PATH};

    auto indexerConnector {IndexerConnector(indexerConfig)};

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
TEST_F(IndexerConnectorTest, PublishInvalidData)
{
    // Callback function that checks if the callback was executed or not.
    std::atomic<bool> callbackCalled {false};
    const auto checkCallbackCalled {[&callbackCalled](const std::string& data, std::string& content)
                                    {
                                        std::ignore = data;
                                        callbackCalled = true;
                                        content = DEFAULT_CONTENT;
                                    }};
    m_indexerServers[A_IDX]->setPublishCallback(checkCallbackCalled);

    // Create connector and wait until the connection is established.
    IndexerConnectorOptions indexerConfig {.name = INDEXER_NAME, .hosts = {A_ADDRESS}, .timeout = INDEXER_TIMEOUT};
    auto indexerConnector {IndexerConnector(indexerConfig)};

    // Trigger publication and expect that it is not made.
    nlohmann::json publishData;
    publishData["operation"] = "DELETED";
    ASSERT_NO_THROW(indexerConnector.publish(publishData.dump()));
    ASSERT_THROW(waitUntil([&callbackCalled]() { return callbackCalled.load(); }, MAX_INDEXER_PUBLISH_TIME_MS),
                 std::runtime_error);
}
/**
 * @brief Test the connection and posterior discard of invalid JSON.
 *
 */
TEST_F(IndexerConnectorTest, DiscardInvalidJSON)
{
    // Callback function that checks if the callback was executed.
    std::atomic<bool> callbackCalled {false};
    const auto checkCallbackCalled {[&callbackCalled](const std::string& data, std::string& content)
                                    {
                                        std::ignore = data;
                                        callbackCalled = true;
                                        content = DEFAULT_CONTENT;
                                    }};
    m_indexerServers[A_IDX]->setPublishCallback(checkCallbackCalled);

    // Create connector and wait until the connection is established.
    IndexerConnectorOptions indexerConfig {.name = INDEXER_NAME, .hosts = {A_ADDRESS}, .timeout = INDEXER_TIMEOUT};
    auto indexerConnector {IndexerConnector(indexerConfig)};

    // Trigger publication of invalid data.
    std::string invalidData = "This is not valid JSON"; // Invalid JSON string
    ASSERT_NO_THROW(indexerConnector.publish(invalidData));

    // Ensure that the callback is NOT called due to invalid data.
    ASSERT_THROW(waitUntil([&callbackCalled]() { return callbackCalled.load(); }, MAX_INDEXER_PUBLISH_TIME_MS),
                 std::runtime_error);
}

/**
 * @brief Test the connection and posterior double data publication into a server. The published data is checked
 * against the expected one.
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
    const auto checkPublishedData {[&callbackCalled, &publishedData](const std::string& data, std::string& content)
                                   {
                                       const auto splitData {base::utils::string::split(data, '\n')};
                                       nlohmann::json entry;
                                       entry["metadata"] = nlohmann::json::parse(splitData.front());
                                       entry["data"] = nlohmann::json::parse(splitData.back());
                                       publishedData.push_back(std::move(entry));
                                       callbackCalled = true;
                                       content = DEFAULT_CONTENT;
                                   }};
    m_indexerServers[A_IDX]->setPublishCallback(checkPublishedData);

    // Create connector and wait until the connection is established.
    IndexerConnectorOptions indexerConfig {
        .name = INDEXER_NAME, .hosts = {A_ADDRESS}, .timeout = INDEXER_TIMEOUT, .databasePath = DATABASE_BASE_PATH};
    auto indexerConnector {IndexerConnector(indexerConfig)};

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
    const auto forceErrorCallback {[&callbackCalled](const std::string& data, std::string& content)
                                   {
                                       std::ignore = data;
                                       callbackCalled = true;
                                       content = DEFAULT_CONTENT;
                                       throw std::runtime_error {"Forced server error"};
                                   }};
    m_indexerServers[A_IDX]->setPublishCallback(forceErrorCallback);

    // Create connector and wait until the connection is established.
    IndexerConnectorOptions indexerConfig {
        .name = INDEXER_NAME, .hosts = {A_ADDRESS}, .timeout = INDEXER_TIMEOUT, .databasePath = DATABASE_BASE_PATH};
    auto indexerConnector {IndexerConnector(indexerConfig)};

    // Trigger publication and expect that it is not made.
    nlohmann::json publishData;
    publishData["id"] = INDEX_ID_A;
    publishData["operation"] = "DELETED";
    ASSERT_NO_THROW(indexerConnector.publish(publishData.dump()));
    ASSERT_NO_THROW(waitUntil([&callbackCalled]() { return callbackCalled.load(); }, MAX_INDEXER_PUBLISH_TIME_MS));
}

/**
 * @brief Test the initialization with upper case character in the index name.
 *
 */
TEST_F(IndexerConnectorTest, UpperCaseCharactersIndexName)
{
    // Create connector and wait until the connection is established.
    IndexerConnectorOptions indexerConfig {
        .name = "UPPER_case_INDEX", .hosts = {A_ADDRESS}, .timeout = INDEXER_TIMEOUT};

    EXPECT_THROW(IndexerConnector {indexerConfig}, std::invalid_argument);
}

/**
 * @brief Test the connection and posterior data publication into a server. The published data is checked against
 * the expected one.
 *
 */
TEST_F(IndexerConnectorTest, PublishDatePlaceholder)
{
    // We create an index with the current date as part of the name.
    nlohmann::json expectedMetadata;
    std::string indexerName = std::string(INDEXER_NAME) + "_$(date)";
    const std::string indexerNameDatePlaceHolder = indexerName;
    base::utils::string::replaceAll(indexerName, "$(date)", base::utils::time::getCurrentDate("."));
    auto INDEX_NAME_FORMAT_REGEX_STR {std::string(INDEXER_NAME) + "_[0-9]{4}.([0-9]|1[0-2]){2}.(([0-9]|1[0-2]){2})"};
    EXPECT_TRUE(std::regex_match(indexerName, std::regex(INDEX_NAME_FORMAT_REGEX_STR)));

    expectedMetadata["index"]["_index"] = indexerName;
    expectedMetadata["index"]["_id"] = INDEX_ID_A;

    // Callback that checks the expected data to be published.
    // The format of the data published is divided in two lines:
    // First line: JSON data with the metadata (indexer name, index ID)
    // Second line: Index data.
    constexpr auto INDEX_DATA {"content"};
    std::atomic<bool> callbackCalled {false};
    const auto checkPublishedData {
        [&expectedMetadata, &callbackCalled, &INDEX_DATA](const std::string& data, std::string& content)
        {
            const auto splitData {base::utils::string::split(data, '\n')};
            ASSERT_EQ(nlohmann::json::parse(splitData.front()), expectedMetadata);
            ASSERT_EQ(nlohmann::json::parse(splitData.back()), INDEX_DATA);
            callbackCalled = true;
            content = DEFAULT_CONTENT;
        }};
    m_indexerServers[A_IDX]->setPublishCallback(checkPublishedData);

    // Create connector and wait until the connection is established.
    IndexerConnectorOptions indexerConfig {
        .name = indexerNameDatePlaceHolder, .hosts = {A_ADDRESS}, .timeout = INDEXER_TIMEOUT};
    const std::string INDEX_NAME_PLACE_HOLDER_FORMAT_REGEX_STR {std::string(INDEXER_NAME) + R"(_\$\(date\))"};
    EXPECT_TRUE(std::regex_match(indexerNameDatePlaceHolder, std::regex(INDEX_NAME_PLACE_HOLDER_FORMAT_REGEX_STR)));
    auto indexerConnector {IndexerConnector(indexerConfig)};

    // Publish content and wait until the publication finishes.
    nlohmann::json publishData;
    publishData["id"] = INDEX_ID_A;
    publishData["operation"] = "INSERT";
    publishData["data"] = INDEX_DATA;
    ASSERT_NO_THROW(indexerConnector.publish(publishData.dump()));
    ASSERT_NO_THROW(waitUntil([&callbackCalled]() { return callbackCalled.load(); }, MAX_INDEXER_PUBLISH_TIME_MS));
}
