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
#include <atomic>
#include <chrono>
#include <filesystem>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>

// Indexer server addresses.
static const std::string INDEXER_HOSTNAME {"localhost"};
static const auto INDEXER_NAME {"indexer_connector_test"};

static const auto A_IDX {0};
static const auto A_PORT {9999};
static const auto A_ADDRESS {INDEXER_HOSTNAME + ":" + std::to_string(A_PORT)};

static const auto B_IDX {1};
static const auto B_PORT {8888};
static const auto B_ADDRESS {INDEXER_HOSTNAME + ":" + std::to_string(B_PORT)};

static const auto C_IDX {2};
static const auto C_PORT {7777};
static const auto C_ADDRESS {INDEXER_HOSTNAME + ":" + std::to_string(C_PORT)};

// The async dispatcher flushes after FlushInterval (default 20s) when the bulk
// hasn't reached ElementsPerBulk.  Allow a comfortable margin above that.
static const auto MAX_ASYNC_PUBLISH_TIME_MS {25000};

void IndexerConnectorTest::SetUp()
{
    m_indexerServers.push_back(std::make_unique<FakeIndexer>(INDEXER_HOSTNAME, A_PORT, "green", INDEXER_NAME));
    m_indexerServers.push_back(std::make_unique<FakeIndexer>(INDEXER_HOSTNAME, B_PORT, "red", INDEXER_NAME));
    m_indexerServers.push_back(std::make_unique<FakeIndexer>(INDEXER_HOSTNAME, C_PORT, "red", INDEXER_NAME));

    for (auto& server : m_indexerServers)
    {
        server->start();
    }
}

void IndexerConnectorTest::TearDown()
{
    const auto QUEUE_FOLDER {std::filesystem::current_path() / "queue"};
    std::filesystem::remove_all(QUEUE_FOLDER);

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

// ─── IndexerConnectorSync connection tests ────────────────────────────────────

/**
 * @brief Health check is synchronous in the constructor.
 * A green server is immediately visible as available after construction.
 */
TEST_F(IndexerConnectorTest, SyncConnectionAvailableServer)
{
    nlohmann::json config;
    config["hosts"] = nlohmann::json::array({A_ADDRESS});

    IndexerConnectorSync connector(config);
    ASSERT_TRUE(connector.isAvailable());
}

/**
 * @brief A red server is immediately seen as unavailable after construction.
 */
TEST_F(IndexerConnectorTest, SyncConnectionUnavailableServer)
{
    nlohmann::json config;
    config["hosts"] = nlohmann::json::array({B_ADDRESS});

    IndexerConnectorSync connector(config);
    ASSERT_FALSE(connector.isAvailable());
}

/**
 * @brief A host that accepts no connections is treated as unavailable.
 */
TEST_F(IndexerConnectorTest, SyncConnectionInvalidServer)
{
    constexpr auto NONEXISTENT_SERVER {"localhost:6789"};
    nlohmann::json config;
    config["hosts"] = nlohmann::json::array({NONEXISTENT_SERVER});

    IndexerConnectorSync connector(config);
    ASSERT_FALSE(connector.isAvailable());
}

/**
 * @brief When several servers are listed, the connector is available as long
 * as at least one of them responds with green/yellow health.
 */
TEST_F(IndexerConnectorTest, SyncConnectionMultipleServersSelectsHealthy)
{
    m_indexerServers[A_IDX]->setHealth("red");
    m_indexerServers[B_IDX]->setHealth("red");
    m_indexerServers[C_IDX]->setHealth("green");

    nlohmann::json config;
    config["hosts"] = nlohmann::json::array({A_ADDRESS, B_ADDRESS, C_ADDRESS});

    IndexerConnectorSync connector(config);
    ASSERT_TRUE(connector.isAvailable());
}

/**
 * @brief Username / password in the config is accepted without errors.
 * (Coverage test — credentials are not verified by the fake indexer.)
 */
TEST_F(IndexerConnectorTest, SyncConnectionWithUserAndPassword)
{
    nlohmann::json config;
    config["hosts"] = nlohmann::json::array({A_ADDRESS});
    config["username"] = "user";
    config["password"] = "password";

    IndexerConnectorSync connector(config);
    ASSERT_TRUE(connector.isAvailable());
}

/**
 * @brief SSL credential paths in the config are accepted without errors.
 * (Coverage test — the fake indexer does not enforce TLS.)
 */
TEST_F(IndexerConnectorTest, SyncConnectionWithSslCredentials)
{
    nlohmann::json config;
    config["hosts"] = nlohmann::json::array({A_ADDRESS});
    config["ssl"]["certificate_authorities"] = nlohmann::json::array({"/var/wazuh-manager/etc/certs/root-ca.pem"});
    config["ssl"]["certificate"] = "/var/wazuh-manager/etc/certs/manager.pem";
    config["ssl"]["key"] = "/var/wazuh-manager/etc/certs/manager-key.pem";

    // SSL paths don't exist, but the connector only validates them when actually
    // connecting over TLS; the health check to the plain-HTTP fake indexer passes.
    IndexerConnectorSync connector(config);
    ASSERT_TRUE(connector.isAvailable());
}

// ─── IndexerConnectorSync bulk-operation tests ────────────────────────────────

/**
 * @brief bulkIndex followed by flush sends a correctly formatted NDJSON bulk
 * request to the /_bulk endpoint.
 */
TEST_F(IndexerConnectorTest, SyncBulkIndexAndFlush)
{
    std::atomic<bool> bulkReceived {false};
    std::string receivedBody;

    m_indexerServers[A_IDX]->setPublishCallback(
        [&](const std::string& body)
        {
            receivedBody = body;
            bulkReceived = true;
        });

    nlohmann::json config;
    config["hosts"] = nlohmann::json::array({A_ADDRESS});
    IndexerConnectorSync connector(config);

    constexpr auto INDEX_NAME {"test_index"};
    constexpr auto DOC_ID {"doc_001"};
    constexpr auto DOC_DATA {R"({"field":"value"})"};

    connector.bulkIndex(DOC_ID, INDEX_NAME, DOC_DATA);
    ASSERT_NO_THROW(connector.flush());

    ASSERT_TRUE(bulkReceived);

    const auto lines = Utils::split(receivedBody, '\n');
    ASSERT_GE(lines.size(), 2u);

    const auto meta = nlohmann::json::parse(lines[0]);
    ASSERT_EQ(meta["index"]["_index"], INDEX_NAME);
    ASSERT_EQ(meta["index"]["_id"], DOC_ID);
    ASSERT_EQ(nlohmann::json::parse(lines[1]), nlohmann::json::parse(DOC_DATA));
}

/**
 * @brief bulkDelete followed by flush sends a correctly formatted NDJSON delete
 * line to the /_bulk endpoint.
 */
TEST_F(IndexerConnectorTest, SyncBulkDeleteAndFlush)
{
    std::atomic<bool> bulkReceived {false};
    std::string receivedBody;

    m_indexerServers[A_IDX]->setPublishCallback(
        [&](const std::string& body)
        {
            receivedBody = body;
            bulkReceived = true;
        });

    nlohmann::json config;
    config["hosts"] = nlohmann::json::array({A_ADDRESS});
    IndexerConnectorSync connector(config);

    constexpr auto INDEX_NAME {"test_index"};
    constexpr auto DOC_ID {"doc_001"};

    connector.bulkDelete(DOC_ID, INDEX_NAME);
    ASSERT_NO_THROW(connector.flush());

    ASSERT_TRUE(bulkReceived);

    const auto lines = Utils::split(receivedBody, '\n');
    ASSERT_GE(lines.size(), 1u);

    const auto meta = nlohmann::json::parse(lines[0]);
    ASSERT_EQ(meta["delete"]["_index"], INDEX_NAME);
    ASSERT_EQ(meta["delete"]["_id"], DOC_ID);
}

/**
 * @brief deleteByQuery followed by flush posts the aggregated query JSON to the
 * /{index}/_delete_by_query endpoint.
 */
TEST_F(IndexerConnectorTest, SyncDeleteByQueryAndFlush)
{
    std::atomic<bool> callbackCalled {false};
    std::string receivedBody;

    m_indexerServers[A_IDX]->setPublishCallback(
        [&](const std::string& body)
        {
            receivedBody = body;
            callbackCalled = true;
        });

    nlohmann::json config;
    config["hosts"] = nlohmann::json::array({A_ADDRESS});
    IndexerConnectorSync connector(config);

    const std::string agentId {"001"};
    connector.deleteByQuery(INDEXER_NAME, agentId);
    ASSERT_NO_THROW(connector.flush());

    ASSERT_TRUE(callbackCalled);

    const auto body = nlohmann::json::parse(receivedBody);
    ASSERT_EQ(body["query"]["bool"]["filter"]["terms"]["wazuh.agent.id"], nlohmann::json::array({agentId}));
}

/**
 * @brief IDs containing characters that require JSON escaping (control bytes,
 * backslashes, double quotes) are transmitted correctly over real HTTP so that
 * the server receives a valid, parseable bulk line.
 */
TEST_F(IndexerConnectorTest, SyncBulkIndexSpecialCharactersInId)
{
    const std::vector<std::string> specialIds {
        "test\x04id",
        "DOMAIN\\group",
        "test\"id",
    };

    nlohmann::json config;
    config["hosts"] = nlohmann::json::array({A_ADDRESS});
    IndexerConnectorSync connector(config);

    for (const auto& id : specialIds)
    {
        std::atomic<bool> bulkReceived {false};
        std::string receivedBody;

        m_indexerServers[A_IDX]->setPublishCallback(
            [&](const std::string& body)
            {
                receivedBody = body;
                bulkReceived = true;
            });

        connector.bulkIndex(id, INDEXER_NAME, R"({"data":"value"})");
        ASSERT_NO_THROW(connector.flush());

        ASSERT_TRUE(bulkReceived) << "No bulk received for id: " << id;

        const auto lines = Utils::split(receivedBody, '\n');
        ASSERT_GE(lines.size(), 2u);

        // The meta line must parse as valid JSON and carry the original ID.
        ASSERT_NO_THROW({
            const auto meta = nlohmann::json::parse(lines[0]);
            ASSERT_EQ(meta["index"]["_id"].get<std::string>(), id);
        }) << "Meta JSON unparseable for id: "
           << id;
    }
}

/**
 * @brief flush throws when the only available server returns a 500 error for
 * the bulk request.
 */
TEST_F(IndexerConnectorTest, SyncFlushThrowsOnServerError)
{
    m_indexerServers[A_IDX]->setPublishCallback([](const std::string&)
                                                { throw std::runtime_error {"Forced server error"}; });

    nlohmann::json config;
    config["hosts"] = nlohmann::json::array({A_ADDRESS});
    IndexerConnectorSync connector(config);

    connector.bulkIndex("id1", INDEXER_NAME, R"({"x":1})");
    ASSERT_THROW(connector.flush(), std::exception);
}

/**
 * @brief flush throws when no server is reachable (all servers are red).
 */
TEST_F(IndexerConnectorTest, SyncFlushThrowsOnUnavailableServer)
{
    nlohmann::json config;
    config["hosts"] = nlohmann::json::array({B_ADDRESS}); // red

    IndexerConnectorSync connector(config);
    ASSERT_FALSE(connector.isAvailable());

    connector.bulkIndex("id1", INDEXER_NAME, R"({"x":1})");
    ASSERT_THROW(connector.flush(), std::exception);
}

/**
 * @brief Multiple bulk operations in a single flush are all delivered in one
 * POST body in NDJSON format.
 */
TEST_F(IndexerConnectorTest, SyncBulkMultipleOperationsInOneFlush)
{
    std::atomic<bool> bulkReceived {false};
    std::string receivedBody;

    m_indexerServers[A_IDX]->setPublishCallback(
        [&](const std::string& body)
        {
            receivedBody = body;
            bulkReceived = true;
        });

    nlohmann::json config;
    config["hosts"] = nlohmann::json::array({A_ADDRESS});
    IndexerConnectorSync connector(config);

    connector.bulkIndex("id_a", INDEXER_NAME, R"({"val":"a"})");
    connector.bulkIndex("id_b", INDEXER_NAME, R"({"val":"b"})");
    connector.bulkDelete("id_c", INDEXER_NAME);
    ASSERT_NO_THROW(connector.flush());

    ASSERT_TRUE(bulkReceived);

    // Three operations → at least 3 NDJSON lines (index has 2 lines each, delete 1)
    const auto lines = Utils::split(receivedBody, '\n');
    ASSERT_GE(lines.size(), 3u);

    const auto meta0 = nlohmann::json::parse(lines[0]);
    ASSERT_EQ(meta0["index"]["_id"], "id_a");

    const auto meta2 = nlohmann::json::parse(lines[2]);
    ASSERT_EQ(meta2["index"]["_id"], "id_b");

    const auto meta4 = nlohmann::json::parse(lines[4]);
    ASSERT_EQ(meta4["delete"]["_id"], "id_c");
}

// ─── IndexerConnectorAsync tests ─────────────────────────────────────────────

/**
 * @brief index() enqueues data that is eventually dispatched as a valid NDJSON
 * bulk POST to the /_bulk endpoint.
 */
TEST_F(IndexerConnectorTest, AsyncIndexDispatchesToBulk)
{
    std::atomic<bool> bulkReceived {false};
    std::string receivedBody;

    m_indexerServers[A_IDX]->setPublishCallback(
        [&](const std::string& body)
        {
            receivedBody = body;
            bulkReceived = true;
        });

    nlohmann::json config;
    config["hosts"] = nlohmann::json::array({A_ADDRESS});

    {
        IndexerConnectorAsync connector(config, "component_test");
        connector.index("doc_async", INDEXER_NAME, R"({"async":true})");

        ASSERT_NO_THROW(waitUntil([&bulkReceived]() { return bulkReceived.load(); }, MAX_ASYNC_PUBLISH_TIME_MS));
    }

    const auto lines = Utils::split(receivedBody, '\n');
    ASSERT_GE(lines.size(), 2u);

    const auto meta = nlohmann::json::parse(lines[0]);
    ASSERT_EQ(meta["index"]["_index"], INDEXER_NAME);
    ASSERT_EQ(meta["index"]["_id"], "doc_async");
}

/**
 * @brief When the server is unavailable, async index() does not deliver data
 * (the queue is drained on destruction without successful publish).
 */
TEST_F(IndexerConnectorTest, AsyncIndexUnavailableServer)
{
    std::atomic<bool> bulkReceived {false};

    m_indexerServers[B_IDX]->setPublishCallback([&](const std::string&) { bulkReceived = true; });

    nlohmann::json config;
    config["hosts"] = nlohmann::json::array({B_ADDRESS}); // red

    {
        IndexerConnectorAsync connector(config, "component_test_unavail");
        connector.index("doc1", INDEXER_NAME, R"({"x":1})");
        // Give the dispatcher a moment to attempt delivery.
        ASSERT_THROW(waitUntil([&bulkReceived]() { return bulkReceived.load(); }, MAX_ASYNC_PUBLISH_TIME_MS),
                     std::runtime_error);
    }

    ASSERT_FALSE(bulkReceived);
}
