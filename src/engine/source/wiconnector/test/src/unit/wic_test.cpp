// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <mockIndexerClient.hpp>
#include <wiconnector/mockIndexerConnectorAsync.hpp>
#include <wiconnector/windexerconnector.hpp>

#include <base/logging.hpp>
#include <chrono>
#include <filesystem>
#include <keyStore.hpp>
#include <thread>

namespace
{
bool seedIndexerCredentials()
{
    try
    {
        // Keystore::put() opens `queue/keystore` relative to the working directory and creates the
        // store itself, but not the directory above it.
        std::filesystem::create_directories("queue");
        Keystore::put("indexer", "username", "test-user");
        Keystore::put("indexer", "password", "test-password");
        return true;
    }
    catch (const std::exception&)
    {
        return false;
    }
}

/// Seeded before main(): the connector caches the indexer credentials on its first use and throws
/// when they are unset.
const bool g_credentialsSeeded = seedIndexerCredentials();
} // namespace

/// The remote configuration timeout handed to the Client-backed constructor in the RemoteConf* cases.
constexpr std::chrono::milliseconds REMOTE_CONF_REQUEST_TIMEOUT {45000};

/// A two-node health view, every node in @p state with @p reason.
static indexer_client::HealthView healthOf(indexer_client::HealthView::NodeState state, std::string reason)
{
    indexer_client::HealthView view;
    view.nodes.push_back({"http://node-1:9200", state, reason});
    view.nodes.push_back({"http://node-2:9200", state, std::move(reason)});
    return view;
}

class WIndexerConnectorTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        logging::testInit(logging::Level::Debug);
        logFunction = logging::createStandaloneLogFunction();
        client = std::make_shared<::testing::NiceMock<indexer_client::MockClient>>();
        query = std::make_shared<::testing::NiceMock<indexer_client::MockQuery>>();
        ON_CALL(*client, query()).WillByDefault(::testing::Return(query));
        ON_CALL(*client, health())
            .WillByDefault(::testing::Return(healthOf(indexer_client::HealthView::NodeState::Available, "")));
    }

    void TearDown() override
    {
        // Clean up any resources if needed
    }

    /// A connector that writes to a mock and reads through the mock Client (RemoteConf* cases).
    std::unique_ptr<wiconnector::WIndexerConnector> makeReaderConnector()
    {
        return std::make_unique<wiconnector::WIndexerConnector>(
            std::make_unique<::testing::NiceMock<wiconnector::mocks::MockIndexerConnectorAsync>>(),
            client,
            REMOTE_CONF_REQUEST_TIMEOUT);
    }

    void searchAnswers(indexer_client::Outcome<nlohmann::json> outcome)
    {
        EXPECT_CALL(*query, search(::testing::_, ::testing::_, ::testing::_, ::testing::_))
            .WillOnce(::testing::Return(std::move(outcome)));
    }

    wiconnector::LogFunctionType logFunction;
    std::shared_ptr<::testing::NiceMock<indexer_client::MockClient>> client;
    std::shared_ptr<::testing::NiceMock<indexer_client::MockQuery>> query;
};

// Test Config class functionality
class ConfigTest : public ::testing::Test
{
};

TEST_F(ConfigTest, BasicConfigToJson)
{
    wiconnector::Config config;
    config.hosts = {"http://localhost:9200"};

    std::string jsonStr = config.toJson();

    // Verify the JSON contains expected fields
    EXPECT_TRUE(jsonStr.find("\"hosts\"") != std::string::npos);
    EXPECT_TRUE(jsonStr.find("\"max_retry_delay_seconds\"") != std::string::npos);
    EXPECT_TRUE(jsonStr.find("localhost:9200") != std::string::npos);
}

TEST_F(ConfigTest, ConfigWithSSLToJson)
{
    wiconnector::Config config;
    config.hosts = {"https://localhost:9200"};
    config.ssl.cacert = {"/path/to/ca.crt"};
    config.ssl.cert = "/path/to/client.crt";
    config.ssl.key = "/path/to/client.key";

    std::string jsonStr = config.toJson();

    // Verify SSL fields are present
    EXPECT_TRUE(jsonStr.find("\"ssl\"") != std::string::npos);
    EXPECT_TRUE(jsonStr.find("\"certificate_authorities\"") != std::string::npos);
    EXPECT_TRUE(jsonStr.find("\"certificate\"") != std::string::npos);
    EXPECT_TRUE(jsonStr.find("\"key\"") != std::string::npos);
}

TEST_F(ConfigTest, ConfigWithoutCredentialsToJson)
{
    wiconnector::Config config;
    config.hosts = {"http://localhost:9200"};

    std::string jsonStr = config.toJson();

    // Credentials come from the keystore, never from Config
    EXPECT_TRUE(jsonStr.find("\"username\"") == std::string::npos);
    EXPECT_TRUE(jsonStr.find("\"password\"") == std::string::npos);
}

TEST_F(ConfigTest, ConfigDefaultMaxRetryDelayToJson)
{
    wiconnector::Config config;
    config.hosts = {"http://localhost:9200"};

    const auto jsonConfig = nlohmann::json::parse(config.toJson());

    ASSERT_TRUE(jsonConfig.contains("max_retry_delay_seconds"));
    EXPECT_EQ(jsonConfig["max_retry_delay_seconds"].get<std::size_t>(), 15U);
}

TEST_F(ConfigTest, ConfigMaxRetryDelayMaximumValueToJson)
{
    constexpr std::size_t MAX_RETRY_DELAY_SECONDS {3600};

    wiconnector::Config config;
    config.hosts = {"http://localhost:9200"};
    config.maxRetryDelaySeconds = MAX_RETRY_DELAY_SECONDS;

    const auto jsonConfig = nlohmann::json::parse(config.toJson());

    ASSERT_TRUE(jsonConfig.contains("max_retry_delay_seconds"));
    EXPECT_EQ(jsonConfig["max_retry_delay_seconds"].get<std::size_t>(), MAX_RETRY_DELAY_SECONDS);
}

// Test WIndexerConnector construction
TEST_F(WIndexerConnectorTest, ConstructorWithValidConfig)
{
    wiconnector::Config config;
    config.hosts = {"http://localhost:9200"};

    EXPECT_NO_THROW({ wiconnector::WIndexerConnector connector(config, logFunction); });
}

TEST_F(WIndexerConnectorTest, ConstructorWithValidJsonConfig)
{
    std::string validJson = R"({
        "hosts": ["http://localhost:9200"]
    })";

    EXPECT_NO_THROW({ wiconnector::WIndexerConnector connector(validJson); });
}

TEST_F(WIndexerConnectorTest, ConstructorWithEmptyJsonConfig)
{
    std::string emptyJson = "";

    EXPECT_THROW({ wiconnector::WIndexerConnector connector(emptyJson); }, std::runtime_error);
}

TEST_F(WIndexerConnectorTest, ConstructorWithInvalidJsonConfig)
{
    std::string invalidJson = "{ invalid json }";

    EXPECT_THROW({ wiconnector::WIndexerConnector connector(invalidJson); }, std::runtime_error);
}

// Test indexing functionality
TEST_F(WIndexerConnectorTest, IndexValidData)
{
    wiconnector::Config config;
    config.hosts = {"http://localhost:9200"}; // This will likely fail to connect, but that's OK for unit test

    wiconnector::WIndexerConnector connector(config, logFunction);

    // This should not throw, even if connection fails (it logs warnings internally)
    EXPECT_NO_THROW({ connector.index("test-index", R"({"field": "value"})"); });
}

TEST_F(WIndexerConnectorTest, IndexEmptyIndex)
{
    wiconnector::Config config;
    config.hosts = {"http://localhost:9200"};

    wiconnector::WIndexerConnector connector(config, logFunction);

    // Should handle empty index name gracefully
    EXPECT_NO_THROW({ connector.index("", R"({"field": "value"})"); });
}

TEST_F(WIndexerConnectorTest, IndexEmptyData)
{
    wiconnector::Config config;
    config.hosts = {"http://localhost:9200"};

    wiconnector::WIndexerConnector connector(config, logFunction);

    // Should handle empty data gracefully
    EXPECT_NO_THROW({ connector.index("test-index", ""); });
}

// Test shutdown functionality
TEST_F(WIndexerConnectorTest, ShutdownConnector)
{
    wiconnector::Config config;
    config.hosts = {"http://localhost:9200"};

    wiconnector::WIndexerConnector connector(config, logFunction);

    // Shutdown should work without throwing
    EXPECT_NO_THROW({ connector.shutdown(); });

    // After shutdown, indexing should still not throw (but will log debug message)
    EXPECT_NO_THROW({ connector.index("test-index", R"({"field": "value"})"); });
}

// Test thread safety
TEST_F(WIndexerConnectorTest, ConcurrentIndexing)
{
    wiconnector::Config config;
    config.hosts = {"http://localhost:9200"};

    wiconnector::WIndexerConnector connector(config, logFunction);

    std::vector<std::thread> threads;
    const int numThreads = 5;
    const int numOperationsPerThread = 10;

    // Launch multiple threads that index data concurrently
    for (int i = 0; i < numThreads; ++i)
    {
        threads.emplace_back(
            [&connector, numOperationsPerThread, i]()
            {
                for (int j = 0; j < numOperationsPerThread; ++j)
                {
                    std::string data =
                        R"({"thread": )" + std::to_string(i) + R"(, "operation": )" + std::to_string(j) + "}";
                    connector.index("test-index-" + std::to_string(i), data);
                }
            });
    }

    // Wait for all threads to complete
    for (auto& thread : threads)
    {
        thread.join();
    }

    // If we reach here without crashing, thread safety test passed
    SUCCEED();
}

TEST_F(WIndexerConnectorTest, ConcurrentIndexingAndShutdown)
{
    wiconnector::Config config;
    config.hosts = {"http://localhost:9200"};

    wiconnector::WIndexerConnector connector(config, logFunction);

    std::atomic<bool> shouldStop {false};
    std::vector<std::thread> threads;

    // Launch indexing threads
    for (int i = 0; i < 3; ++i)
    {
        threads.emplace_back(
            [&connector, &shouldStop, i]()
            {
                int counter = 0;
                while (!shouldStop.load())
                {
                    std::string data =
                        R"({"thread": )" + std::to_string(i) + R"(, "counter": )" + std::to_string(counter++) + "}";
                    connector.index("test-index", data);
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                }
            });
    }

    // Let threads run for a bit
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Shutdown the connector while threads are running
    EXPECT_NO_THROW({ connector.shutdown(); });

    // Stop the threads
    shouldStop = true;
    for (auto& thread : threads)
    {
        thread.join();
    }

    SUCCEED();
}

// Integration-style test (will be skipped if no real indexer available)
TEST_F(WIndexerConnectorTest, DISABLED_IntegrationTest)
{
    // This test is disabled by default as it requires a real Elasticsearch/OpenSearch instance
    wiconnector::Config config;
    config.hosts = {"http://localhost:9200"};

    wiconnector::WIndexerConnector connector(config, logFunction);

    // Try to index some data
    connector.index("test-integration-index", R"({
        "timestamp": "2025-09-18T10:00:00Z",
        "level": "INFO",
        "message": "Test message from WIndexerConnector integration test",
        "source": "wic_test"
    })");

    // Give some time for async operation
    std::this_thread::sleep_for(std::chrono::seconds(2));

    SUCCEED() << "Integration test completed. Check your indexer for the document.";
}

/****************************************************************************************
 * Mock-backed tests for the indexer-async-facing methods.
 *
 ****************************************************************************************/

using ::testing::_;
using ::testing::An;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::Throw;

class WIndexerConnectorMockTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        logging::testInit(logging::Level::Debug);
        mockOwned = std::make_unique<NiceMock<wiconnector::mocks::MockIndexerConnectorAsync>>();
        mock = mockOwned.get();
    }

    /// Build the connector.
    std::unique_ptr<wiconnector::WIndexerConnector> makeConnector()
    {
        return std::make_unique<wiconnector::WIndexerConnector>(std::move(mockOwned));
    }

    std::unique_ptr<NiceMock<wiconnector::mocks::MockIndexerConnectorAsync>> mockOwned;
    NiceMock<wiconnector::mocks::MockIndexerConnectorAsync>* mock {nullptr};
};

/**************************
 * getQueueSize / getDroppedEvents
 **************************/
TEST_F(WIndexerConnectorMockTest, GetQueueSizeForwardsToBackend)
{
    EXPECT_CALL(*mock, getQueueSize()).WillOnce(Return(uint64_t {42}));
    auto connector = makeConnector();
    EXPECT_EQ(connector->getQueueSize(), 42U);
}

TEST_F(WIndexerConnectorMockTest, GetQueueSizeReturnsZeroAfterShutdown)
{
    auto connector = makeConnector();
    connector->shutdown();
    EXPECT_EQ(connector->getQueueSize(), 0U);
}

TEST_F(WIndexerConnectorMockTest, GetDroppedEventsForwardsToBackend)
{
    EXPECT_CALL(*mock, getDroppedEvents()).WillOnce(Return(uint64_t {7}));
    auto connector = makeConnector();
    EXPECT_EQ(connector->getDroppedEvents(), 7U);
}

TEST_F(WIndexerConnectorMockTest, GetDroppedEventsReturnsZeroAfterShutdown)
{
    auto connector = makeConnector();
    connector->shutdown();
    EXPECT_EQ(connector->getDroppedEvents(), 0U);
}

/**************************
 * index()
 **************************/
TEST_F(WIndexerConnectorMockTest, IndexSwallowsIndexerConnectorException)
{
    EXPECT_CALL(*mock, indexDataStream(_, _)).WillOnce(Throw(IndexerConnectorException("boom")));
    auto connector = makeConnector();
    EXPECT_NO_THROW(connector->index("idx", R"({"a":1})"));
}

TEST_F(WIndexerConnectorMockTest, IndexSwallowsStdException)
{
    EXPECT_CALL(*mock, indexDataStream(_, _)).WillOnce(Throw(std::runtime_error("oops")));
    auto connector = makeConnector();
    EXPECT_NO_THROW(connector->index("idx", R"({"a":1})"));
}

/**************************
 * getEngineRemoteConfig
 **************************/
TEST_F(WIndexerConnectorMockTest, GetEngineRemoteConfigHappyPath)
{
    nlohmann::json hits = {{"total", {{"value", 1}}},
                           {"hits", {{{"_source", {{"engine", {{"index_raw_events", false}}}}}}}}};
    EXPECT_CALL(*mock, search(An<std::string_view>(), 1U, _, _)).WillOnce(Return(hits));

    auto connector = makeConnector();
    auto cfg = connector->getEngineRemoteConfig();
    EXPECT_TRUE(cfg.isObject());
}

TEST_F(WIndexerConnectorMockTest, GetEngineRemoteConfigZeroHitsThrows)
{
    nlohmann::json hits = {{"total", {{"value", 0}}}, {"hits", nlohmann::json::array()}};
    EXPECT_CALL(*mock, search(An<std::string_view>(), 1U, _, _)).WillOnce(Return(hits));
    auto connector = makeConnector();
    EXPECT_THROW(connector->getEngineRemoteConfig(), IndexerConnectorException);
}

TEST_F(WIndexerConnectorMockTest, GetEngineRemoteConfigMultipleHitsThrows)
{
    nlohmann::json hits = {
        {"total", {{"value", 2}}},
        {"hits", {{{"_source", {{"engine", {{"a", 1}}}}}}, {{"_source", {{"engine", {{"b", 2}}}}}}}}};
    EXPECT_CALL(*mock, search(An<std::string_view>(), 1U, _, _)).WillOnce(Return(hits));
    auto connector = makeConnector();
    EXPECT_THROW(connector->getEngineRemoteConfig(), IndexerConnectorException);
}

TEST_F(WIndexerConnectorMockTest, GetEngineRemoteConfigMissingEngineThrows)
{
    nlohmann::json hits = {{"total", {{"value", 1}}}, {"hits", {{{"_source", {{"other", "value"}}}}}}};
    EXPECT_CALL(*mock, search(An<std::string_view>(), 1U, _, _)).WillOnce(Return(hits));
    auto connector = makeConnector();
    EXPECT_THROW(connector->getEngineRemoteConfig(), IndexerConnectorException);
}

TEST_F(WIndexerConnectorMockTest, GetEngineRemoteConfigEngineNotObjectThrows)
{
    nlohmann::json hits = {{"total", {{"value", 1}}}, {"hits", {{{"_source", {{"engine", "not-an-object"}}}}}}};
    EXPECT_CALL(*mock, search(An<std::string_view>(), 1U, _, _)).WillOnce(Return(hits));
    auto connector = makeConnector();
    EXPECT_THROW(connector->getEngineRemoteConfig(), IndexerConnectorException);
}

TEST_F(WIndexerConnectorMockTest, GetEngineRemoteConfigAfterShutdownThrows)
{
    auto connector = makeConnector();
    connector->shutdown();
    EXPECT_THROW(connector->getEngineRemoteConfig(), std::runtime_error);
}

/****************************************************************************************
 * getEngineRemoteConfig through the engine's indexer_client Client (E10a)
 ****************************************************************************************/

using ::testing::Invoke;
using ::testing::SaveArg;

namespace
{
nlohmann::json responseWith(nlohmann::json hits)
{
    return {{"took", 1}, {"timed_out", false}, {"hits", std::move(hits)}};
}
} // namespace

TEST_F(WIndexerConnectorTest, RemoteConfReadsThroughTheClient)
{
    std::string index;
    nlohmann::json body;
    indexer_client::QueryOptions options;
    indexer_client::Deadline deadline;
    const auto before = std::chrono::steady_clock::now();
    EXPECT_CALL(*query, search(_, _, _, _))
        .WillOnce(Invoke(
            [&](std::string_view i,
                const nlohmann::json& b,
                const indexer_client::QueryOptions& o,
                indexer_client::Deadline d)
            {
                index = i;
                body = b;
                options = o;
                deadline = d;
                return indexer_client::Outcome<nlohmann::json>::success(
                    responseWith({{"total", {{"value", 1}, {"relation", "eq"}}},
                                  {"hits", {{{"_source", {{"engine", {{"index_raw_events", true}}}}}}}}}));
            }));

    auto connector = makeReaderConnector();
    const auto cfg = connector->getEngineRemoteConfig();
    EXPECT_EQ(cfg.getBool("/index_raw_events"), true);

    // The v1 body, unchanged.
    EXPECT_EQ(index, ".wazuh-settings");
    const nlohmann::json expected = {{"size", 1},
                                     {"track_total_hits", true},
                                     {"stored_fields", nlohmann::json::array()},
                                     {"query", {{"match_all", nlohmann::json::object()}}},
                                     {"_source", {{"includes", {"engine"}}, {"excludes", nlohmann::json::array()}}}};
    EXPECT_EQ(body, expected);

    // One attempt; the page bounded by the request timeout; the call a margin above it.
    ASSERT_TRUE(options.retry.maxAttempts.has_value());
    EXPECT_EQ(*options.retry.maxAttempts, 1U);
    EXPECT_EQ(options.pageDeadline, REMOTE_CONF_REQUEST_TIMEOUT);
    EXPECT_GT(deadline, before + REMOTE_CONF_REQUEST_TIMEOUT);
    EXPECT_LE(deadline, std::chrono::steady_clock::now() + REMOTE_CONF_REQUEST_TIMEOUT + std::chrono::seconds(10));
}

TEST_F(WIndexerConnectorTest, RemoteConfZeroHitsThrows)
{
    searchAnswers(indexer_client::Outcome<nlohmann::json>::success(
        responseWith({{"total", {{"value", 0}}}, {"hits", nlohmann::json::array()}})));
    auto connector = makeReaderConnector();
    EXPECT_THROW(connector->getEngineRemoteConfig(), IndexerConnectorException);
}

TEST_F(WIndexerConnectorTest, RemoteConfMultipleHitsThrows)
{
    searchAnswers(indexer_client::Outcome<nlohmann::json>::success(
        responseWith({{"total", {{"value", 2}}},
                      {"hits", {{{"_source", {{"engine", {{"a", 1}}}}}}, {{"_source", {{"engine", {{"b", 2}}}}}}}}})));
    auto connector = makeReaderConnector();
    EXPECT_THROW(connector->getEngineRemoteConfig(), IndexerConnectorException);
}

TEST_F(WIndexerConnectorTest, RemoteConfMissingEngineThrows)
{
    searchAnswers(indexer_client::Outcome<nlohmann::json>::success(
        responseWith({{"total", {{"value", 1}}}, {"hits", {{{"_source", {{"other", "value"}}}}}}})));
    auto connector = makeReaderConnector();
    EXPECT_THROW(connector->getEngineRemoteConfig(), IndexerConnectorException);
}

TEST_F(WIndexerConnectorTest, RemoteConfResponseWithoutHitsThrows)
{
    searchAnswers(indexer_client::Outcome<nlohmann::json>::success(nlohmann::json {{"took", 1}}));
    auto connector = makeReaderConnector();
    EXPECT_THROW(connector->getEngineRemoteConfig(), IndexerConnectorException);
}

TEST_F(WIndexerConnectorTest, RemoteConfFailureThrowsWithTheCause)
{
    searchAnswers(indexer_client::Outcome<nlohmann::json>::failure(
        indexer_client::Cause::NotFound, "index_not_found_exception", 404));
    auto connector = makeReaderConnector();
    try
    {
        connector->getEngineRemoteConfig();
        FAIL() << "expected an exception";
    }
    catch (const IndexerConnectorException& e)
    {
        EXPECT_NE(std::string {e.what()}.find("not_found"), std::string::npos) << e.what();
    }
}

TEST_F(WIndexerConnectorTest, RemoteConfClientClosedThrows)
{
    // A search cut by requestClose() is a failure, never "no remote configuration".
    searchAnswers(indexer_client::Outcome<nlohmann::json>::failure(indexer_client::Cause::ClientClosed, "closed"));
    auto connector = makeReaderConnector();
    EXPECT_THROW(connector->getEngineRemoteConfig(), IndexerConnectorException);
}

TEST_F(WIndexerConnectorTest, RemoteConfClosedClientThrowsWithoutSearching)
{
    EXPECT_CALL(*client, query()).WillOnce(Return(nullptr));
    EXPECT_CALL(*query, search(_, _, _, _)).Times(0);
    auto connector = makeReaderConnector();
    try
    {
        connector->getEngineRemoteConfig();
        FAIL() << "expected an exception";
    }
    catch (const IndexerConnectorException& e)
    {
        EXPECT_NE(std::string {e.what()}.find("client_closed"), std::string::npos) << e.what();
    }
}

TEST_F(WIndexerConnectorTest, RemoteConfNoUsableNodeFailsAtOnce)
{
    ON_CALL(*client, health())
        .WillByDefault(Return(healthOf(indexer_client::HealthView::NodeState::Down, "connect: refused")));
    EXPECT_CALL(*query, search(_, _, _, _)).Times(0);
    auto connector = makeReaderConnector();

    const auto t0 = std::chrono::steady_clock::now();
    EXPECT_THROW(connector->getEngineRemoteConfig(), IndexerConnectorException);
    EXPECT_LT(std::chrono::steady_clock::now() - t0, std::chrono::milliseconds(100));
}

TEST_F(WIndexerConnectorTest, RemoteConfWaitsForTheFirstProbe)
{
    // Before the first probe round every node is Down without a reason: the call goes to the library, which waits.
    ON_CALL(*client, health()).WillByDefault(Return(healthOf(indexer_client::HealthView::NodeState::Down, "")));
    searchAnswers(indexer_client::Outcome<nlohmann::json>::success(
        responseWith({{"total", {{"value", 1}}}, {"hits", {{{"_source", {{"engine", nlohmann::json::object()}}}}}}})));
    auto connector = makeReaderConnector();
    EXPECT_NO_THROW(connector->getEngineRemoteConfig());
}

TEST_F(WIndexerConnectorTest, RemoteConfWaitBeforeTheFirstProbeIsCapped)
{
    // Before the first probe round the wait for a node is capped like the content adapter's probeDeadline (I158b),
    // so one read does not hold a scheduler thread for a whole request timeout (45 s here).
    ON_CALL(*client, health()).WillByDefault(Return(healthOf(indexer_client::HealthView::NodeState::Down, "")));
    indexer_client::Deadline deadline;
    const auto before = std::chrono::steady_clock::now();
    EXPECT_CALL(*query, search(_, _, _, _))
        .WillOnce(Invoke(
            [&](std::string_view,
                const nlohmann::json&,
                const indexer_client::QueryOptions&,
                indexer_client::Deadline d)
            {
                deadline = d;
                return indexer_client::Outcome<nlohmann::json>::success(responseWith(
                    {{"total", {{"value", 1}}}, {"hits", {{{"_source", {{"engine", nlohmann::json::object()}}}}}}}));
            }));
    auto connector = makeReaderConnector();
    EXPECT_NO_THROW(connector->getEngineRemoteConfig());
    EXPECT_LE(deadline - before, std::chrono::milliseconds {10000} + std::chrono::milliseconds {500});
}

TEST_F(WIndexerConnectorTest, RemoteConfAfterShutdownThrows)
{
    auto connector = makeReaderConnector();
    connector->shutdown();
    EXPECT_CALL(*query, search(_, _, _, _)).Times(0);
    EXPECT_THROW(connector->getEngineRemoteConfig(), std::runtime_error);
    EXPECT_EQ(client.use_count(), 1); // shutdown() released the Client.
}

TEST_F(WIndexerConnectorTest, RemoteConfNullReaderIsRejected)
{
    EXPECT_THROW(
        wiconnector::WIndexerConnector(std::make_unique<NiceMock<wiconnector::mocks::MockIndexerConnectorAsync>>(),
                                       nullptr,
                                       REMOTE_CONF_REQUEST_TIMEOUT),
        std::runtime_error);
}
