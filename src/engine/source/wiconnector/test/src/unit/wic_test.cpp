// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <wiconnector/mockIndexerConnectorAsync.hpp>
#include <wiconnector/windexerconnector.hpp>

#include <algorithm>
#include <base/logging.hpp>
#include <base/utils/generator.hpp>
#include <cctype>
#include <chrono>
#include <filesystem>
#include <keyStore.hpp>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "indexerConnectorAsyncAdapter.hpp"

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

class WIndexerConnectorTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        logging::testInit(logging::Level::Debug);
        logFunction = logging::createStandaloneLogFunction();
    }

    void TearDown() override
    {
        // Clean up any resources if needed
    }

    wiconnector::LogFunctionType logFunction;
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
using ::testing::Invoke;
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
 * getQueueSize / getDroppedEvents / getRequeuedEvents
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

TEST_F(WIndexerConnectorMockTest, GetRequeuedEventsForwardsToBackend)
{
    EXPECT_CALL(*mock, getRequeuedEvents()).WillOnce(Return(uint64_t {5}));
    auto connector = makeConnector();
    EXPECT_EQ(connector->getRequeuedEvents(), 5U);
}

TEST_F(WIndexerConnectorMockTest, GetRequeuedEventsReturnsZeroAfterShutdown)
{
    auto connector = makeConnector();
    connector->shutdown();
    EXPECT_EQ(connector->getRequeuedEvents(), 0U);
}

TEST_F(WIndexerConnectorMockTest, GetDeduplicatedEventsForwardsToBackend)
{
    EXPECT_CALL(*mock, getDeduplicatedEvents()).WillOnce(Return(uint64_t {5}));
    ON_CALL(*mock, getDroppedEvents()).WillByDefault(Return(uint64_t {7}));
    auto connector = makeConnector();
    EXPECT_EQ(connector->getDeduplicatedEvents(), 5U);
}

TEST_F(WIndexerConnectorMockTest, GetDeduplicatedEventsReturnsZeroAfterShutdown)
{
    auto connector = makeConnector();
    connector->shutdown();
    EXPECT_EQ(connector->getDeduplicatedEvents(), 0U);
}

/**************************
 * index()
 **************************/
TEST_F(WIndexerConnectorMockTest, IndexSwallowsIndexerConnectorException)
{
    EXPECT_CALL(*mock, indexDataStream(_, _, _)).WillOnce(Throw(IndexerConnectorException("boom")));
    auto connector = makeConnector();
    EXPECT_NO_THROW(connector->index("idx", R"({"a":1})"));
}

TEST_F(WIndexerConnectorMockTest, IndexSwallowsStdException)
{
    EXPECT_CALL(*mock, indexDataStream(_, _, _)).WillOnce(Throw(std::runtime_error("oops")));
    auto connector = makeConnector();
    EXPECT_NO_THROW(connector->index("idx", R"({"a":1})"));
}

namespace
{
struct IdCapture
{
    std::mutex mtx;
    std::vector<std::string> ids;
    std::vector<std::string> indices;
    std::vector<std::string> datas;
};

bool isValidDocId(const std::string& id)
{
    if (id.size() != base::utils::generators::DOC_ID_LENGTH)
    {
        return false;
    }
    return std::all_of(
        id.begin(), id.end(), [](unsigned char c) { return std::isalnum(c) != 0 || c == '_' || c == '-'; });
}

int failingRand(unsigned char*, int)
{
    return 0;
}

// Restores the previous random source when the test ends.
class DocIdRandSourceGuard
{
public:
    explicit DocIdRandSourceGuard(base::utils::generators::detail::RandBytesFn fn)
        : m_previous(base::utils::generators::detail::exchangeRandBytesForTesting(fn))
    {
    }

    ~DocIdRandSourceGuard() { base::utils::generators::detail::exchangeRandBytesForTesting(m_previous); }

    DocIdRandSourceGuard(const DocIdRandSourceGuard&) = delete;
    DocIdRandSourceGuard& operator=(const DocIdRandSourceGuard&) = delete;

private:
    base::utils::generators::detail::RandBytesFn m_previous;
};
} // namespace

TEST_F(WIndexerConnectorMockTest, IndexGeneratesDistinctIdPerCall)
{
    IdCapture cap;
    ON_CALL(*mock, indexDataStream(_, _, _))
        .WillByDefault(Invoke(
            [&cap](std::string_view index, std::string_view id, std::string_view data)
            {
                std::lock_guard<std::mutex> lock(cap.mtx);
                cap.indices.emplace_back(index);
                cap.ids.emplace_back(id);
                cap.datas.emplace_back(data);
            }));
    auto connector = makeConnector();
    const std::string body = R"({"a":1})";
    connector->index("idx", body);
    connector->index("idx", body);

    ASSERT_EQ(cap.ids.size(), 2U);
    EXPECT_EQ(cap.indices[0], "idx");
    EXPECT_EQ(cap.indices[1], "idx");
    EXPECT_EQ(cap.datas[0], body);
    EXPECT_EQ(cap.datas[1], body);
    EXPECT_NE(cap.ids[0], cap.ids[1]);
}

TEST_F(WIndexerConnectorMockTest, IndexPassesDocIdFormat)
{
    IdCapture cap;
    ON_CALL(*mock, indexDataStream(_, _, _))
        .WillByDefault(Invoke(
            [&cap](std::string_view, std::string_view id, std::string_view)
            {
                std::lock_guard<std::mutex> lock(cap.mtx);
                cap.ids.emplace_back(id);
            }));
    auto connector = makeConnector();
    connector->index("idx", R"({"a":1})");

    ASSERT_EQ(cap.ids.size(), 1U);
    EXPECT_EQ(cap.ids[0].size(), 27U);
    EXPECT_TRUE(isValidDocId(cap.ids[0])) << cap.ids[0];
}

TEST_F(WIndexerConnectorMockTest, IndexIdsUniqueAcrossThreads)
{
    constexpr int kThreads = 4;
    constexpr int kPerThread = 250;
    IdCapture cap;
    ON_CALL(*mock, indexDataStream(_, _, _))
        .WillByDefault(Invoke(
            [&cap](std::string_view, std::string_view id, std::string_view)
            {
                std::lock_guard<std::mutex> lock(cap.mtx);
                cap.ids.emplace_back(id);
            }));
    auto connector = makeConnector();

    std::vector<std::thread> threads;
    for (int t = 0; t < kThreads; ++t)
    {
        threads.emplace_back(
            [&connector]()
            {
                for (int i = 0; i < kPerThread; ++i)
                {
                    connector->index("idx", R"({"a":1})");
                }
            });
    }
    for (auto& th : threads)
    {
        th.join();
    }

    ASSERT_EQ(cap.ids.size(), static_cast<size_t>(kThreads * kPerThread));
    std::sort(cap.ids.begin(), cap.ids.end());
    EXPECT_EQ(std::adjacent_find(cap.ids.begin(), cap.ids.end()), cap.ids.end());
}

TEST_F(WIndexerConnectorMockTest, IndexDropsEventWhenIdGenerationFails)
{
    IdCapture cap;
    ON_CALL(*mock, indexDataStream(_, _, _))
        .WillByDefault(Invoke(
            [&cap](std::string_view, std::string_view id, std::string_view)
            {
                std::lock_guard<std::mutex> lock(cap.mtx);
                cap.ids.emplace_back(id);
            }));
    auto connector = makeConnector();

    size_t afterFirst = 0;
    // A new thread has no per-thread prefix yet, so the failing source makes generateDocId() throw.
    std::thread worker(
        [&]()
        {
            {
                DocIdRandSourceGuard guard(&failingRand);
                EXPECT_NO_THROW(connector->index("idx", R"({"a":1})"));
            }
            {
                std::lock_guard<std::mutex> lock(cap.mtx);
                afterFirst = cap.ids.size();
            }
            EXPECT_NO_THROW(connector->index("idx", R"({"a":1})"));
        });
    worker.join();

    EXPECT_EQ(afterFirst, 0U);
    ASSERT_EQ(cap.ids.size(), 1U);
    EXPECT_TRUE(isValidDocId(cap.ids[0])) << cap.ids[0];
}

TEST(IndexerConnectorAsyncAdapterTest, ForwardsIdAsSecondArgument)
{
    logging::testInit(logging::Level::Debug);
    const nlohmann::json config = {{"hosts", {"http://127.0.0.1:1"}}};
    auto inner = std::make_unique<IndexerConnectorAsync>(
        config, LoggingContext {logging::default_tag(), logging::createStandaloneLogFunction()});
    auto adapter = std::make_unique<wiconnector::IndexerConnectorAsyncAdapter>(std::move(inner));

    EXPECT_THROW(adapter->indexDataStream("idx", std::string(513, 'x'), "{}"), IndexerConnectorException);
    EXPECT_NO_THROW(adapter->indexDataStream("idx", "id", std::string(513, 'x')));
    adapter.reset();
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
