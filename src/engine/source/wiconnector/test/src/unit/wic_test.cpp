#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <wiconnector/mockIndexerConnectorAsync.hpp>
#include <wiconnector/windexerconnector.hpp>

#include <base/logging.hpp>
#include <chrono>
#include <thread>

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
    const std::size_t maxHitsPerRequest {1000};
};

// Test Config class functionality
class ConfigTest : public ::testing::Test
{
};

TEST_F(ConfigTest, BasicConfigToJson)
{
    wiconnector::Config config;
    config.hosts = {"http://localhost:9200"};
    config.username = "admin";
    config.password = "admin";

    std::string jsonStr = config.toJson();

    // Verify the JSON contains expected fields
    EXPECT_TRUE(jsonStr.find("\"hosts\"") != std::string::npos);
    EXPECT_TRUE(jsonStr.find("\"username\"") != std::string::npos);
    EXPECT_TRUE(jsonStr.find("\"password\"") != std::string::npos);
    EXPECT_TRUE(jsonStr.find("localhost:9200") != std::string::npos);
}

TEST_F(ConfigTest, ConfigWithSSLToJson)
{
    wiconnector::Config config;
    config.hosts = {"https://localhost:9200"};
    config.username = "admin";
    config.password = "admin";
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

    // Should not contain username/password when empty
    EXPECT_TRUE(jsonStr.find("\"username\"") == std::string::npos);
    EXPECT_TRUE(jsonStr.find("\"password\"") == std::string::npos);
}

// Test WIndexerConnector construction
TEST_F(WIndexerConnectorTest, ConstructorWithValidConfig)
{
    wiconnector::Config config;
    config.hosts = {"http://localhost:9200"};
    config.username = "admin";
    config.password = "admin";

    EXPECT_NO_THROW({ wiconnector::WIndexerConnector connector(config, logFunction, maxHitsPerRequest); });
}

TEST_F(WIndexerConnectorTest, ConstructorWithValidJsonConfig)
{
    std::string validJson = R"({
        "hosts": ["http://localhost:9200"],
        "username": "admin",
        "password": "admin"
    })";

    EXPECT_NO_THROW({ wiconnector::WIndexerConnector connector(validJson, maxHitsPerRequest); });
}

TEST_F(WIndexerConnectorTest, ConstructorWithEmptyJsonConfig)
{
    std::string emptyJson = "";

    EXPECT_THROW({ wiconnector::WIndexerConnector connector(emptyJson, maxHitsPerRequest); }, std::runtime_error);
}

TEST_F(WIndexerConnectorTest, ConstructorWithInvalidJsonConfig)
{
    std::string invalidJson = "{ invalid json }";

    EXPECT_THROW({ wiconnector::WIndexerConnector connector(invalidJson, maxHitsPerRequest); }, std::runtime_error);
}

// Test that constructor throws when maxHitsPerRequest is zero
TEST_F(WIndexerConnectorTest, ConstructorMaxHitsToZero)
{
    wiconnector::Config config;
    config.hosts = {"http://localhost:9200"};
    config.username = "admin";
    config.password = "admin";

    // Should not throw maxHitsPerRequest set to 0 will fallback to 1.
    EXPECT_NO_THROW({ wiconnector::WIndexerConnector connector(config, logFunction, 0); });
}

// Test indexing functionality
TEST_F(WIndexerConnectorTest, IndexValidData)
{
    wiconnector::Config config;
    config.hosts = {"http://localhost:9200"}; // This will likely fail to connect, but that's OK for unit test
    config.username = "admin";
    config.password = "admin";

    wiconnector::WIndexerConnector connector(config, logFunction, maxHitsPerRequest);

    // This should not throw, even if connection fails (it logs warnings internally)
    EXPECT_NO_THROW({ connector.index("test-index", R"({"field": "value"})"); });
}

TEST_F(WIndexerConnectorTest, IndexEmptyIndex)
{
    wiconnector::Config config;
    config.hosts = {"http://localhost:9200"};
    config.username = "admin";
    config.password = "admin";

    wiconnector::WIndexerConnector connector(config, logFunction, maxHitsPerRequest);

    // Should handle empty index name gracefully
    EXPECT_NO_THROW({ connector.index("", R"({"field": "value"})"); });
}

TEST_F(WIndexerConnectorTest, IndexEmptyData)
{
    wiconnector::Config config;
    config.hosts = {"http://localhost:9200"};
    config.username = "admin";
    config.password = "admin";

    wiconnector::WIndexerConnector connector(config, logFunction, maxHitsPerRequest);

    // Should handle empty data gracefully
    EXPECT_NO_THROW({ connector.index("test-index", ""); });
}

// Test shutdown functionality
TEST_F(WIndexerConnectorTest, ShutdownConnector)
{
    wiconnector::Config config;
    config.hosts = {"http://localhost:9200"};
    config.username = "admin";
    config.password = "admin";

    wiconnector::WIndexerConnector connector(config, logFunction, maxHitsPerRequest);

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
    config.username = "admin";
    config.password = "admin";

    wiconnector::WIndexerConnector connector(config, logFunction, maxHitsPerRequest);

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
    config.username = "admin";
    config.password = "admin";

    wiconnector::WIndexerConnector connector(config, logFunction, maxHitsPerRequest);

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

// Test requestShutdown is callable and is non-destructive
TEST_F(WIndexerConnectorTest, RequestShutdownIsNonDestructive)
{
    wiconnector::Config config;
    config.hosts = {"http://localhost:9200"};
    config.username = "admin";
    config.password = "admin";

    wiconnector::WIndexerConnector connector(config, logFunction, maxHitsPerRequest);

    // requestShutdown only sets a flag; should not throw and should not destroy the connector
    EXPECT_NO_THROW({ connector.requestShutdown(); });

    // Indexing should still be possible after requestShutdown (only the destructive shutdown
    // resets the underlying async connector).
    EXPECT_NO_THROW({ connector.index("test-index", R"({"field": "value"})"); });
}

// Test that requestShutdown followed by shutdown works cleanly
TEST_F(WIndexerConnectorTest, RequestShutdownThenShutdown)
{
    wiconnector::Config config;
    config.hosts = {"http://localhost:9200"};
    config.username = "admin";
    config.password = "admin";

    wiconnector::WIndexerConnector connector(config, logFunction, maxHitsPerRequest);

    EXPECT_NO_THROW({ connector.requestShutdown(); });
    EXPECT_NO_THROW({ connector.shutdown(); });
}

// Test that requestShutdown is idempotent (safe to call multiple times)
TEST_F(WIndexerConnectorTest, RequestShutdownIdempotent)
{
    wiconnector::Config config;
    config.hosts = {"http://localhost:9200"};
    config.username = "admin";
    config.password = "admin";

    wiconnector::WIndexerConnector connector(config, logFunction, maxHitsPerRequest);

    EXPECT_NO_THROW({ connector.requestShutdown(); });
    EXPECT_NO_THROW({ connector.requestShutdown(); });
    EXPECT_NO_THROW({ connector.requestShutdown(); });
}

// Integration-style test (will be skipped if no real indexer available)
TEST_F(WIndexerConnectorTest, DISABLED_IntegrationTest)
{
    // This test is disabled by default as it requires a real Elasticsearch/OpenSearch instance
    wiconnector::Config config;
    config.hosts = {"http://localhost:9200"};
    config.username = "admin";
    config.password = "admin";

    wiconnector::WIndexerConnector connector(config, logFunction, maxHitsPerRequest);

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
using ::testing::DoAll;
using ::testing::HasSubstr;
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
    std::unique_ptr<wiconnector::WIndexerConnector> makeConnector(std::size_t maxHits = 1000)
    {
        return std::make_unique<wiconnector::WIndexerConnector>(std::move(mockOwned), maxHits);
    }

    static PointInTime makePit(const std::string& id = "pit-id-1") { return PointInTime(id, 1234567890ULL, "5m"); }

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
 * existsPolicy
 **************************/
TEST_F(WIndexerConnectorMockTest, ExistsPolicyTrueWhenHits)
{
    nlohmann::json hits = {{"total", {{"value", 1}}}, {"hits", nlohmann::json::array()}};
    EXPECT_CALL(*mock, search(An<std::string_view>(), _, _, _)).WillOnce(Return(hits));
    auto connector = makeConnector();
    EXPECT_TRUE(connector->existsPolicy("default"));
}

TEST_F(WIndexerConnectorMockTest, ExistsPolicyFalseWhenZeroHits)
{
    nlohmann::json hits = {{"total", {{"value", 0}}}, {"hits", nlohmann::json::array()}};
    EXPECT_CALL(*mock, search(An<std::string_view>(), _, _, _)).WillOnce(Return(hits));
    auto connector = makeConnector();
    EXPECT_FALSE(connector->existsPolicy("default"));
}

TEST_F(WIndexerConnectorMockTest, ExistsPolicyEmptySpaceThrows)
{
    auto connector = makeConnector();
    EXPECT_THROW(connector->existsPolicy(""), std::runtime_error);
}

TEST_F(WIndexerConnectorMockTest, ExistsPolicyAfterShutdownThrows)
{
    auto connector = makeConnector();
    connector->shutdown();
    EXPECT_THROW(connector->existsPolicy("default"), std::runtime_error);
}

/**************************
 * existsIocDataIndex
 **************************/
TEST_F(WIndexerConnectorMockTest, ExistsIocDataIndexTrue)
{
    EXPECT_CALL(*mock, search(An<std::string_view>(), 0U, _, _)).WillOnce(Return(nlohmann::json::object()));
    auto connector = makeConnector();
    EXPECT_TRUE(connector->existsIocDataIndex());
}

TEST_F(WIndexerConnectorMockTest, ExistsIocDataIndexFalseOnException)
{
    EXPECT_CALL(*mock, search(An<std::string_view>(), 0U, _, _))
        .WillOnce(Throw(IndexerConnectorException("index_not_found_exception")));
    auto connector = makeConnector();
    EXPECT_FALSE(connector->existsIocDataIndex());
}

TEST_F(WIndexerConnectorMockTest, ExistsIocDataIndexAfterShutdownThrows)
{
    auto connector = makeConnector();
    connector->shutdown();
    EXPECT_THROW(connector->existsIocDataIndex(), std::runtime_error);
}

/**************************
 * getPolicyHashAndEnabled
 **************************/
namespace
{
nlohmann::json policyHit(const std::string& hash,
                         bool enabled,
                         const std::vector<std::string>& integrations = {"int1"})
{
    nlohmann::json hit = {{"_source",
                           {{"space", {{"hash", {{"sha256", hash}}}}},
                            {"document", {{"enabled", enabled}, {"integrations", integrations}}}}}};
    return hit;
}
} // namespace

TEST_F(WIndexerConnectorMockTest, GetPolicyHashAndEnabledHappyPath)
{
    nlohmann::json hits = {{"total", {{"value", 1}}}, {"hits", {policyHit("abc123", true)}}};
    EXPECT_CALL(*mock, search(An<std::string_view>(), 1U, _, _)).WillOnce(Return(hits));
    auto connector = makeConnector();
    auto [hash, enabled] = connector->getPolicyHashAndEnabled("default");
    EXPECT_EQ(hash, "abc123");
    EXPECT_TRUE(enabled);
}

TEST_F(WIndexerConnectorMockTest, GetPolicyHashAndEnabledDisabledWhenNoIntegrations)
{
    nlohmann::json hits = {{"total", {{"value", 1}}}, {"hits", {policyHit("zz", true, {})}}};
    EXPECT_CALL(*mock, search(An<std::string_view>(), 1U, _, _)).WillOnce(Return(hits));
    auto connector = makeConnector();
    auto [hash, enabled] = connector->getPolicyHashAndEnabled("default");
    EXPECT_EQ(hash, "zz");
    EXPECT_FALSE(enabled);
}

TEST_F(WIndexerConnectorMockTest, GetPolicyHashAndEnabledDisabledWhenEnabledFalse)
{
    nlohmann::json hits = {{"total", {{"value", 1}}}, {"hits", {policyHit("zz", false, {"a"})}}};
    EXPECT_CALL(*mock, search(An<std::string_view>(), 1U, _, _)).WillOnce(Return(hits));
    auto connector = makeConnector();
    auto pair = connector->getPolicyHashAndEnabled("default");
    EXPECT_FALSE(pair.second);
}

TEST_F(WIndexerConnectorMockTest, GetPolicyHashAndEnabledZeroHitsThrows)
{
    nlohmann::json hits = {{"total", {{"value", 0}}}, {"hits", nlohmann::json::array()}};
    EXPECT_CALL(*mock, search(An<std::string_view>(), 1U, _, _)).WillOnce(Return(hits));
    auto connector = makeConnector();
    EXPECT_THROW(connector->getPolicyHashAndEnabled("default"), IndexerConnectorException);
}

TEST_F(WIndexerConnectorMockTest, GetPolicyHashAndEnabledMultipleHitsThrows)
{
    nlohmann::json hits = {{"total", {{"value", 2}}}, {"hits", {policyHit("a", true), policyHit("b", true)}}};
    EXPECT_CALL(*mock, search(An<std::string_view>(), 1U, _, _)).WillOnce(Return(hits));
    auto connector = makeConnector();
    EXPECT_THROW(connector->getPolicyHashAndEnabled("default"), IndexerConnectorException);
}

TEST_F(WIndexerConnectorMockTest, GetPolicyHashAndEnabledMissingFieldsThrows)
{
    nlohmann::json hits = {{"total", {{"value", 1}}}, {"hits", {{{"_source", {{"space", {{"hash", {}}}}}}}}}};
    EXPECT_CALL(*mock, search(An<std::string_view>(), 1U, _, _)).WillOnce(Return(hits));
    auto connector = makeConnector();
    EXPECT_THROW(connector->getPolicyHashAndEnabled("default"), IndexerConnectorException);
}

TEST_F(WIndexerConnectorMockTest, GetPolicyHashAndEnabledMissingEnabledThrows)
{
    nlohmann::json hits = {
        {"total", {{"value", 1}}},
        {"hits",
         {{{"_source",
            {{"space", {{"hash", {{"sha256", "abc"}}}}}, {"document", {{"integrations", {"a"}}}}}}}}}};
    EXPECT_CALL(*mock, search(An<std::string_view>(), 1U, _, _)).WillOnce(Return(hits));
    auto connector = makeConnector();
    EXPECT_THROW(connector->getPolicyHashAndEnabled("default"), IndexerConnectorException);
}

TEST_F(WIndexerConnectorMockTest, GetPolicyHashAndEnabledMissingIntegrationsThrows)
{
    nlohmann::json hits = {
        {"total", {{"value", 1}}},
        {"hits",
         {{{"_source", {{"space", {{"hash", {{"sha256", "abc"}}}}}, {"document", {{"enabled", true}}}}}}}}};
    EXPECT_CALL(*mock, search(An<std::string_view>(), 1U, _, _)).WillOnce(Return(hits));
    auto connector = makeConnector();
    EXPECT_THROW(connector->getPolicyHashAndEnabled("default"), IndexerConnectorException);
}

TEST_F(WIndexerConnectorMockTest, GetPolicyHashAndEnabledEmptySpaceThrows)
{
    auto connector = makeConnector();
    EXPECT_THROW(connector->getPolicyHashAndEnabled(""), std::runtime_error);
}

TEST_F(WIndexerConnectorMockTest, GetPolicyHashAndEnabledAfterShutdownThrows)
{
    auto connector = makeConnector();
    connector->shutdown();
    EXPECT_THROW(connector->getPolicyHashAndEnabled("default"), std::runtime_error);
}

/**************************
 * getPolicy
 **************************/
namespace
{
nlohmann::json makePolicyHit(const std::string& indexName,
                             const std::string& docName,
                             const nlohmann::json& sortVal,
                             std::optional<std::string> spaceHash = std::nullopt)
{
    nlohmann::json src = {{"document", {{"name", docName}}}};
    if (spaceHash.has_value())
    {
        src["space"] = {{"hash", {{"sha256", *spaceHash}}}};
    }
    return {{"_index", indexName}, {"_source", src}, {"sort", sortVal}};
}
} // namespace

TEST_F(WIndexerConnectorMockTest, GetPolicyHappyPath)
{
    auto pit = makePit();
    EXPECT_CALL(*mock, createPointInTime(_, _, true)).WillOnce(Return(pit));
    EXPECT_CALL(*mock, deletePointInTime(_)).Times(1);

    nlohmann::json hits = {{"total", {{"value", 5}}},
                           {"hits",
                            {makePolicyHit("wazuh-threatintel-kvdbs", "kv1", nlohmann::json::array({1, "a"})),
                             makePolicyHit("wazuh-threatintel-decoders", "d1", nlohmann::json::array({2, "b"})),
                             makePolicyHit("wazuh-threatintel-filters", "f1", nlohmann::json::array({3, "c"})),
                             makePolicyHit("wazuh-threatintel-integrations", "i1", nlohmann::json::array({4, "d"})),
                             makePolicyHit("wazuh-threatintel-policies",
                                           "policy1",
                                           nlohmann::json::array({5, "e"}),
                                           std::string("HASHX"))}}};

    EXPECT_CALL(*mock, search(_, _, _, _, _, _)).WillOnce(Return(hits));

    auto connector = makeConnector(/*maxHits=*/10);
    auto resources = connector->getPolicy("default");

    EXPECT_EQ(resources.kvdbs.size(), 1U);
    EXPECT_EQ(resources.decoders.size(), 1U);
    EXPECT_EQ(resources.filters.size(), 1U);
    EXPECT_EQ(resources.integration.size(), 1U);
    EXPECT_TRUE(resources.policy.isObject());
    std::string hash;
    EXPECT_EQ(resources.policy.getString(hash, "/hash"), json::RetGet::Success);
    EXPECT_EQ(hash, "HASHX");
    std::string originSpace;
    EXPECT_EQ(resources.policy.getString(originSpace, "/origin_space"), json::RetGet::Success);
    EXPECT_EQ(originSpace, "default");
}

TEST_F(WIndexerConnectorMockTest, GetPolicyEmptyResultEndsPagination)
{
    auto pit = makePit();
    EXPECT_CALL(*mock, createPointInTime(_, _, _)).WillOnce(Return(pit));
    EXPECT_CALL(*mock, deletePointInTime(_)).Times(1);

    nlohmann::json hits = {{"total", {{"value", 0}}}, {"hits", nlohmann::json::array()}};
    EXPECT_CALL(*mock, search(_, _, _, _, _, _)).WillOnce(Return(hits));

    auto connector = makeConnector();
    auto resources = connector->getPolicy("default");
    EXPECT_TRUE(resources.kvdbs.empty());
    EXPECT_TRUE(resources.decoders.empty());
    EXPECT_TRUE(resources.filters.empty());
    EXPECT_TRUE(resources.integration.empty());
}

TEST_F(WIndexerConnectorMockTest, GetPolicyEmptySpaceThrows)
{
    auto pit = makePit();
    EXPECT_CALL(*mock, createPointInTime(_, _, _)).WillOnce(Return(pit));
    EXPECT_CALL(*mock, deletePointInTime(_)).Times(1);
    auto connector = makeConnector();
    EXPECT_THROW(connector->getPolicy(""), std::runtime_error);
}

TEST_F(WIndexerConnectorMockTest, GetPolicyShutdownDuringPaginationThrows)
{
    auto pit = makePit();
    EXPECT_CALL(*mock, createPointInTime(_, _, _)).WillOnce(Return(pit));
    EXPECT_CALL(*mock, deletePointInTime(_)).Times(1);

    auto connector = makeConnector();
    connector->requestShutdown();
    EXPECT_THROW(connector->getPolicy("default"), IndexerConnectorException);
}

TEST_F(WIndexerConnectorMockTest, GetPolicyAfterShutdownThrows)
{
    auto connector = makeConnector();
    connector->shutdown();
    EXPECT_THROW(connector->getPolicy("default"), std::runtime_error);
}

TEST_F(WIndexerConnectorMockTest, GetPolicyUnknownIndexNameThrows)
{
    auto pit = makePit();
    EXPECT_CALL(*mock, createPointInTime(_, _, _)).WillOnce(Return(pit));
    EXPECT_CALL(*mock, deletePointInTime(_)).Times(1);

    nlohmann::json hits = {
        {"total", {{"value", 1}}},
        {"hits", {makePolicyHit("not-a-known-index", "x", nlohmann::json::array({1, "a"}))}}};
    EXPECT_CALL(*mock, search(_, _, _, _, _, _)).WillOnce(Return(hits));

    auto connector = makeConnector();
    EXPECT_THROW(connector->getPolicy("default"), IndexerConnectorException);
}

TEST_F(WIndexerConnectorMockTest, GetPolicyMissingPolicyHashThrows)
{
    auto pit = makePit();
    EXPECT_CALL(*mock, createPointInTime(_, _, _)).WillOnce(Return(pit));
    EXPECT_CALL(*mock, deletePointInTime(_)).Times(1);

    // Provide a hit whose _source.space.hash.sha256 is the wrong type (number instead of string)
    // so the get<string>() conversion throws, exercising the catch in getPolicy.
    nlohmann::json badHit = {{"_index", "wazuh-threatintel-policies"},
                             {"_source",
                              {{"document", {{"name", "p"}}},
                               {"space", {{"hash", {{"sha256", 12345}}}}}}},
                             {"sort", nlohmann::json::array({1, "a"})}};
    nlohmann::json hits = {{"total", {{"value", 1}}}, {"hits", {badHit}}};
    EXPECT_CALL(*mock, search(_, _, _, _, _, _)).WillOnce(Return(hits));

    auto connector = makeConnector();
    EXPECT_THROW(connector->getPolicy("default"), IndexerConnectorException);
}

/**************************
 * getEngineRemoteConfig
 **************************/
TEST_F(WIndexerConnectorMockTest, GetEngineRemoteConfigHappyPath)
{
    nlohmann::json hits = {
        {"total", {{"value", 1}}},
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
        {"hits",
         {{{"_source", {{"engine", {{"a", 1}}}}}}, {{"_source", {{"engine", {{"b", 2}}}}}}}}};
    EXPECT_CALL(*mock, search(An<std::string_view>(), 1U, _, _)).WillOnce(Return(hits));
    auto connector = makeConnector();
    EXPECT_THROW(connector->getEngineRemoteConfig(), IndexerConnectorException);
}

TEST_F(WIndexerConnectorMockTest, GetEngineRemoteConfigMissingEngineThrows)
{
    nlohmann::json hits = {{"total", {{"value", 1}}},
                           {"hits", {{{"_source", {{"other", "value"}}}}}}};
    EXPECT_CALL(*mock, search(An<std::string_view>(), 1U, _, _)).WillOnce(Return(hits));
    auto connector = makeConnector();
    EXPECT_THROW(connector->getEngineRemoteConfig(), IndexerConnectorException);
}

TEST_F(WIndexerConnectorMockTest, GetEngineRemoteConfigEngineNotObjectThrows)
{
    nlohmann::json hits = {{"total", {{"value", 1}}},
                           {"hits", {{{"_source", {{"engine", "not-an-object"}}}}}}};
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

/**************************
 * getIocTypeHashes
 **************************/
TEST_F(WIndexerConnectorMockTest, GetIocTypeHashesHappyPath)
{
    auto pit = makePit();
    EXPECT_CALL(*mock, createPointInTime(_, _, _)).WillOnce(Return(pit));
    EXPECT_CALL(*mock, deletePointInTime(_)).Times(1);

    nlohmann::json firstPage = {
        {"hits",
         {{{"_id", "__ioc_type_hashes__"},
           {"_source",
            {{"type_hashes",
              {{"ip", {{"hash", {{"sha256", "h-ip"}}}}},
               {"domain", {{"hash", {{"sha256", "h-dom"}}}}}}}}},
           {"sort", nlohmann::json::array({1, "a"})}}}}};
    nlohmann::json emptyPage = {{"hits", nlohmann::json::array()}};

    // batchSize is 1: queryByBatches keeps paginating while size == batchSize, so we need
    // a second empty response to terminate the loop.
    EXPECT_CALL(*mock, search(_, _, _, _, _, _))
        .WillOnce(Return(firstPage))
        .WillOnce(Return(emptyPage));

    auto connector = makeConnector();
    auto result = connector->getIocTypeHashes();
    EXPECT_EQ(result.size(), 2U);
    EXPECT_EQ(result["ip"], "h-ip");
    EXPECT_EQ(result["domain"], "h-dom");
}

TEST_F(WIndexerConnectorMockTest, GetIocTypeHashesNoDocumentThrows)
{
    auto pit = makePit();
    EXPECT_CALL(*mock, createPointInTime(_, _, _)).WillOnce(Return(pit));
    EXPECT_CALL(*mock, deletePointInTime(_)).Times(1);

    nlohmann::json hits = {{"hits", nlohmann::json::array()}};
    EXPECT_CALL(*mock, search(_, _, _, _, _, _)).WillOnce(Return(hits));

    auto connector = makeConnector();
    EXPECT_THROW(connector->getIocTypeHashes(), IndexerConnectorException);
}

TEST_F(WIndexerConnectorMockTest, GetIocTypeHashesFlatFormat)
{
    auto pit = makePit();
    EXPECT_CALL(*mock, createPointInTime(_, _, _)).WillOnce(Return(pit));
    EXPECT_CALL(*mock, deletePointInTime(_)).Times(1);

    nlohmann::json firstPage = {
        {"hits",
         {{{"_id", "__ioc_type_hashes__"},
           {"_source", {{"ip", {{"hash", {{"sha256", "h-ip"}}}}}}},
           {"sort", nlohmann::json::array({1, "a"})}}}}};
    nlohmann::json emptyPage = {{"hits", nlohmann::json::array()}};

    EXPECT_CALL(*mock, search(_, _, _, _, _, _))
        .WillOnce(Return(firstPage))
        .WillOnce(Return(emptyPage));

    auto connector = makeConnector();
    auto result = connector->getIocTypeHashes();
    EXPECT_EQ(result["ip"], "h-ip");
}

/**************************
 * streamIocsByType
 **************************/
TEST_F(WIndexerConnectorMockTest, StreamIocsByTypeHappyPath)
{
    auto pit = makePit();
    EXPECT_CALL(*mock, createPointInTime(_, _, _)).WillOnce(Return(pit));
    EXPECT_CALL(*mock, deletePointInTime(_)).Times(1);

    auto makeIocHit = [](const std::string& name, const nlohmann::json& sortVal)
    {
        return nlohmann::json {{"_id", name},
                               {"_source", {{"document", {{"name", name}, {"type", "ip"}}}}},
                               {"sort", sortVal}};
    };

    // Two hits: first call returns 2, which equals batchSize → loop terminates.
    nlohmann::json firstPage = {{"hits",
                                 {makeIocHit("ioc1", nlohmann::json::array({1, "a"})),
                                  makeIocHit("ioc2", nlohmann::json::array({2, "b"}))}}};

    EXPECT_CALL(*mock, search(_, _, _, _, _, _)).WillOnce(Return(firstPage));

    std::vector<std::pair<std::string, std::string>> received;
    auto connector = makeConnector();
    auto count = connector->streamIocsByType(
        "ip", /*batchSize=*/10, [&received](const std::string& k, const std::string& v) { received.emplace_back(k, v); });
    EXPECT_EQ(count, 2U);
    EXPECT_EQ(received.size(), 2U);
    EXPECT_EQ(received[0].first, "ioc1");
    EXPECT_EQ(received[1].first, "ioc2");
}

TEST_F(WIndexerConnectorMockTest, StreamIocsByTypeEmptyTypeThrows)
{
    auto connector = makeConnector();
    EXPECT_THROW(connector->streamIocsByType("", 10, [](const std::string&, const std::string&) {}),
                 std::runtime_error);
}

TEST_F(WIndexerConnectorMockTest, StreamIocsByTypeNullCallbackThrows)
{
    auto connector = makeConnector();
    wiconnector::IWIndexerConnector::IocRecordCallback nullCb;
    EXPECT_THROW(connector->streamIocsByType("ip", 10, nullCb), std::runtime_error);
}

TEST_F(WIndexerConnectorMockTest, StreamIocsByTypeSkipsHitWithoutDocumentName)
{
    auto pit = makePit();
    EXPECT_CALL(*mock, createPointInTime(_, _, _)).WillOnce(Return(pit));
    EXPECT_CALL(*mock, deletePointInTime(_)).Times(1);

    nlohmann::json hits = {
        {"hits",
         {{{"_id", "missing-name"},
           {"_source", {{"document", {{"type", "ip"}}}}},
           {"sort", nlohmann::json::array({1, "a"})}}}}};

    EXPECT_CALL(*mock, search(_, _, _, _, _, _)).WillOnce(Return(hits));

    auto connector = makeConnector();
    auto count =
        connector->streamIocsByType("ip", 10, [](const std::string&, const std::string&) {});
    EXPECT_EQ(count, 0U);
}

TEST_F(WIndexerConnectorMockTest, StreamIocsByTypeSkipsHitWithoutSource)
{
    auto pit = makePit();
    EXPECT_CALL(*mock, createPointInTime(_, _, _)).WillOnce(Return(pit));
    EXPECT_CALL(*mock, deletePointInTime(_)).Times(1);

    nlohmann::json hits = {{"hits", {{{"_id", "no-source"}, {"sort", nlohmann::json::array({1, "a"})}}}}};

    EXPECT_CALL(*mock, search(_, _, _, _, _, _)).WillOnce(Return(hits));

    auto connector = makeConnector();
    auto count =
        connector->streamIocsByType("ip", 10, [](const std::string&, const std::string&) {});
    EXPECT_EQ(count, 0U);
}

TEST_F(WIndexerConnectorMockTest, StreamIocsByTypePaginatesAndStopsOnShutdown)
{
    auto pit = makePit();
    EXPECT_CALL(*mock, createPointInTime(_, _, _)).WillOnce(Return(pit));
    EXPECT_CALL(*mock, deletePointInTime(_)).Times(1);

    auto fullPage = [&](const std::string& prefix)
    {
        nlohmann::json arr = nlohmann::json::array();
        for (int i = 0; i < 2; ++i)
        {
            arr.push_back({{"_id", prefix + std::to_string(i)},
                           {"_source", {{"document", {{"name", prefix + std::to_string(i)}, {"type", "ip"}}}}},
                           {"sort", nlohmann::json::array({i, "x"})}});
        }
        return nlohmann::json {{"hits", arr}};
    };

    auto connector = makeConnector();

    // First call returns a full page, then we trigger shutdown so the
    // second iteration short-circuits with an exception.
    EXPECT_CALL(*mock, search(_, _, _, _, _, _))
        .WillOnce(DoAll(Invoke([connector_ptr = connector.get()](
                                   const PointInTime&, std::size_t, const nlohmann::json&,
                                   const nlohmann::json&, const std::optional<nlohmann::json>&,
                                   const std::optional<nlohmann::json>&)
                               { connector_ptr->requestShutdown(); }),
                        Return(fullPage("a"))));

    EXPECT_THROW(connector->streamIocsByType("ip", 2, [](const std::string&, const std::string&) {}),
                 IndexerConnectorException);
}

