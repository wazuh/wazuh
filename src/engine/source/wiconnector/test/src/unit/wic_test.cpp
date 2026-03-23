#include <gmock/gmock.h>
#include <gtest/gtest.h>

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

    EXPECT_NO_THROW({ wiconnector::WIndexerConnector connector(config, logFunction); });
}

TEST_F(WIndexerConnectorTest, ConstructorWithValidJsonConfig)
{
    std::string validJson = R"({
        "hosts": ["http://localhost:9200"],
        "username": "admin",
        "password": "admin"
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
    config.username = "admin";
    config.password = "admin";

    wiconnector::WIndexerConnector connector(config, logFunction);

    // This should not throw, even if connection fails (it logs warnings internally)
    EXPECT_NO_THROW({ connector.index("test-index", R"({"field": "value"})"); });
}

TEST_F(WIndexerConnectorTest, IndexEmptyIndex)
{
    wiconnector::Config config;
    config.hosts = {"http://localhost:9200"};
    config.username = "admin";
    config.password = "admin";

    wiconnector::WIndexerConnector connector(config, logFunction);

    // Should handle empty index name gracefully
    EXPECT_NO_THROW({ connector.index("", R"({"field": "value"})"); });
}

TEST_F(WIndexerConnectorTest, IndexEmptyData)
{
    wiconnector::Config config;
    config.hosts = {"http://localhost:9200"};
    config.username = "admin";
    config.password = "admin";

    wiconnector::WIndexerConnector connector(config, logFunction);

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
    config.username = "admin";
    config.password = "admin";

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
    config.username = "admin";
    config.password = "admin";

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
    config.username = "admin";
    config.password = "admin";

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
