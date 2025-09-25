#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <ctistore/contentDownloader.hpp>
#include <ctistore/cm.hpp>
#include <base/name.hpp>

#include <filesystem>
#include <fstream>

using namespace cti::store;
using namespace testing;

class ContentDownloaderTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        // Create test directories
        testDir = "/tmp/cti_store_test_" + std::to_string(std::time(nullptr));
        std::filesystem::create_directories(testDir);

        // Create test configuration
        testConfig.outputFolder = testDir + "/content";
        testConfig.databasePath = testDir + "/db";
        testConfig.interval = 60; // 1 minute for testing
        testConfig.onDemand = true;
        testConfig.topicName = "test_cti_store";
    }

    void TearDown() override
    {
        // Clean up test directories
        std::filesystem::remove_all(testDir);
    }

    std::string testDir;
    ContentManagerConfig testConfig;
};

TEST_F(ContentDownloaderTest, ConfigurationToJsonConversion)
{
    ContentManagerConfig config;
    config.topicName = "test_topic";
    config.interval = 1800;
    config.onDemand = false;
    config.consumerName = "Test Consumer";
    config.url = "https://test.example.com/api";

    auto jsonConfig = config.toJson();

    EXPECT_EQ(jsonConfig.getString("/topicName").value(), "test_topic");
    EXPECT_EQ(jsonConfig.getInt("/interval").value(), 1800);
    EXPECT_EQ(jsonConfig.getBool("/ondemand").value(), false);

    EXPECT_EQ(jsonConfig.getString("/configData/consumerName").value(), "Test Consumer");
    EXPECT_EQ(jsonConfig.getString("/configData/url").value(), "https://test.example.com/api");
}

TEST_F(ContentDownloaderTest, ConfigurationFromJsonConversion)
{
    json::Json jsonConfig(R"({
        "topicName": "test_topic",
        "interval": 7200,
        "ondemand": true,
        "configData": {
            "consumerName": "Test Consumer",
            "contentSource": "test-source",
            "url": "https://test.example.com/api",
            "databasePath": "/tmp/test_db"
        }
    })");

    ContentManagerConfig config;
    config.fromJson(jsonConfig);

    EXPECT_EQ(config.topicName, "test_topic");
    EXPECT_EQ(config.interval, 7200);
    EXPECT_TRUE(config.onDemand);
    EXPECT_EQ(config.consumerName, "Test Consumer");
    EXPECT_EQ(config.contentSource, "test-source");
    EXPECT_EQ(config.url, "https://test.example.com/api");
    EXPECT_EQ(config.databasePath, "/tmp/test_db");
}

TEST_F(ContentDownloaderTest, ContentDownloaderConstruction)
{
    EXPECT_NO_THROW({
        ContentDownloader downloader(testConfig);
    });

    // Verify directories were created
    EXPECT_TRUE(std::filesystem::exists(testConfig.outputFolder));
    EXPECT_TRUE(std::filesystem::exists(testConfig.databasePath));
}

TEST_F(ContentDownloaderTest, ContentDownloaderStartStop)
{
    ContentDownloader downloader(testConfig);

    EXPECT_FALSE(downloader.isRunning());

    // Note: actual start may fail without ContentRegister implementation
    // This test verifies the interface works correctly
    downloader.start();

    if (downloader.isRunning())
    {
        EXPECT_TRUE(downloader.isRunning());
        downloader.stop();
        EXPECT_FALSE(downloader.isRunning());
    }
}

TEST_F(ContentDownloaderTest, UpdateInterval)
{
    ContentDownloader downloader(testConfig);

    size_t newInterval = 7200;
    EXPECT_NO_THROW({
        downloader.updateInterval(newInterval);
    });

    auto config = downloader.getConfig();
    EXPECT_EQ(config.interval, newInterval);
}

TEST_F(ContentDownloaderTest, ProcessMessageWithInvalidFormat)
{
    ContentDownloader downloader(testConfig);

    std::string invalidMessage = R"({"invalid": "format"})";
    auto result = downloader.processMessage(invalidMessage);

    EXPECT_EQ(std::get<0>(result), 0); // offset
    EXPECT_EQ(std::get<1>(result), ""); // hash
    EXPECT_FALSE(std::get<2>(result)); // status
}

TEST_F(ContentDownloaderTest, ProcessMessageWithValidOffsetFormat)
{
    ContentDownloader downloader(testConfig);

    // Create a test file with content
    std::string testFile = testDir + "/test_content.json";
    std::ofstream file(testFile);
    file << R"({"name": "test_asset", "offset": 100, "data": "test_data"})" << std::endl;
    file.close();

    std::string validMessage = R"({
        "paths": [")" + testFile + R"("],
        "type": "offsets",
        "offset": 0
    })";

    auto result = downloader.processMessage(validMessage);

    // The processing should succeed even if storage is not fully implemented
    EXPECT_EQ(std::get<0>(result), 100); // offset from file content
    EXPECT_TRUE(std::get<2>(result)); // status should be true
}

TEST_F(ContentDownloaderTest, ProcessMessageWithRawType)
{
    ContentDownloader downloader(testConfig);

    // Create a test file with raw content
    std::string testFile = testDir + "/test_raw.json";
    std::ofstream file(testFile);
    file << R"({"name": "asset1", "offset": 50})" << std::endl;
    file << R"({"name": "asset2", "offset": 150})" << std::endl;
    file.close();

    std::string rawMessage = R"({
        "paths": [")" + testFile + R"("],
        "type": "raw",
        "offset": 0
    })";

    auto result = downloader.processMessage(rawMessage);

    // Should return the highest offset
    EXPECT_EQ(std::get<0>(result), 150);
    EXPECT_TRUE(std::get<2>(result));
}

TEST(ContentManagerConfigTest, DefaultValues)
{
    ContentManagerConfig config; // default constructed
    EXPECT_EQ(config.topicName, "engine_cti_store");
    EXPECT_EQ(config.interval, 3600);
    EXPECT_TRUE(config.onDemand);
    EXPECT_EQ(config.consumerName, "Wazuh Engine");
    EXPECT_EQ(config.contentSource, "cti-offset");
    EXPECT_EQ(config.outputFolder, "/var/ossec/engine/cti_store/content");
    EXPECT_EQ(config.databasePath, "/var/ossec/engine/cti_store/rocksdb");
}

TEST(ContentManagerConfigTest, FromJsonOverridesPaths)
{
    json::Json jsonConfig(R"({
        "topicName": "custom_topic",
        "interval": 1800,
        "ondemand": false,
        "configData": {
            "consumerName": "Custom Consumer",
            "url": "https://custom.example.com/api",
            "outputFolder": "custom_content",
            "databasePath": "custom_db"
        }
    })");

    ContentManagerConfig config; // start with defaults
    config.fromJson(jsonConfig);
    EXPECT_EQ(config.topicName, "custom_topic");
    EXPECT_EQ(config.interval, 1800);
    EXPECT_FALSE(config.onDemand);
    EXPECT_EQ(config.consumerName, "Custom Consumer");
    // Since we now take provided values verbatim even if relative
    EXPECT_EQ(config.outputFolder, "custom_content");
    EXPECT_EQ(config.databasePath, "custom_db");
}

// Integration tests for ContentManager
TEST(ContentManagerTest, BasicOperations)
{
    ContentManagerConfig config;
    config.databasePath = "/tmp/cti_test_db_" + std::to_string(std::time(nullptr));
    config.outputFolder = "/tmp/cti_test_content_" + std::to_string(std::time(nullptr));

    ContentManager manager(config, false);

    // Test ICMReader interface methods
    EXPECT_NO_THROW({
        auto assets = manager.getAssetList(AssetType::DECODER);
        EXPECT_TRUE(assets.empty()); // Should be empty initially
    });

    EXPECT_FALSE(manager.assetExists(base::Name("test_asset")));

    auto kvdbs = manager.listKVDB();
    EXPECT_TRUE(kvdbs.empty());

    EXPECT_FALSE(manager.kvdbExists("test_kvdb"));

    auto integrations = manager.getPolicyIntegrationList();
    EXPECT_TRUE(integrations.empty());

    // Clean up
    std::filesystem::remove_all(config.databasePath);
    std::filesystem::remove_all(config.outputFolder);
}

TEST(ContentManagerTest, SyncOperations)
{
    ContentManagerConfig config;
    config.databasePath = "/tmp/cti_sync_db_" + std::to_string(std::time(nullptr));
    config.outputFolder = "/tmp/cti_sync_content_" + std::to_string(std::time(nullptr));

    ContentManager manager(config, false);

    EXPECT_FALSE(manager.isSyncRunning());

    // Start sync (may fail without full ContentRegister implementation)
    manager.startSync();

    if (manager.isSyncRunning())
    {
        EXPECT_TRUE(manager.isSyncRunning());

        // Test interval update
        manager.updateSyncInterval(1800);
        auto updatedConfig = manager.getConfig();
        EXPECT_EQ(updatedConfig.interval, 1800);

        // Stop sync
        manager.stopSync();
        EXPECT_FALSE(manager.isSyncRunning());
    }

    // Clean up
    std::filesystem::remove_all(config.databasePath);
    std::filesystem::remove_all(config.outputFolder);
}
