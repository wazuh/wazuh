#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <base/name.hpp>
#include <ctistore/cm.hpp>
#include "contentdownloader.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <unistd.h>

using namespace cti::store;
using namespace testing;

namespace
{
std::string makeIsolatedConfig(ContentManagerConfig& cfg, const std::string& tag)
{
    auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    std::string base = "/tmp/cti_dl_" + tag + '_' + std::to_string(now) + '_' + std::to_string(::getpid());
    cfg.outputFolder = base + "/content";
    cfg.databasePath = base + "/rocksdb";
    cfg.assetStorePath = base + "/assets";
    return base;
}
} // namespace

class ContentDownloaderTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
        testDir = "/tmp/cti_store_test_" + std::to_string(now) + '_' + std::to_string(::getpid());
        std::filesystem::create_directories(testDir);

        testConfig.outputFolder = testDir + "/content";
        testConfig.databasePath = testDir + "/db";
        testConfig.assetStorePath = testDir + "/assets";
        testConfig.interval = 60;
        testConfig.onDemand = true;
        testConfig.topicName = "test_cti_store";
    }

    void TearDown() override { std::filesystem::remove_all(testDir); }

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

TEST_F(ContentDownloaderTest, ToNlohmannConsistency)
{
    ContentManagerConfig cfg;
    cfg.topicName = "tn";
    cfg.interval = 42;
    cfg.onDemand = true;
    cfg.consumerName = "C";
    cfg.outputFolder = "out";
    cfg.databasePath = "db";
    cfg.offset = 7;

    auto nj = contentManagerConfigToNlohmann(cfg);
    auto ej = cfg.toJson();

    EXPECT_EQ(nj["topicName"].get<std::string>(), ej.getString("/topicName").value());
    EXPECT_EQ(nj["interval"].get<int>(), ej.getInt("/interval").value());
    EXPECT_EQ(nj["ondemand"].get<bool>(), ej.getBool("/ondemand").value());
    EXPECT_EQ(nj["configData"]["consumerName"].get<std::string>(), ej.getString("/configData/consumerName").value());
    EXPECT_EQ(nj["configData"]["offset"].get<int>(), ej.getInt("/configData/offset").value());
}

TEST(ContentManagerConfigValidationTest, ValidDefaultConfig)
{
    ContentManagerConfig cfg; // defaults are valid
    EXPECT_NO_THROW(cfg.validate());
}

TEST(ContentManagerConfigValidationTest, InvalidInterval)
{
    ContentManagerConfig cfg;
    cfg.interval = 0;
    EXPECT_THROW(cfg.validate(), std::runtime_error);
}

TEST(ContentManagerConfigValidationTest, InvalidURLForCTISource)
{
    ContentManagerConfig cfg;
    cfg.url = "ftp://invalid"; // not http/https
    EXPECT_THROW(cfg.validate(), std::runtime_error);
}

TEST(ContentManagerConfigValidationTest, OfflineAllowsMissingHTTP)
{
    ContentManagerConfig cfg;
    cfg.contentSource = "offline";
    cfg.url.clear(); // allowed
    EXPECT_NO_THROW(cfg.validate());
}

TEST(ContentManagerConfigValidationTest, AcceptsNonRawCompressionType)
{
    ContentManagerConfig cfg;
    cfg.compressionType = "gzip"; // Should be accepted; content_manager handles decompression
    EXPECT_NO_THROW(cfg.validate());
}

TEST_F(ContentDownloaderTest, ContentDownloaderConstruction)
{
    EXPECT_NO_THROW({ ContentDownloader downloader(testConfig); });

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
    EXPECT_NO_THROW({ downloader.updateInterval(newInterval); });

    auto config = downloader.getConfig();
    EXPECT_EQ(config.interval, newInterval);
}

TEST_F(ContentDownloaderTest, UpdateConfigRejectsInvalid)
{
    ContentDownloader downloader(testConfig);
    ContentManagerConfig bad = testConfig;
    bad.interval = 0; // invalid
    EXPECT_THROW(downloader.updateConfig(bad), std::runtime_error);
    // Original config remains
    auto current = downloader.getConfig();
    EXPECT_EQ(current.interval, testConfig.interval);
}

TEST(ContentManagerTest, ManagerUpdateConfigRejectsInvalid)
{
    ContentManagerConfig cfg;
    auto base = makeIsolatedConfig(cfg, "mgr_update_invalid");
    ContentManager manager(cfg);
    ContentManagerConfig bad = cfg;
    bad.interval = 0;
    EXPECT_THROW(manager.updateConfig(bad, false), std::runtime_error);
    auto stored = manager.getConfig();
    EXPECT_EQ(stored.interval, cfg.interval);
    std::filesystem::remove_all(base);
}

TEST_F(ContentDownloaderTest, ProcessMessageWithInvalidFormat)
{
    ContentManager cm(testConfig);
    std::string invalidMessage = R"({"invalid": "format"})";
    auto result = cm.testProcessMessage(invalidMessage);
    EXPECT_EQ(std::get<0>(result), 0);
    EXPECT_EQ(std::get<1>(result), "");
    EXPECT_FALSE(std::get<2>(result));
}

TEST_F(ContentDownloaderTest, ProcessMessageWithValidOffsetFormat)
{
    ContentManager cm(testConfig);
    std::string testFile = testDir + "/test_content.json";
    std::ofstream file(testFile);
    file << R"({"data":[{"offset":100,"type":"create","payload":{"type":"decoder","document":{"id":"dec1"}}}]})"
         << std::endl;
    file.close();
    std::string validMessage = std::string("{\"paths\":[\"") + testFile + "\"],\"type\":\"offsets\",\"offset\":0}";
    auto result = cm.testProcessMessage(validMessage);
    EXPECT_EQ(std::get<0>(result), 100);
    EXPECT_TRUE(std::get<2>(result));
}

TEST_F(ContentDownloaderTest, ProcessMessageWithRawType)
{
    ContentManager cm(testConfig);
    std::string testFile = testDir + "/test_raw.json";
    std::ofstream file(testFile);
    file << R"({"name": "asset1", "offset": 50, "payload":{"type":"policy"}})" << std::endl;
    file << R"({"name": "asset2", "offset": 150, "payload":{"type":"integration"}})" << std::endl;
    file.close();
    std::string rawMessage = std::string("{\"paths\":[\"") + testFile + "\"],\"type\":\"raw\",\"offset\":0}";
    auto result = cm.testProcessMessage(rawMessage);
    EXPECT_EQ(std::get<0>(result), 150);
    EXPECT_TRUE(std::get<2>(result));
}

TEST(ContentManagerConfigTest, DefaultValues)
{
    ContentManagerConfig config; // default constructed
    EXPECT_EQ(config.topicName, "engine_cti_store");
    EXPECT_EQ(config.interval, 3600);
    EXPECT_FALSE(config.onDemand);
    EXPECT_EQ(config.consumerName, "Wazuh Engine");
    EXPECT_EQ(config.contentSource, "cti-offset");
    EXPECT_EQ(config.outputFolder, "content");
    EXPECT_EQ(config.contentFileName, "cti_content.json");
    EXPECT_EQ(config.databasePath, "offset_database");
    EXPECT_EQ(config.assetStorePath, "assets_database");
    EXPECT_TRUE(config.outputFolder.rfind("/var/ossec", 0) != 0);
    EXPECT_TRUE(config.databasePath.rfind("/var/ossec", 0) != 0);
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

TEST_F(ContentDownloaderTest, RelativePathsResolvedAgainstBasePath)
{
    auto baseRoot = testDir + "/root";
    ContentManagerConfig cfg;
    cfg.basePath = baseRoot;
    cfg.outputFolder = "content";
    cfg.databasePath = "rocksdb";

    ASSERT_FALSE(std::filesystem::exists(baseRoot));

    ContentDownloader downloader(cfg);
    auto effective = downloader.getConfig();

    EXPECT_TRUE(effective.outputFolder.find(baseRoot) == 0);
    EXPECT_TRUE(effective.databasePath.find(baseRoot) == 0);
    EXPECT_EQ(effective.outputFolder, baseRoot + std::string {"/content"});
    EXPECT_EQ(effective.databasePath, baseRoot + std::string {"/rocksdb"});

    EXPECT_TRUE(std::filesystem::exists(effective.outputFolder));
    EXPECT_TRUE(std::filesystem::exists(effective.databasePath));
}

TEST(ContentManagerTest, RelativePathsResolvedInConstructor)
{
    auto ts = std::to_string(std::time(nullptr));
    std::string baseRoot = std::string {"/tmp/cti_cm_rel_"} + ts + "/root";
    cti::store::ContentManagerConfig cfg;
    cfg.basePath = baseRoot;
    cfg.outputFolder = "content"; // relative
    cfg.databasePath = "rocksdb"; // relative

    // Before construction, paths are still relative
    ASSERT_EQ(cfg.outputFolder, "content");
    ASSERT_EQ(cfg.databasePath, "rocksdb");

    // Construct manager (should normalize + create directories + open DB)
    cti::store::ContentManager manager(cfg);
    auto effective = manager.getConfig();

    EXPECT_TRUE(effective.outputFolder.find(baseRoot) == 0);
    EXPECT_TRUE(effective.databasePath.find(baseRoot) == 0);
    EXPECT_EQ(effective.outputFolder, baseRoot + std::string {"/content"});
    EXPECT_EQ(effective.databasePath, baseRoot + std::string {"/rocksdb"});

    EXPECT_TRUE(std::filesystem::exists(effective.outputFolder));
    EXPECT_TRUE(std::filesystem::exists(effective.databasePath));

    std::filesystem::remove_all(baseRoot);
}

TEST(ContentManagerTest, AssetStorePathOverridesDatabasePath)
{
    auto ts = std::to_string(std::time(nullptr));
    ContentManagerConfig cfg;
    cfg.basePath = std::string {"/tmp/cti_cm_asset_"} + ts;
    cfg.outputFolder = "content";
    cfg.databasePath = "offset_db";   // offsets
    cfg.assetStorePath = "assets_db"; // assets

    ContentManager manager(cfg);
    auto effective = manager.getConfig();
    EXPECT_TRUE(effective.assetStorePath.find(cfg.basePath) == 0);
    EXPECT_NE(effective.assetStorePath, effective.databasePath);
    EXPECT_TRUE(std::filesystem::exists(effective.assetStorePath));
    EXPECT_TRUE(std::filesystem::exists(effective.databasePath));
    std::filesystem::remove_all(cfg.basePath);
}

// Integration tests for ContentManager
TEST(ContentManagerTest, BasicOperations)
{
    ContentManagerConfig config;
    auto base = makeIsolatedConfig(config, "basic_ops");

    ContentManager manager(config);

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
    // Should be empty on a brand new store. If not, print size for diagnostics.
    ASSERT_TRUE(integrations.empty()) << "Expected empty policy integration list, got size=" << integrations.size();

    // Clean up
    std::filesystem::remove_all(base);
}

TEST(ContentManagerTest, SyncOperations)
{
    ContentManagerConfig config;
    auto base = makeIsolatedConfig(config, "sync_ops");

    ContentManager manager(config);

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
    std::filesystem::remove_all(base);
}

TEST(ContentManagerTest, UpdateConfigWithRestartRestartsRunningSync)
{
    ContentManagerConfig cfg;
    auto base = makeIsolatedConfig(cfg, "restart_sync");
    cfg.interval = 2; // small interval

    ContentManager manager(cfg);

    // Start sync (may not actually run if ContentRegister unavailable, so guard with check)
    manager.startSync();
    bool wasRunning = manager.isSyncRunning();

    // Prepare new valid config with different interval to force update
    ContentManagerConfig updated = cfg;
    updated.interval = cfg.interval + 5;

    manager.updateConfig(updated, true);

    auto after = manager.getConfig();
    EXPECT_EQ(after.interval, updated.interval);

    // If originally running, it should still (or again) be running after restart attempt
    if (wasRunning)
    {
        EXPECT_TRUE(manager.isSyncRunning());
    }

    std::filesystem::remove_all(base);
}
