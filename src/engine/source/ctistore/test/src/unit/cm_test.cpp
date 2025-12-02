#include <chrono>
#include <filesystem>
#include <fstream>
#include <memory>
#include <thread>
#include <unistd.h>

#include <gtest/gtest.h>

#include <ctistore/cm.hpp>

// Helper utilities for generating isolated configurations for ContentManager tests.
namespace
{
std::string makeIsolatedConfig(cti::store::ContentManagerConfig& cfg, const std::string& tag)
{
    // Use high resolution clock + pid to avoid collisions in fast/parallel CI runs.
    auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    std::string base = "/tmp/cti_store_" + tag + '_' + std::to_string(now) + '_' + std::to_string(::getpid());
    cfg.outputFolder = base + "/content";
    cfg.databasePath = base + "/rocksdb";
    cfg.assetStorePath = base + "/assets";
    return base;
}
} // namespace

TEST(ContentManagerTest, init)
{
    // Use writable temp directories to avoid permission issues with default absolute paths.
    cti::store::ContentManagerConfig cfg;
    auto base = makeIsolatedConfig(cfg, "cm_init");

    std::unique_ptr<cti::store::ContentManager> cm;
    ASSERT_NO_THROW({ cm = std::make_unique<cti::store::ContentManager>(cfg); });
    ASSERT_NE(cm, nullptr);

    // Clean up
    std::filesystem::remove_all(base);
}

TEST(ContentManagerTest, processClassificationAllTypes)
{
    cti::store::ContentManagerConfig cfg;
    auto base = makeIsolatedConfig(cfg, "cm_proc");
    cfg.deleteDownloadedContent = false;

    cti::store::ContentManager cm(cfg);

    // Create a temporary content file with one line for each type
    std::filesystem::create_directories(cfg.outputFolder);
    const std::string filePath = cfg.outputFolder + "/batch.json";
    std::ofstream f(filePath);
    ASSERT_TRUE(f.is_open());
    f << R"({"name":"policy","offset":1,"version":1,"inserted_at":"2025-01-01T00:00:00Z","payload":{"integrations":["i1"],"title":"Sample Policy","type":"policy"}})"
      << '\n';
    f << R"({"name":"i1","offset":2,"version":1,"inserted_at":"2025-01-01T00:00:01Z","payload":{"document":{"title":"Integration 1","decoders":["d1"],"kvdbs":["k1"],"id":"i1"},"type":"integration"}})"
      << '\n';
    f << R"({"name":"d1","offset":3,"version":1,"inserted_at":"2025-01-01T00:00:02Z","payload":{"document":{"metadata":{"module":"mod1"},"id":"d1"},"type":"decoder"},"integration_id":"i1"})"
      << '\n';
    f << R"({"name":"k1","offset":4,"version":1,"inserted_at":"2025-01-01T00:00:03Z","payload":{"type":"kvdb","integration_id":"i1","document":{"id":"k1","content":{"k":"v"}}}})"
      << '\n';
    f.close();

    std::string message = std::string("{\"paths\":[\"") + filePath + "\"],\"type\":\"raw\",\"offset\":0}";

    auto result = cm.testProcessMessage(message);

    EXPECT_EQ(std::get<0>(result), 4); // highest offset processed
    EXPECT_TRUE(std::get<2>(result));

    std::filesystem::remove_all(base);
}

TEST(ContentManagerTest, processSkipsUnclassifiedLines)
{
    cti::store::ContentManagerConfig cfg;
    auto base = makeIsolatedConfig(cfg, "cm_proc_skip");
    cfg.deleteDownloadedContent = false;

    cti::store::ContentManager cm(cfg);

    std::filesystem::create_directories(cfg.outputFolder);
    const std::string filePath = cfg.outputFolder + "/batch.json";
    std::ofstream f(filePath);
    ASSERT_TRUE(f.is_open());
    // Missing type -> should be unclassified but still offset updated
    f << R"({"name":"unknown","offset":10})" << '\n';
    // Valid decoder line
    f << R"({"name":"dX","offset":11,"payload":{"document":{"metadata":{"module":"m"}},"type":"decoder"}})" << '\n';
    f.close();

    std::string message = std::string("{\"paths\":[\"") + filePath + "\"],\"type\":\"raw\",\"offset\":0}";
    auto result = cm.testProcessMessage(message);

    EXPECT_EQ(std::get<0>(result), 11); // last offset from second line
    EXPECT_TRUE(std::get<2>(result));

    std::filesystem::remove_all(base);
}

// ============================
// resolveUUIDFromName Tests
// ============================

TEST(ContentManagerTest, ResolveUUIDFromName_Integration)
{
    cti::store::ContentManagerConfig cfg;
    auto base = makeIsolatedConfig(cfg, "cm_resolve_uuid");
    cfg.deleteDownloadedContent = false;

    cti::store::ContentManager cm(cfg);

    // Store an integration via content processing
    std::filesystem::create_directories(cfg.outputFolder);
    const std::string filePath = cfg.outputFolder + "/integration.json";
    std::ofstream f(filePath);
    ASSERT_TRUE(f.is_open());
    f << R"({"name":"integration-uuid-123","offset":1,"version":1,"inserted_at":"2025-01-01T00:00:00Z","payload":{"document":{"title":"Test Integration","decoders":[],"kvdbs":[]},"type":"integration"}})"
      << '\n';
    f.close();

    std::string message = std::string("{\"paths\":[\"") + filePath + "\"],\"type\":\"raw\",\"offset\":0}";
    auto result = cm.testProcessMessage(message);
    EXPECT_TRUE(std::get<2>(result));

    // Resolve UUID from name
    std::string uuid = cm.resolveUUIDFromName(base::Name("Test Integration"), "integration");
    EXPECT_EQ(uuid, "integration-uuid-123");

    std::filesystem::remove_all(base);
}

TEST(ContentManagerTest, ResolveUUIDFromName_Decoder)
{
    cti::store::ContentManagerConfig cfg;
    auto base = makeIsolatedConfig(cfg, "cm_resolve_uuid_decoder");
    cfg.deleteDownloadedContent = false;

    cti::store::ContentManager cm(cfg);

    // Store a decoder
    std::filesystem::create_directories(cfg.outputFolder);
    const std::string filePath = cfg.outputFolder + "/decoder.json";
    std::ofstream f(filePath);
    ASSERT_TRUE(f.is_open());
    f << R"({"name":"decoder-uuid-456","offset":1,"version":1,"inserted_at":"2025-01-01T00:00:00Z","payload":{"document":{"name":"test_decoder","metadata":{"module":"test"}},"type":"decoder"}})"
      << '\n';
    f.close();

    std::string message = std::string("{\"paths\":[\"") + filePath + "\"],\"type\":\"raw\",\"offset\":0}";
    auto result = cm.testProcessMessage(message);
    EXPECT_TRUE(std::get<2>(result));

    // Resolve UUID from name
    std::string uuid = cm.resolveUUIDFromName(base::Name("test_decoder"), "decoder");
    EXPECT_EQ(uuid, "decoder-uuid-456");

    std::filesystem::remove_all(base);
}

TEST(ContentManagerTest, ResolveUUIDFromName_NotFound)
{
    cti::store::ContentManagerConfig cfg;
    auto base = makeIsolatedConfig(cfg, "cm_resolve_uuid_notfound");

    cti::store::ContentManager cm(cfg);

    // Try to resolve UUID for non-existent integration
    EXPECT_THROW(
        cm.resolveUUIDFromName(base::Name("NonExistent"), "integration"),
        std::runtime_error
    );

    std::filesystem::remove_all(base);
}

TEST(ContentManagerTest, ResolveUUIDFromName_ConsistentResults)
{
    cti::store::ContentManagerConfig cfg;
    auto base = makeIsolatedConfig(cfg, "cm_resolve_uuid_consistent");
    cfg.deleteDownloadedContent = false;

    cti::store::ContentManager cm(cfg);

    // Store an integration
    std::filesystem::create_directories(cfg.outputFolder);
    const std::string filePath = cfg.outputFolder + "/integration.json";
    std::ofstream f(filePath);
    ASSERT_TRUE(f.is_open());
    f << R"({"name":"consistent-uuid","offset":1,"version":1,"inserted_at":"2025-01-01T00:00:00Z","payload":{"document":{"title":"Consistent Test","decoders":[],"kvdbs":[]},"type":"integration"}})"
      << '\n';
    f.close();

    std::string message = std::string("{\"paths\":[\"") + filePath + "\"],\"type\":\"raw\",\"offset\":0}";
    auto result = cm.testProcessMessage(message);
    EXPECT_TRUE(std::get<2>(result));

    // Test round-trip: Name -> UUID -> Name
    std::string uuid = cm.resolveUUIDFromName(base::Name("Consistent Test"), "integration");
    EXPECT_EQ(uuid, "consistent-uuid");

    // Verify round-trip using resolveNameAndTypeFromUUID
    auto nameType = cm.resolveNameAndTypeFromUUID(uuid);
    EXPECT_EQ(nameType.first, "Consistent Test");
    EXPECT_EQ(nameType.second, "integration");

    std::filesystem::remove_all(base);
}

  // ============================
  // resolveNameAndTypeFromUUID Tests
  // ============================

  TEST(ContentManagerTest, ResolveNameAndTypeFromUUID_Integration)
  {
    cti::store::ContentManagerConfig cfg;
    auto base = makeIsolatedConfig(cfg, "cm_resolve_name_type");
    cfg.deleteDownloadedContent = false;

    cti::store::ContentManager cm(cfg);

    // Store an integration via content processing
    std::filesystem::create_directories(cfg.outputFolder);
    const std::string filePath = cfg.outputFolder + "/integration_name.json";
    std::ofstream f(filePath);
    ASSERT_TRUE(f.is_open());
    f << R"({"name":"integration-uuid-123","offset":1,"version":1,"inserted_at":"2025-01-01T00:00:00Z","payload":{"document":{"title":"Test Integration","decoders":[],"kvdbs":[]},"type":"integration"}})" 
      << '\n';
    f.close();

    std::string message = std::string("{\"paths\":[\"") + filePath + "\"],\"type\":\"raw\",\"offset\":0}";
    auto result = cm.testProcessMessage(message);
    EXPECT_TRUE(std::get<2>(result));

    auto nameType = cm.resolveNameAndTypeFromUUID("integration-uuid-123");
    EXPECT_EQ(nameType.first, "Test Integration");
    EXPECT_EQ(nameType.second, "integration");

    std::filesystem::remove_all(base);
  }

  TEST(ContentManagerTest, ResolveNameAndTypeFromUUID_Decoder)
  {
    cti::store::ContentManagerConfig cfg;
    auto base = makeIsolatedConfig(cfg, "cm_resolve_name_type_decoder");
    cfg.deleteDownloadedContent = false;

    cti::store::ContentManager cm(cfg);

    // Store a decoder
    std::filesystem::create_directories(cfg.outputFolder);
    const std::string filePath = cfg.outputFolder + "/decoder_name.json";
    std::ofstream f(filePath);
    ASSERT_TRUE(f.is_open());
    f << R"({"name":"decoder-uuid-456","offset":1,"version":1,"inserted_at":"2025-01-01T00:00:00Z","payload":{"document":{"name":"test_decoder","metadata":{"module":"test"}},"type":"decoder"}})" 
      << '\n';
    f.close();

    std::string message = std::string("{\"paths\":[\"") + filePath + "\"],\"type\":\"raw\",\"offset\":0}";
    auto result = cm.testProcessMessage(message);
    EXPECT_TRUE(std::get<2>(result));

    auto nameType = cm.resolveNameAndTypeFromUUID("decoder-uuid-456");
    EXPECT_EQ(nameType.first, "test_decoder");
    EXPECT_EQ(nameType.second, "decoder");

    std::filesystem::remove_all(base);
  }

  TEST(ContentManagerTest, ResolveNameAndTypeFromUUID_KVDB)
  {
    cti::store::ContentManagerConfig cfg;
    auto base = makeIsolatedConfig(cfg, "cm_resolve_name_type_kvdb");
    cfg.deleteDownloadedContent = false;

    cti::store::ContentManager cm(cfg);

    // Store a KVDB
    std::filesystem::create_directories(cfg.outputFolder);
    const std::string filePath = cfg.outputFolder + "/kvdb_name.json";
    std::ofstream f(filePath);
    ASSERT_TRUE(f.is_open());
    f << R"({"name":"kvdb-uuid-789","offset":1,"version":1,"inserted_at":"2025-01-01T00:00:00Z","payload":{"type":"kvdb","document":{"id":"kvdb-uuid-789","title":"TestKVDB","content":{"k":"v"}}}})" 
      << '\n';
    f.close();

    std::string message = std::string("{\"paths\":[\"") + filePath + "\"],\"type\":\"raw\",\"offset\":0}";
    auto result = cm.testProcessMessage(message);
    EXPECT_TRUE(std::get<2>(result));

    auto nameType = cm.resolveNameAndTypeFromUUID("kvdb-uuid-789");
    EXPECT_EQ(nameType.first, "TestKVDB");
    EXPECT_EQ(nameType.second, "kvdb");

    std::filesystem::remove_all(base);
  }

  TEST(ContentManagerTest, ResolveNameAndTypeFromUUID_NotFound)
  {
    cti::store::ContentManagerConfig cfg;
    auto base = makeIsolatedConfig(cfg, "cm_resolve_name_type_notfound");

    cti::store::ContentManager cm(cfg);

    // Try to resolve name/type for non-existent uuid
    EXPECT_THROW(
      cm.resolveNameAndTypeFromUUID("non-existent-uuid"),
      std::runtime_error
    );

    std::filesystem::remove_all(base);
  }
