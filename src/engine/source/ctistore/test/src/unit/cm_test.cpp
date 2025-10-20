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
