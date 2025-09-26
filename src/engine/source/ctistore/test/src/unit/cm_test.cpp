#include <chrono>
#include <filesystem>
#include <fstream>
#include <memory>
#include <thread>
#include <unistd.h>

#include <gtest/gtest.h>

#include <ctistore/cm.hpp>

TEST(ContentManagerTest, init)
{
    // Use writable temp directories to avoid permission issues with default absolute paths.
    auto ts = std::to_string(std::time(nullptr));
    cti::store::ContentManagerConfig cfg;
    cfg.outputFolder = "/tmp/cti_store_cm_init_" + ts + "/content";
    cfg.databasePath = "/tmp/cti_store_cm_init_" + ts + "/rocksdb";

    std::unique_ptr<cti::store::ContentManager> cm;
    ASSERT_NO_THROW({ cm = std::make_unique<cti::store::ContentManager>(cfg, false); });
    ASSERT_NE(cm, nullptr);

    // Clean up
    std::filesystem::remove_all("/tmp/cti_store_cm_init_" + ts);
}
