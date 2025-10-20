#include <filesystem>
#include <memory>
#include <chrono>
#include <string>

#include <gtest/gtest.h>

#include <ctistore/cm.hpp>

TEST(ContentManagerTest, init)
{
    // Use a unique writable temporary directory to avoid permission issues in CI environments.
    const auto tmpBase = std::filesystem::temp_directory_path() / (
        std::string("cti_cm_component_") + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));

    cti::store::ContentManagerConfig cfg;
    cfg.outputFolder = (tmpBase / "content").string();
    cfg.databasePath = (tmpBase / "rocksdb").string();
    cfg.assetStorePath = (tmpBase / "assets").string();

    std::unique_ptr<cti::store::ContentManager> cm;
    ASSERT_NO_THROW({ cm = std::make_unique<cti::store::ContentManager>(cfg); });
    ASSERT_NE(cm, nullptr);

    // Cleanup (best-effort)
    std::error_code ec; // avoid throwing during cleanup
    std::filesystem::remove_all(tmpBase, ec);
}
