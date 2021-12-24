#include "diskStorage_test.hpp"
#include <filesystem>

// const std::string currentDir = std::filesystem::current_path().string();
// const std::string testDir {currentDir + "/test/source/catalog/storageDriver/disk/db_test"};
const std::string db_dir_test {"/root/repos/wazuh/src/engine/test/source/catalog/storageDriver/disk/db_test"};


TEST(diskStorage, path)
{

    diskStorage ds(db_dir_test);
    storageDriverInterface* dsi {&ds};

    //dsi->getAssetList(AssetType::Decoder);
    //dsi->getAsset(AssetType::Decoder, "syslog").dump();
    //std::string json_dump {dsi->getAsset(AssetType::Decoder, "syslog").dump()};

    std::string json_dump {dsi->getAsset(AssetType::Schemas, "wazuh-decoders").dump()};

    EXPECT_STREQ("test out --> ", json_dump.c_str());
}
