#include <filesystem>
#include <iostream>
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"
#include "rapidjson/schema.h"
#include "diskStorage_test.hpp"


// Test: get asset list from inaccesible directory
TEST(getAssetList, invalid_path)
{

    diskStorage ds("/temp123");
    StorageDriverInterface* dsi {&ds};

    ASSERT_THROW(dsi->getAssetList(AssetType::Decoder), std::filesystem::filesystem_error);

}

// Test: get asset list from empty directory
TEST(getAssetList, valid_path_wo_db)
{

    // Create tmp db
    char* tmpDir = createDBtmp();

    diskStorage ds(tmpDir);
    StorageDriverInterface* dsi {&ds};
    auto array = dsi->getAssetList(AssetType::Decoder);

    ASSERT_EQ(array.size(), 0);

    removeDBtmp(&tmpDir);

}

// Test: get asset list from 1 decoder (1 file)
TEST(getAssetList, one_decoder_one_file) {

    char* tmpDir = createDBtmp();

    auto decoder_path = std::filesystem::path(tmpDir) / "decoders" / "test_decoder.yml";
    std::ofstream ofs {decoder_path};
    ofs << "test_decoder: {}";
    ofs.close();

    diskStorage ds(tmpDir);
    StorageDriverInterface* dsi {&ds};
    auto array = dsi->getAssetList(AssetType::Decoder);

    ASSERT_EQ(array.size(), 1);
    ASSERT_STREQ(array[0].c_str(), "test_decoder");

    removeDBtmp(&tmpDir);

}

// Test: get asset list, 2 decoder (2 file)
TEST(getAssetList, two_decoder_two_file) {

    char* tmpDir = createDBtmp();

    auto newFile = [tmpDir](std::string name) -> void {
        auto decoder_path = std::filesystem::path(tmpDir) / "decoders" / name;
        std::ofstream ofs {decoder_path};
        ofs << "test_decoder: {}";
        ofs.close();
    };

    newFile("test_decoder.yml");
    newFile("test_decoder_2.yml");


    diskStorage ds(tmpDir);
    StorageDriverInterface* dsi {&ds};
    auto array = dsi->getAssetList(AssetType::Decoder);

    ASSERT_EQ(array.size(), 2);
    ASSERT_STREQ(array[0].c_str(), "test_decoder_2");
    ASSERT_STREQ(array[1].c_str(), "test_decoder");

    removeDBtmp(&tmpDir);

}


// Test: Ignore non-yml files
TEST(getAssetList, one_decoder_and_other_file) {

    char* tmpDir = createDBtmp();

    auto newFile = [tmpDir](std::string name) -> void {
        auto decoder_path = std::filesystem::path(tmpDir) / "decoders" / name;
        std::ofstream ofs {decoder_path};
        ofs << "test_decoder: {}";
        ofs.close();
    };

    // Decoder
    newFile("test_decoder.yml");
    // Non decoders
    newFile("test_decoder_2.YML");
    newFile("test_decoder_3.json");
    newFile("test_decoder_4.yaml");
    newFile("test_decoder_5.JSON");
    newFile("test_decoder_6.YAML");
    newFile("test_decoder_6");

    diskStorage ds(tmpDir);
    StorageDriverInterface* dsi {&ds};
    auto array = dsi->getAssetList(AssetType::Decoder);

    ASSERT_EQ(array.size(), 1);
    ASSERT_STREQ(array[0].c_str(), "test_decoder");

    removeDBtmp(&tmpDir);

}
