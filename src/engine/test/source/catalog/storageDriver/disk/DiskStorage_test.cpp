#include <filesystem>
#include <iostream>
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"
#include "rapidjson/schema.h"
#include "DiskStorage_test.hpp"


// Test: Get asset list from inaccesible directory
TEST(getAssetList, invalid_path)
{

    DiskStorage ds("/temp123");
    StorageDriverInterface* pSI {&ds};

    ASSERT_THROW(pSI->getAssetList(AssetType::Decoder), std::filesystem::filesystem_error);

}

// Test: get asset list from empty directory
TEST(getAssetList, valid_path_wo_db)
{

    // Create tmp db
    char* tmpDir = createDBtmp();

    DiskStorage ds(tmpDir);
    StorageDriverInterface* pSI {&ds};
    auto array = pSI->getAssetList(AssetType::Decoder);

    ASSERT_EQ(array.size(), 0);

    removeDBtmp(&tmpDir);

}

// Test: get asset list from 1 decoder (1 file)
TEST(getAssetList, one_asset_one_file)
{

    char* tmpDir = createDBtmp();

    auto decoder_path = std::filesystem::path(tmpDir) / "decoders" / "test_decoder.yml";
    std::ofstream ofs {decoder_path};
    ofs << "test_decoder: {}";
    ofs.close();

    DiskStorage ds(tmpDir);
    StorageDriverInterface* pSI {&ds};
    auto array = pSI->getAssetList(AssetType::Decoder);

    ASSERT_EQ(array.size(), 1);
    ASSERT_STREQ(array[0].c_str(), "test_decoder");

    removeDBtmp(&tmpDir);

}

// Test: get asset list, 2 decoder (2 file)
TEST(getAssetList, two_asset_two_file)
{

    char* tmpDir = createDBtmp();

    auto newFile = [tmpDir](std::string name) -> void
    {
        auto decoder_path = std::filesystem::path(tmpDir) / "decoders" / name;
        std::ofstream ofs {decoder_path};
        ofs << "test_decoder: {}";
        ofs.close();
    };

    newFile("test_decoder.yml");
    newFile("test_decoder_2.yml");


    DiskStorage ds(tmpDir);
    StorageDriverInterface* pSI {&ds};
    auto array = pSI->getAssetList(AssetType::Decoder);

    ASSERT_EQ(array.size(), 2);
    ASSERT_STREQ(array[0].c_str(), "test_decoder_2");
    ASSERT_STREQ(array[1].c_str(), "test_decoder");

    removeDBtmp(&tmpDir);

}


// Test: Ignore non-yml files
TEST(getAssetList, one_asset_and_other_file)
{

    char* tmpDir = createDBtmp();

    auto newFile = [tmpDir](std::string name) -> void
    {
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

    DiskStorage ds(tmpDir);
    StorageDriverInterface* pSI {&ds};
    auto array = pSI->getAssetList(AssetType::Decoder);

    ASSERT_EQ(array.size(), 1);
    ASSERT_STREQ(array[0].c_str(), "test_decoder");

    removeDBtmp(&tmpDir);

}

// Test: Asset not found then throw exception
TEST(getAsset, asset_not_found)
{
    char* tmpDir = createDBtmp();

    DiskStorage ds(tmpDir);
    StorageDriverInterface* pSI {&ds};

    EXPECT_THROW(
    {
        try
        {
            auto asset = pSI->getAsset(AssetType::Decoder, "not_found");
        }
        catch (const std::runtime_error& e)
        {
            ASSERT_STREQ(e.what(), "Asset not found in file: 'decoders/not_found.yml'");
            throw;
        }}
    , std::runtime_error);

    removeDBtmp(&tmpDir);
}

// Test: Get an empty asset
TEST(getAsset, asset_empty)
{

    char* tmpDir = createDBtmp();

    DiskStorage ds(tmpDir);
    StorageDriverInterface* pSI {&ds};

    auto decoder_path = std::filesystem::path(tmpDir) / "decoders" / "empty.yml";
    std::ofstream ofs {decoder_path};
    ofs << "";
    ofs.close();

    auto asset = pSI->getAsset(AssetType::Decoder, "empty");

    ASSERT_STREQ(asset.c_str(), "");

    removeDBtmp(&tmpDir);

}

// Test: Get asset ok
TEST(getAsset, asset_ok)
{

    char* tmpDir = createDBtmp();

    DiskStorage ds(tmpDir);
    StorageDriverInterface* pSI {&ds};

    auto decoder_path = std::filesystem::path(tmpDir) / "decoders" / "test_ok.yml";
    std::ofstream ofs {decoder_path};
    ofs << "test_decoder: { 123 }";
    ofs.close();

    auto asset = pSI->getAsset(AssetType::Decoder, "test_ok");

    ASSERT_STREQ(asset.c_str(), "test_decoder: { 123 }");

    removeDBtmp(&tmpDir);

}

// Test: File/asset exist but is inaccessible/unreadable
TEST(getAsset, asset_inaccessible)
{

    char* tmpDir = createDBtmp();

    DiskStorage ds(tmpDir);
    StorageDriverInterface* pSI {&ds};

    auto decoder_path = std::filesystem::path(tmpDir) / "decoders" / "not_readable.yml";

    // Create a non-regular file (socket, fifo, etc) (inaccessible)
    mknod(decoder_path.c_str(), S_IFSOCK | (S_IRWXU | S_IRWXG | S_IRWXO), 0);

    EXPECT_THROW(
    {
        try
        {
            auto asset = pSI->getAsset(AssetType::Decoder, "not_readable");
        }
        catch (const std::runtime_error& e)
        {
            ASSERT_STREQ(e.what(), "Error reading file: 'decoders/not_readable.yml'");
            throw;
        }}
    , std::runtime_error);


    removeDBtmp(&tmpDir);

}
