#include "Catalog_test.hpp"
#include "rapidjson/writer.h"
#include "gtest/gtest.h"


// Test: An asset that fails the check against the schema
TEST(Catalog, get_asset_invalid_schema)
{

    auto storageDriver = std::make_unique<fakeStorage>();
    auto catalog = std::make_unique<Catalog>(std::move(storageDriver));

    EXPECT_THROW(
    {
        try
        {
            auto asset = catalog->getAsset(AssetType::Decoder, "syslog_invalid_schema");
        }
        catch (const std::runtime_error& e)
        {
            ASSERT_STREQ(e.what(), "The asset 'syslog_invalid_schema' is invalid: Invalid JSON schema: '#/properties/draft'\nInvalid keyword: 'type'\nInvalid document: '#/draft'\n");
            throw;
        }}
    , std::runtime_error);

}

// Test: Get a corrupted JSON schema
TEST(Catalog, get_asset_corrupted_json_schema)
{

    auto storageDriver = std::make_unique<fakeStorage>();
    storageDriver->set_malformed_schemas(true);
    auto catalog = std::make_unique<Catalog>(std::move(storageDriver));

    EXPECT_THROW(
    {
        try
        {
            auto asset = catalog->getAsset(AssetType::Decoder, "syslog2");
        }
        catch (const std::runtime_error& e)
        {
            ASSERT_STREQ(e.what(), "Could not parse the schema for the asset type.");
            throw;
        }}
    , std::runtime_error);


}

// Test: Get a corrupted asset (YML Malformed thow an YAML::ParserException)
TEST(Catalog, get_asset_corrupted)
{

    auto storageDriver = std::make_unique<fakeStorage>();
    auto catalog = std::make_unique<Catalog>(std::move(storageDriver));

    EXPECT_THROW(catalog->getAsset(AssetType::Decoder, "syslog_malformed"), YAML::ParserException);

}

// Test: Get asset for which there is no schema
TEST(Catalog, get_asset_schema_not_found)
{

    auto storageDriver = std::make_unique<fakeStorage>();
    storageDriver->set_empty_schemas(true);
    auto catalog = std::make_unique<Catalog>(std::move(storageDriver));

    EXPECT_THROW(
    {
        try
        {
            auto asset = catalog->getAsset(AssetType::Decoder, "syslog2");
        }
        catch (const std::runtime_error& e)
        {
            ASSERT_STREQ(e.what(), "Could not get the schema 'wazuh-decoders' for the asset type.");
            throw;
        }}
    , std::runtime_error);

}

// Test: Get asset with does not exist
TEST(Catalog, get_asset_not_found)
{

    auto storageDriver = std::make_unique<fakeStorage>();
    auto catalog = std::make_unique<Catalog>(std::move(storageDriver));

    rapidjson::Document decoder = catalog->getAsset(AssetType::Decoder, "not_found_asset");
    ASSERT_TRUE(decoder.IsNull());

    EXPECT_NO_THROW(catalog->getAsset(AssetType::Decoder, "not_found_asset"));
}

// Test: Get a valid asset
TEST(Catalog, get_asset_valid)
{

    auto storageDriver = std::make_unique<fakeStorage>();
    auto catalog = std::make_unique<Catalog>(std::move(storageDriver));

    rapidjson::Document decoder = catalog->getAsset(AssetType::Decoder, "syslog2");

    if (decoder.IsNull())
    {
        FAIL() << "The decoder is null";
    }
    else if (decoder.IsObject())
    {
        auto nameProp = decoder.FindMember("name");

        if (nameProp->value.IsNull())
        {
            FAIL() << "The decoder no have a name";
        }
        else if (nameProp->value.IsString())
        {
            EXPECT_STREQ("syslog2", nameProp->value.GetString());
        }
        else
        {
            FAIL() << "The decoder name is not a string";
        }
    }
    else
    {
        FAIL() << "The decoder is not an object";
    }

}
