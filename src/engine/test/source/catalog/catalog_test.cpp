#include <gtest/gtest.h>
#include <rapidjson/writer.h>
// TODO we are leaking the yaml exception
#include <yaml-cpp/yaml.h>

#include <catalog.hpp>

using namespace catalog;

//TODO fix failing catalog tests

// Test: An asset that fails the check against the schema
TEST(getAsset, get_asset_invalid_schema)
{
    Catalog catalog {StorageType::Local, "base/path"};

    EXPECT_THROW(catalog.getAsset(AssetType::Decoder, "syslog_invalid_schema"),
                 std::runtime_error);
}

// Test: Get a corrupted JSON schema
TEST(getAsset, get_asset_corrupted_json_schema)
{
    Catalog catalog {StorageType::Local, "base/path"};

    EXPECT_THROW(catalog.getAsset(AssetType::Decoder, "syslog2"),
                 std::runtime_error);
}

// Test: Get a corrupted asset (YML Malformed thow an YAML::ParserException)
TEST(getAsset, get_asset_corrupted)
{
    auto catalog = Catalog {StorageType::Local, "base/path"};
    EXPECT_THROW(catalog.getAsset(AssetType::Decoder, "syslog_malformed"),
                 ::YAML::ParserException);
}

// Test: Get asset for which there is no schema
TEST(getAsset, get_asset_schema_not_found)
{
    auto catalog = Catalog {StorageType::Local, "base/path"};
    EXPECT_THROW(catalog.getAsset(AssetType::Decoder, "syslog2"),
                 std::runtime_error);
}

// Test: Get asset with does not exist (Driver should throw an exception)
TEST(getAsset, get_asset_not_found)
{
    auto catalog = Catalog {StorageType::Local, "base/path"};

    EXPECT_THROW(catalog.getAsset(AssetType::Decoder, "not_found_asset"),
                 std::runtime_error);
}

// Test: Get a valid asset
TEST(getAsset, get_asset_valid)
{
    auto catalog = Catalog {StorageType::Local, "base/path"};

    rapidjson::Document decoder =
        catalog.getAsset(AssetType::Decoder, "syslog2");

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
