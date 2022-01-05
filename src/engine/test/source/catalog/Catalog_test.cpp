#include "Catalog_test.hpp"
#include "rapidjson/writer.h"

// Test that the getDecoder method return a valid decoder
TEST(Catalog, get_decoder_valid)
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
        if (decoder.FindMember("name")->value.IsString())
        {
            EXPECT_STREQ("syslog2", decoder.FindMember("name")->value.GetString());
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
