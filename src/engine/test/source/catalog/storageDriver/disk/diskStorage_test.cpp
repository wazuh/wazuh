#include <filesystem>

#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"
#include "rapidjson/schema.h"
#include "diskStorage_test.hpp"


// const std::string currentDir = std::filesystem::current_path().string();
// const std::string testDir {currentDir + "/test/source/catalog/storageDriver/disk/db_test"};
const std::string db_dir_test {"/root/repos/wazuh/src/engine/test/source/catalog/storageDriver/disk/db_test"};


TEST(diskStorage, path)
{

    diskStorage ds(db_dir_test);
    StorageDriverInterface* dsi {&ds};

    auto syslogDecStr {dsi->getAsset(AssetType::Decoder, "syslog")};
    auto decSchemaStr {dsi->getAsset(AssetType::Schemas, "wazuh-decoders")};

    rapidjson::Document syslogDec {};
    syslogDec.Parse(syslogDecStr.c_str());

    rapidjson::Document decSchema {};
    decSchema.Parse(decSchemaStr.c_str());

    rapidjson::SchemaDocument schema(decSchema);
    rapidjson::SchemaValidator validator(schema);

    if (!syslogDec.Accept(validator))
    {
        // Input JSON is invalid according to the schema
        // Output diagnostic information
        rapidjson::StringBuffer sb;
        validator.GetInvalidSchemaPointer().StringifyUriFragment(sb);
        printf("Invalid schema: %s\n", sb.GetString());
        printf("Invalid keyword: %s\n", validator.GetInvalidSchemaKeyword());
        sb.Clear();
        validator.GetInvalidDocumentPointer().StringifyUriFragment(sb);
        printf("Invalid document: %s\n", sb.GetString());
    }
    else
    {
        printf("Valid\n");
    }

    rapidjson::StringBuffer SB;

    SB.Clear();
    rapidjson::Writer<rapidjson::StringBuffer> writer(SB);

    syslogDec.Accept(writer);
    std::cout << SB.GetString() << std::endl;


    EXPECT_STREQ("test out --> ", "json_dump.c_str()");
}
