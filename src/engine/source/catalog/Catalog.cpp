#include "Catalog.hpp"
#include "rapidjson/schema.h"


std::optional<std::string> Catalog::validateJSON(rapidjson::Document& json,
                                                 rapidjson::Document& schema)
{

    rapidjson::SchemaDocument schemaDocument(schema);
    rapidjson::SchemaValidator validator(schemaDocument);

    if (!json.Accept(validator))
    {
        // Input JSON is invalid according to the schema
        std::ostringstream oss {};
        rapidjson::StringBuffer sb;
        validator.GetInvalidSchemaPointer().StringifyUriFragment(sb);
        oss << "Invalid JSON schema: '" << sb.GetString() << "'" << std::endl;

        oss << "Invalid keyword: '" << validator.GetInvalidSchemaKeyword()
            << "'" << std::endl;
        sb.Clear();

        validator.GetInvalidDocumentPointer().StringifyUriFragment(sb);
        oss << "Invalid document: '" << sb.GetString() << "'" << std::endl;

        return oss.str();
    }

    return {};
}

rapidjson::Document Catalog::getAsset(const AssetType type,
                                      std::string_view assetName)
{

    using std::string;
    using rapidjson::Document;

    string assetStr {};
    string assetSchemaStr {};

    switch (type)
    {
        case AssetType::Decoder:
        case AssetType::Rule:
        case AssetType::Output:
        case AssetType::Filter:
        case AssetType::Environments:

            assetStr = spStorageDriver->getAsset(type, assetName);

            if (assetStr.empty())
            {
                return {};
            }

            try
            {
                assetSchemaStr = spStorageDriver->getAsset(AssetType::Schemas,
                                                           assetTypeToSchema.at(type));
            }
            catch (std::runtime_error& e)
            {
                throw std::runtime_error("Could not get the schema '" +
                                         assetTypeToSchema.at(type) +
                                         "' for the asset type. DRIVER: " + e.what());
            }

            break;

        case AssetType::Schemas:
            assetSchemaStr = spStorageDriver->getAsset(AssetType::Schemas, assetName);
            break;

        default:
            throw std::runtime_error("Not implemented");
            break;
    }

    // Parse schema
    Document jsonSchema {};
    jsonSchema.Parse(assetSchemaStr.c_str());

    if (jsonSchema.HasParseError())
    {
        throw std::runtime_error("Could not parse the schema for the asset type.");
    }
    // Check if asset is the schema
    else if  (type == AssetType::Schemas)
    {
        return jsonSchema;
    }

    // if not, parse asset. Throw a YML::ParserException if the asset is not valid
    Document asset {yml2json::loadYMLfromString(assetStr)};

    // Validate the asset
    if (auto errorStr = validateJSON(asset, jsonSchema); errorStr)
    {
        throw std::runtime_error("The asset '" + string{assetName} +
                                 "' is invalid: " + errorStr.value());
    }

    return asset;
}

std::vector<std::string> Catalog::getAssetList(const AssetType type)
{

    std::vector<std::string> assetList {};
    assetList = this->spStorageDriver->getAssetList(type);

    return assetList;
}
