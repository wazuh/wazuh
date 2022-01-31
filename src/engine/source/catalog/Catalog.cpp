#include "Catalog.hpp"
#include "rapidjson/schema.h"

using namespace catalog;

std::optional<std::string> Catalog::validateJSON(rapidjson::Document & json, rapidjson::Document & schema) const
{

    rapidjson::SchemaDocument schemaDocument(schema);
    rapidjson::SchemaValidator validator(schemaDocument);

    if (!json.Accept(validator))
    {
        // Input JSON is invalid according to the schema
        std::ostringstream oss{};
        rapidjson::StringBuffer sb;
        validator.GetInvalidSchemaPointer().StringifyUriFragment(sb);
        oss << "Invalid JSON schema: '" << sb.GetString() << "'" << std::endl;

        oss << "Invalid keyword: '" << validator.GetInvalidSchemaKeyword() << "'" << std::endl;
        sb.Clear();

        validator.GetInvalidDocumentPointer().StringifyUriFragment(sb);
        oss << "Invalid document: '" << sb.GetString() << "'" << std::endl;

        return oss.str();
    }

    return {};
}

rapidjson::Document Catalog::getAsset(const std::string & type, std::string assetName) const
{
    return this->getAsset(stringToAssetType(type), assetName);
}

rapidjson::Document Catalog::getAsset(const AssetType type, std::string assetName) const
{

    using rapidjson::Document;
    using std::string;

    string assetStr{};
    string assetSchemaStr{};
    Document jsonSchema{};

    if (type == AssetType::Schema)
    {
        assetSchemaStr = this->spStorageDriver->getAsset(AssetType::Schema, assetName);

        // Parse schema
        jsonSchema.Parse(assetSchemaStr.c_str());
        return jsonSchema;
    }

    assetStr = spStorageDriver->getAsset(type, assetName);

    if (assetStr.empty())
    {
        throw std::runtime_error("Asset " + assetName + " is empty");
    }

    try
    {
        assetSchemaStr = spStorageDriver->getAsset(AssetType::Schema, assetTypeToSchema.at(type));
    }
    catch (std::runtime_error & e)
    {
        throw std::runtime_error("Could not get the schema '" + assetTypeToSchema.at(type) +
                                 "' for the asset type. DRIVER: " + e.what());
    }

    // Parse schema
    jsonSchema.Parse(assetSchemaStr.c_str());

    if (jsonSchema.HasParseError())
    {
        throw std::runtime_error("Could not parse the schema for the asset type.");
    }

    // if not, parse asset. Throw a YML::ParserException if the asset is not valid
    Document asset{yml2json::loadYMLfromString(assetStr)};

    // Validate the asset
    if (auto errorStr = validateJSON(asset, jsonSchema); errorStr)
    {
        throw std::runtime_error("The asset '" + string{assetName} + "' is invalid: " + errorStr.value());
    }

    return asset;
}

std::vector<std::string> Catalog::getAssetList(const AssetType type)
{

    return this->spStorageDriver->getAssetList(type);
}
